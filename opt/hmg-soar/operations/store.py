"""SQLite state with transactional audit and optimistic concurrency."""
import contextlib
import datetime as dt
import hashlib
import json
import sqlite3
import os
import uuid
from pathlib import Path

from .security import OperationError

DB_PATH = Path("/var/lib/eyemole/platform/operations.sqlite3")


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (
 project TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL,
 data TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
 updated_at TEXT NOT NULL, PRIMARY KEY(project,kind,id));
CREATE TABLE IF NOT EXISTS audit (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL,
 actor TEXT NOT NULL, action TEXT NOT NULL, object_id TEXT NOT NULL,
 data TEXT NOT NULL, timestamp TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, project TEXT NOT NULL, kind TEXT NOT NULL,
 object_id TEXT NOT NULL, actor TEXT NOT NULL, payload TEXT NOT NULL,
 state TEXT NOT NULL, created_at TEXT NOT NULL, started_at TEXT,
 finished_at TEXT, result TEXT, error TEXT,
 UNIQUE(project,kind,object_id));
CREATE INDEX IF NOT EXISTS jobs_state ON jobs(state,created_at);
PRAGMA user_version=1;
"""


class Store:
    def __init__(self, path=None):
        self.path = path or DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o660)
            os.fchmod(fd, 0o660)
            os.close(fd)
        except FileExistsError:
            pass
        with self.connect() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version > 1:
                raise OperationError("Banco criado por versão mais recente; recuperação exige migração compatível.", 503)
            conn.executescript(SCHEMA)

    @contextlib.contextmanager
    def connect(self):
        conn = sqlite3.connect(str(self.path), timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=15000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextlib.contextmanager
    def transaction(self):
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            yield conn

    def get(self, project, kind, identifier, conn=None):
        if conn is None:
            with self.connect() as db:
                return self.get(project, kind, identifier, db)
        row = conn.execute("SELECT * FROM objects WHERE project=? AND kind=? AND id=?",
                           (project, kind, identifier)).fetchone()
        if row is None:
            raise OperationError("Registro não encontrado.", 404)
        data = json.loads(row["data"])
        return dict(data, id=identifier, project=project, version=row["version"], updated_at=row["updated_at"])

    def list(self, project, kind, limit=1000):
        with self.connect() as conn:
            rows = conn.execute("SELECT id FROM objects WHERE project=? AND kind=? ORDER BY updated_at DESC LIMIT ?",
                                (project, kind, limit)).fetchall()
            return [self.get(project, kind, row["id"], conn) for row in rows]

    def put(self, project, kind, identifier, data, actor, action, expected=None, conn=None):
        if conn is None:
            with self.transaction() as db:
                return self.put(project, kind, identifier, data, actor, action, expected, db)
        row = conn.execute("SELECT version FROM objects WHERE project=? AND kind=? AND id=?",
                           (project, kind, identifier)).fetchone()
        version = row[0] if row else 0
        if expected is not None and version != expected:
            raise OperationError("Registro alterado por outro usuário; recarregue antes de salvar.", 409)
        conn.execute("INSERT INTO objects VALUES(?,?,?,?,?,?) ON CONFLICT(project,kind,id) DO UPDATE SET data=excluded.data,version=excluded.version,updated_at=excluded.updated_at",
                     (project, kind, identifier, encode(data), version + 1, now()))
        self.audit(conn, project, actor, action, identifier, {"kind": kind, "version": version + 1})
        return self.get(project, kind, identifier, conn)

    def audit(self, conn, project, actor, action, identifier, data):
        row = conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        previous = row[0] if row else "0" * 64
        stamp = now()
        body = encode([project, actor, action, identifier, data, stamp, previous])
        digest = hashlib.sha256(body.encode()).hexdigest()
        conn.execute("INSERT INTO audit(project,actor,action,object_id,data,timestamp,previous_hash,hash) VALUES(?,?,?,?,?,?,?,?)",
                     (project, actor, action, identifier, encode(data), stamp, previous, digest))

    def audit_entries(self, project, limit=200):
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM audit WHERE project=? ORDER BY seq DESC LIMIT ?", (project, limit))]

    def queue(self, project, kind, identifier, actor, payload):
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE project=? AND kind=? AND object_id=?",
                               (project, kind, identifier)).fetchone()
            # Mutating external jobs are never automatically repeated after ambiguous failure.
            if row:
                if kind in {"plans", "kiro", "sync", "evidence"} and row["state"] in {"failed", "interrupted", "succeeded"}:
                    conn.execute("DELETE FROM jobs WHERE id=?", (row["id"],))
                    self.audit(conn, project, actor, "job.requeued", row["id"], {"kind": kind})
                else:
                    return dict(row)
            if conn.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running')").fetchone()[0] >= 1000:
                raise OperationError("Fila cheia; aguarde os trabalhos pendentes.", 429)
            job_id = uuid.uuid4().hex
            conn.execute("INSERT INTO jobs(id,project,kind,object_id,actor,payload,state,created_at) VALUES(?,?,?,?,?,?,?,?)",
                         (job_id, project, kind, identifier, actor, encode(payload), "queued", now()))
            self.audit(conn, project, actor, "job.queued", job_id, {"kind": kind})
            return dict(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())

    def claim(self):
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE state='queued' ORDER BY created_at LIMIT 1").fetchone()
            if not row:
                return None
            conn.execute("UPDATE jobs SET state='running',started_at=? WHERE id=?", (now(), row["id"]))
            return dict(row)

    def finish(self, job_id, result=None, error=None):
        with self.transaction() as conn:
            job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            conn.execute("UPDATE jobs SET state=?,finished_at=?,result=?,error=? WHERE id=? AND state='running'",
                         ("failed" if error else "succeeded", now(), encode(result), error, job_id))
            if job:
                self.audit(conn, job["project"], job["actor"], "job.failed" if error else "job.succeeded", job_id, {"kind": job["kind"]})

    def recover_interrupted(self):
        # Called by the sole worker under a process lock, never by API.
        with self.transaction() as conn:
            conn.execute("UPDATE jobs SET state='interrupted',finished_at=?,error='Worker interrompido; conferir destino antes de repetir.' WHERE state='running'", (now(),))

    def jobs(self, project):
        with self.connect() as conn:
            rows = conn.execute("SELECT id,kind,object_id,actor,state,created_at,finished_at,result,error FROM jobs WHERE project=? ORDER BY created_at DESC LIMIT 200", (project,))
            return [dict(r) for r in rows]
