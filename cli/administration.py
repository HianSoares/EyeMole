"""Privileged diagnostics and recovery, installed root-owned outside the application."""
import contextlib
import datetime as dt
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import uuid
from pathlib import Path

POLICY_PATH = Path("/etc/hmg-soar/update-policy.json")
UNITS = ("hmg-soar-report.service", "hmg-soar-report.timer", "hmg-soar-grype.service", "hmg-soar-grype.timer",
         "hmg-soar-api.service", "eyemole-update-check.service", "eyemole-update-check.timer", "eyemole-platform-worker.service")
MANAGED = (Path("/opt/hmg-soar"), Path("/var/www/wazuh-soar"), Path("/etc/hmg-soar"), Path("/etc/nginx"),
           Path("/etc/polkit-1/rules.d/49-hmg-soar.rules"), Path("/usr/local/bin/eyemole"), Path("/usr/local/lib/eyemole"),
           Path("/var/lib/eyemole/platform"), *(Path("/etc/systemd/system") / unit for unit in UNITS))


class RecoveryError(RuntimeError):
    pass


def policy():
    data = {"backup_root": "/var/backups/eyemole", "keep_snapshots": 3, "max_backup_bytes": 20 * 1024 ** 3,
            "minimum_free_bytes": 256 * 1024 ** 2, "report_keep_count": 100, "report_max_bytes": 2 * 1024 ** 3}
    if POLICY_PATH.exists():
        configured = json.loads(POLICY_PATH.read_text())
        if not isinstance(configured, dict) or set(configured) - set(data):
            raise RecoveryError("Política de atualização inválida.")
        data.update(configured)
    if not Path(data["backup_root"]).is_absolute() or int(data["keep_snapshots"]) < 2 or int(data["minimum_free_bytes"]) < 0:
        raise RecoveryError("Destino de backup deve ser absoluto; preservar pelo menos dois snapshots.")
    if any(not isinstance(data[k], int) or isinstance(data[k], bool) or data[k] < 0 for k in ("keep_snapshots", "max_backup_bytes", "minimum_free_bytes", "report_keep_count", "report_max_bytes")):
        raise RecoveryError("Limites de retenção devem ser inteiros não negativos.")
    return data


def allocated(path):
    if not path.exists() or path.is_symlink():
        return 0
    if path.is_file():
        return path.stat().st_blocks * 512
    total = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
        for name in files:
            entry = Path(root) / name
            if not entry.is_symlink():
                total += entry.stat().st_blocks * 512
    return total


def nearest(path):
    while not path.exists():
        path = path.parent
    return path


def preflight(config=None, managed=None):
    config = config or policy()
    managed = tuple(managed or MANAGED)
    required = sum(allocated(p) for p in managed)
    root = Path(config["backup_root"])
    probe = nearest(root)
    # Compression is not assumed: an incompressible snapshot must still fit.
    if shutil.disk_usage(probe).free < required + int(config["minimum_free_bytes"]):
        raise RecoveryError(f"Espaço insuficiente no destino de backup: necessário até {required + int(config['minimum_free_bytes'])} bytes. Libere espaço ou configure backup_root.")
    for path in (Path("/opt/hmg-soar"), Path("/var/www/wazuh-soar")):
        if shutil.disk_usage(nearest(path)).free < int(config["minimum_free_bytes"]):
            raise RecoveryError("Espaço insuficiente para instalação em " + str(path))
    db = Path("/var/lib/eyemole/platform/operations.sqlite3")
    if db.is_file():
        with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as conn:
            if conn.execute("SELECT count(*) FROM jobs WHERE state='running'").fetchone()[0]:
                raise RecoveryError("Integração em execução; aguarde o worker antes de atualizar.")
    return {"backup_required_max_bytes": required, "backup_available_bytes": shutil.disk_usage(probe).free}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def secure_directory(path):
    if path.is_symlink():
        raise RecoveryError("Diretório de backup não pode ser symlink.")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise RecoveryError("Diretório de backup deve ser privado e pertencer ao administrador.")


class Snapshot:
    def __init__(self, directory, paths=None, filesystem_root=Path("/")):
        self.directory = Path(directory)
        self.paths = tuple(paths or MANAGED)
        self.root = filesystem_root
        self.archive = self.directory / "snapshot.tar.gz"
        self.manifest = self.directory / "manifest.json"

    def create(self):
        secure_directory(self.directory)
        relative = [str(p.relative_to(self.root)) for p in self.paths if p.exists()]
        db = self.root / "var/lib/eyemole/platform/operations.sqlite3"
        if db.exists():
            with sqlite3.connect(str(db)) as conn:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        if not relative:
            raise RecoveryError("Não há instalação para preservar.")
        temporary = self.archive.with_suffix(".partial")
        subprocess.run(["tar", "--acls", "--xattrs", "--sparse", "-czf", str(temporary), "-C", str(self.root), "--", *relative],
                       check=True, timeout=1800, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        temporary.replace(self.archive)
        os.chmod(self.archive, 0o600)
        data = {"schema": 1, "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "sha256": sha256(self.archive), "paths": [str(p.relative_to(self.root)) for p in self.paths],
                "present": relative, "status": "prepared"}
        self.manifest.write_text(json.dumps(data))
        os.chmod(self.manifest, 0o600)
        self.verify()
        # Compare bytes and metadata before changing installed code.
        subprocess.run(["tar", "--acls", "--xattrs", "--compare", "--gzip", "--file", str(self.archive), "--directory", str(self.root)],
                       check=True, timeout=1800, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return self

    def verify(self):
        for path in (self.directory, self.archive, self.manifest):
            info = path.lstat()
            if path.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise RecoveryError("Snapshot deve ser privado, sem symlinks e administrado por root.")
        data = json.loads(self.manifest.read_text())
        permitted = [str(p.relative_to(self.root)) for p in self.paths]
        if data.get("schema") != 1 or data.get("paths") != permitted or sha256(self.archive) != data.get("sha256"):
            raise RecoveryError("Manifesto ou integridade do snapshot inválido.")
        if not isinstance(data.get("present"), list) or not set(data["present"]) <= set(permitted):
            raise RecoveryError("Caminhos presentes inválidos no manifesto.")
        with tarfile.open(self.archive, "r:gz") as archive:
            count = 0
            for member in archive:
                count += 1
                name = Path(member.name)
                if count > 500000 or name.is_absolute() or ".." in name.parts or not any(member.name == p or member.name.startswith(p + "/") for p in permitted):
                    raise RecoveryError("Conteúdo do snapshot fora dos caminhos gerenciados.")
                # The installer uses setgid directories for web/worker group
                # inheritance. Preserve those, but never privileged file modes.
                allowed_type = member.isfile() or member.isdir() or member.issym() or member.islnk()
                if (not allowed_type or member.mode & 0o4000
                        or (member.mode & 0o2000 and not member.isdir())):
                    raise RecoveryError(
                        f"Entrada não permitida no snapshot: {member.name} "
                        f"(tipo={member.type!r}, modo={oct(member.mode)})."
                    )
                if member.issym() or member.islnk():
                    if member.issym():
                        target = Path(os.path.normpath(member.linkname.lstrip("/"))) if member.linkname.startswith("/") else Path(os.path.normpath(str(name.parent / member.linkname)))
                    else:
                        target = Path(os.path.normpath(member.linkname))
                    container = next(p for p in permitted if member.name == p or member.name.startswith(p + "/"))
                    if target.is_absolute() or ".." in target.parts or not (str(target) == container or str(target).startswith(container + "/")):
                        raise RecoveryError("Link do snapshot atravessa caminhos gerenciados.")
        return data

    def mark(self, state):
        data = self.verify()
        data["status"] = state
        self.manifest.write_text(json.dumps(data))

    def remember_services(self, states):
        data = self.verify()
        data["service_states"] = {u: states.get(u, "inactive") for u in UNITS}
        self.manifest.write_text(json.dumps(data))

    def check_restore_space(self):
        self.verify()
        sizes = {}
        with tarfile.open(self.archive, "r:gz") as archive:
            for member in archive:
                if member.isfile():
                    for path in self.paths:
                        name = str(path.relative_to(self.root))
                        if member.name == name or member.name.startswith(name + "/"):
                            sizes[path] = sizes.get(path, 0) + member.size
                            break
        devices = {}
        for path in self.paths:
            probe = nearest(path.parent)
            device = probe.stat().st_dev
            required, _ = devices.get(device, (0, probe))
            devices[device] = (required + sizes.get(path, 0), probe)
        for required, probe in devices.values():
            if shutil.disk_usage(probe).free < required + 256 * 1024 ** 2:
                raise RecoveryError("Espaço insuficiente para preparar recuperação atômica em " + str(probe))

    def restore(self):
        data = self.verify()
        self.check_restore_space()
        with tarfile.open(self.archive, "r:gz") as archive:
            if any(any(k.startswith("SCHILY.acl.") for k in member.pax_headers) for member in archive) and not shutil.which("setfacl"):
                raise RecoveryError("Recuperação de ACL requer setfacl (pacote acl).")
        # Recover on each target filesystem, so renaming the staged tree is atomic there.
        for path in self.paths:
            name = str(path.relative_to(self.root))
            present = name in data["present"]
            if not present:
                if path.exists() or path.is_symlink():
                    shutil.rmtree(path) if path.is_dir() and not path.is_symlink() else path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=".eyemole-restore-", dir=path.parent) as directory:
                stage = Path(directory)
                # Extraction uses Python's traversal/symlink checks. Restore uid/gid after filtering.
                with tarfile.open(self.archive, "r:gz") as archive:
                    members = [m for m in archive if m.name == name or m.name.startswith(name + "/")]
                    def safe_filter(member, destination):
                        if member.issym() and member.linkname.startswith("/"):
                            target = Path(member.linkname)
                            if not any(target == p or p in target.parents for p in self.paths):
                                raise RecoveryError("Symlink do snapshot aponta fora dos caminhos gerenciados.")
                            member = member.replace(linkname=os.path.relpath(str(target).lstrip("/"), str(Path(member.name).parent)))
                        safe = tarfile.data_filter(member, destination)
                        return safe.replace(uid=member.uid, gid=member.gid, mode=member.mode) if safe else None
                    if any(any(k.startswith("SCHILY.acl.") for k in m.pax_headers) for m in members) and not shutil.which("setfacl"):
                        raise RecoveryError("Recuperação de ACL requer setfacl (pacote acl).")
                    archive.extractall(stage, members=members, filter=safe_filter)
                    # GNU tar preserves ACLs/xattrs in PAX headers. Python extraction
                    # restores content/ownership; restore these attributes before rename.
                    for member in members:
                        target = stage / member.name
                        for key, value in member.pax_headers.items():
                            if key.startswith("SCHILY.xattr."):
                                os.setxattr(target, key[len("SCHILY.xattr."):], value.encode("utf-8", "surrogateescape"), follow_symlinks=False)
                            elif key in {"SCHILY.acl.access", "SCHILY.acl.default"}:
                                args = ["setfacl", "--set-file=-", str(target)]
                                if key.endswith("default"):
                                    args.insert(1, "-d")
                                subprocess.run(args, input=value.replace(",", "\n"), text=True, check=True, capture_output=True, timeout=15)
                restored = stage / name
                old = path.parent / (".eyemole-old-" + uuid.uuid4().hex)
                exists = path.exists() or path.is_symlink()
                if exists:
                    path.rename(old)
                try:
                    restored.rename(path)
                except Exception:
                    if exists:
                        old.rename(path)
                    raise
                if exists:
                    shutil.rmtree(old) if old.is_dir() and not old.is_symlink() else old.unlink()
        self.mark("restored")


@contextlib.contextmanager
def pause_application(run):
    active = []
    try:
        for service in ("hmg-soar-api.service", "eyemole-platform-worker.service"):
            probe = run(["systemctl", "show", service, "--property=ActiveState", "--value"], capture_output=True, timeout=15)
            if probe.stdout.strip() == "active":
                run(["systemctl", "stop", service], timeout=30)
                active.append(service)
        yield
    finally:
        if not Path("/run/eyemole-recovery-required").exists():
            for service in active:
                loaded = run(["systemctl", "show", service, "--property=LoadState", "--value"], capture_output=True, timeout=15)
                if loaded.stdout.strip() == "loaded":
                    run(["systemctl", "restart", service], timeout=30)


def service_states(run):
    return {u: run(["systemctl", "show", u, "--property=ActiveState", "--value"], capture_output=True, timeout=15).stdout.strip() for u in UNITS}


def restore_services(snapshot, run):
    for unit, state in snapshot.verify().get("service_states", {}).items():
        if unit not in UNITS:
            raise RecoveryError("Unidade não gerenciada no snapshot.")
        if state == "active":
            run(["systemctl", "start", unit], timeout=30)


def diagnostics(tls_check=None):
    checks = []
    for path in ("/", "/var", "/opt"):
        usage = shutil.disk_usage(path)
        checks.append({"check": "disk", "path": path, "ok": usage.free >= 256 * 1024 ** 2,
                       "free_bytes": usage.free, "used_percent": round(100 * usage.used / usage.total, 1)})
    for unit in UNITS:
        result = subprocess.run(["systemctl", "show", unit, "--property=ActiveState", "--value"],
                                capture_output=True, text=True, timeout=10)
        value = result.stdout.strip() or "unknown"
        oneshot = unit in {"hmg-soar-report.service", "hmg-soar-grype.service", "eyemole-update-check.service"}
        last = subprocess.run(["systemctl", "show", unit, "--property=Result", "--value"], capture_output=True, text=True, timeout=10)
        result_state = last.stdout.strip()
        checks.append({"check": "service", "unit": unit, "ok": (value == "active" or oneshot and value == "inactive") and result_state in {"", "success"}, "state": value, "last_result": result_state})
    try:
        report = json.loads(Path("/var/www/wazuh-soar/data/latest.json").read_text())
        metadata = report.get("metadata", {})
        generated = dt.datetime.fromisoformat(metadata.get("generated_at", "").replace("Z", "+00:00")).astimezone()
        age = (dt.datetime.now(dt.timezone.utc) - generated).total_seconds()
        checks.append({"check": "collection", "ok": metadata.get("collection", {}).get("complete") is True and 0 <= age <= 86400,
                       "generated_at": metadata.get("generated_at"), "agents": len(metadata.get("agents_analyzed", []))})
    except (OSError, ValueError):
        checks.append({"check": "collection", "ok": False})
    if tls_check:
        try:
            tls_check()
            checks.append({"check": "internal_tls", "ok": True})
        except Exception:
            checks.append({"check": "internal_tls", "ok": False, "action": "Confira CA, SAN e permissões do usuário hmg-soar."})
    return checks


def configure_access(username, role, projects, agents=(), enable=False, path=Path("/etc/hmg-soar/platform.json")):
    import re
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,160}", username) or role not in {"admin", "analyst", "owner", "auditor"}:
        raise RecoveryError("Usuário ou papel inválido.")
    data = json.loads(path.read_text())
    if any(p != "*" and p not in data.get("projects", {}) for p in projects):
        raise RecoveryError("Projeto não configurado.")
    if role != "admin" and "*" in projects:
        raise RecoveryError("Escopo global reservado ao administrador.")
    data.setdefault("users", {})[username] = {"role": role, "projects": projects, "agent_ids": list(agents)}
    if enable:
        if role != "admin" or projects != ["*"]:
            raise RecoveryError("Habilitação exige administrador global.")
        data["enabled"] = True
    temporary = path.with_name(".platform-" + uuid.uuid4().hex)
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    info = path.stat()
    os.chown(temporary, info.st_uid, info.st_gid)
    os.chmod(temporary, info.st_mode & 0o777)
    temporary.replace(path)
    return {"user": username, "role": role, "projects": projects, "enabled": data.get("enabled", False)}


def cleanup(config=None, apply=False):
    config = config or policy()
    root = Path(config["backup_root"])
    candidates = []
    if root.exists():
        for directory in root.glob("eyemole-snapshot-*"):
            try:
                snapshot = Snapshot(directory)
                data = snapshot.verify()
                # Prepared/failed/restored backups remain available for reconciliation.
                if data.get("status") == "successful":
                    candidates.append((data["created_at"], directory, allocated(directory)))
            except Exception:
                continue
    candidates.sort(reverse=True)
    keep = max(int(config["keep_snapshots"]), 2)
    total = sum(c[2] for c in candidates)
    removed = []
    for index in range(len(candidates) - 1, 1, -1):
        _, directory, size = candidates[index]
        if index >= keep or total > int(config["max_backup_bytes"]):
            removed.append(str(directory))
            total -= size
            if apply:
                shutil.rmtree(directory)
    reports = Path("/var/www/wazuh-soar/reports")
    histories = sorted((p for p in reports.glob("relatorio_wazuh_*.html") if p.is_file() and not p.is_symlink()),
                       key=lambda p: p.stat().st_mtime, reverse=True) if reports.exists() else []
    size = sum(p.stat().st_size for p in histories)
    for index in range(len(histories) - 1, 1, -1):
        path = histories[index]
        if index >= max(int(config["report_keep_count"]), 2) or size > int(config["report_max_bytes"]):
            removed.append(str(path))
            size -= path.stat().st_size
            if apply:
                path.unlink()
    return {"apply": apply, "paths": removed, "preserved_minimum": 2}


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["backup-install", "verify"])
    parser.add_argument("directory", nargs="?")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RecoveryError("Operação exige root.")
    if args.command == "verify":
        Snapshot(Path(args.directory)).verify()
    else:
        cfg = policy()
        preflight(cfg)
        root = Path(cfg["backup_root"])
        secure_directory(root)
        directory = root / ("eyemole-snapshot-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
        Snapshot(directory).create()
        print(directory)


if __name__ == "__main__":
    main()
