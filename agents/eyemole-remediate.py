#!/usr/bin/python3
"""Optional Wazuh 4.x Linux Active Response receiver. Install/configure explicitly.

No arbitrary shell: HMAC, local package allowlist, expiry, replay protection and
installed-version precondition precede a pinned apt/dnf/yum action.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

POLICY = Path("/etc/eyemole/execution.json")
STATE = Path("/var/lib/eyemole-executor")


def decode(argument, policy, current=None):
    current = current or int(time.time())
    if not isinstance(argument, str) or len(argument) > 12000:
        raise ValueError("packet_size")
    packet = json.loads(base64.b64decode(argument, altchars=b"-_", validate=True))
    if set(packet) != {"payload", "signature"}:
        raise ValueError("packet_schema")
    payload = packet["payload"]
    expected = {"id", "agent_id", "package", "package_manager", "installed_version", "fixed_version", "issued_at", "expires_at"}
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ValueError("payload_schema")
    key = policy.get("hmac_key", "")
    if len(key) < 32:
        raise ValueError("key")
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    signature = hmac.new(key.encode(), raw, hashlib.sha256).hexdigest()
    if not isinstance(packet["signature"], str) or not hmac.compare_digest(signature, packet["signature"]):
        raise ValueError("signature")
    if not policy.get("enabled") or payload["agent_id"] != policy.get("agent_id") or payload["agent_id"] == "000":
        raise ValueError("agent_or_disabled")
    if not re.fullmatch(r"[a-f0-9]{32}", payload["id"]):
        raise ValueError("id")
    if not isinstance(payload["issued_at"], int) or not isinstance(payload["expires_at"], int):
        raise ValueError("time")
    if not current - 300 <= payload["issued_at"] <= current + 30 or not current < payload["expires_at"] <= payload["issued_at"] + 300:
        raise ValueError("expired")
    package = payload["package"]
    if not isinstance(package, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9+_.:-]{0,127}", package) or package not in policy.get("packages", []):
        raise ValueError("package")
    for field in ("installed_version", "fixed_version"):
        if not isinstance(payload[field], str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.+:~_-]{0,127}", payload[field]):
            raise ValueError("version")
    if payload["package_manager"] not in policy.get("package_managers", []) or payload["package_manager"] not in {"apt", "dnf", "yum"}:
        raise ValueError("manager")
    return payload


def action(payload, query=subprocess.check_output):
    package, fixed = payload["package"], payload["fixed_version"]
    if payload["package_manager"] == "apt":
        installed = query(["/usr/bin/dpkg-query", "-W", "-f=${Version}", "--", package], timeout=15, text=True).strip()
        argv = ["/usr/bin/apt-get", "-y", "--only-upgrade", "install", "--", package + "=" + fixed]
    else:
        installed = query(["/usr/bin/rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", "--", package], timeout=15, text=True).strip()
        argv = ["/usr/bin/" + payload["package_manager"], "-y", "upgrade", "--", package + "-" + fixed]
    if installed != payload["installed_version"]:
        raise ValueError("installed_version_changed")
    if fixed == installed:
        raise ValueError("already_installed")
    return argv


def main():
    if os.geteuid() != 0:
        return 1
    try:
        stat = POLICY.stat()
        if POLICY.is_symlink() or stat.st_uid != 0 or stat.st_mode & 0o077:
            raise ValueError("policy_permissions")
        policy = json.loads(POLICY.read_text())
        raw = sys.stdin.readline(20000)
        message = json.loads(raw)
        if message.get("command") != "add":
            return 0
        args = message.get("parameters", {}).get("extra_args", [])
        if len(args) != 1:
            raise ValueError("arguments")
        payload = decode(args[0], policy)
        argv = action(payload)
        STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(STATE, 0o700)
        # Reserve once BEFORE invoking the package manager. Failed actions are not replayed.
        with sqlite3.connect(str(STATE / "actions.sqlite3"), timeout=10) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY, timestamp INTEGER, state TEXT)")
            conn.execute("INSERT INTO actions VALUES(?,?,?)", (payload["id"], int(time.time()), "started"))
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "DEBIAN_FRONTEND": "noninteractive"}
        log_path = STATE / (payload["id"] + ".log")
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as log:
            result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log, timeout=600)
        with sqlite3.connect(str(STATE / "actions.sqlite3")) as conn:
            conn.execute("UPDATE actions SET state=? WHERE id=?", ("applied" if result.returncode == 0 else "failed", payload["id"]))
        print(json.dumps({"eyemole_action": payload["id"], "state": "applied" if result.returncode == 0 else "failed", "correction_confirmed": False}))
        return result.returncode
    except Exception as exc:
        # Never emit packet, policy, signatures or key material.
        print(json.dumps({"state": "rejected", "reason": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
