#!/usr/bin/python3
"""Wazuh 4.x Linux Active Response receiver: fixed READ-ONLY collection for EyeMole.

Install/configure explicitly (see docs/AUTOMATIC_REMEDIATION.md). No shell and
no free commands: the request is HMAC-signed by the EyeMole worker, bound to
this agent, short-lived and single-use; only the actions below run, with
validated parameters and fixed argv. The output is uploaded with this agent's
own token to the upload URL configured locally (never taken from the request).
Nothing is changed on the system.
"""
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

POLICY = Path("/etc/eyemole/collector.json")
STATE = Path("/var/lib/eyemole-collector")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}")
ACTIONS = {"os_release": None, "dpkg_source": "package", "apt_policy": "package"}
MAX_OUTPUT = 32 * 1024
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}


def _b64decode(text):
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,16000}", text):
        raise ValueError("encoding")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def verify(argument, policy, current=None):
    """Signature over the exact payload text, then schema, agent, time window and actions."""
    current = current or int(time.time())
    packet = json.loads(_b64decode(argument))
    if not isinstance(packet, dict) or set(packet) != {"p", "s"}:
        raise ValueError("packet_schema")
    key = policy.get("hmac_key", "")
    if not isinstance(key, str) or len(key) < 32:
        raise ValueError("key")
    expected = hmac.new(key.encode(), str(packet["p"]).encode(), hashlib.sha256).hexdigest()
    if not isinstance(packet["s"], str) or not hmac.compare_digest(expected, packet["s"]):
        raise ValueError("signature")
    payload = json.loads(_b64decode(packet["p"]))
    if not isinstance(payload, dict) or set(payload) != {"id", "project", "agent_id", "finding_id", "actions",
                                                         "issued_at", "expires_at"}:
        raise ValueError("payload_schema")
    if not policy.get("enabled") or payload["agent_id"] != policy.get("agent_id") or payload["agent_id"] == "000":
        raise ValueError("agent_or_disabled")
    if not re.fullmatch(r"[a-f0-9]{32}", str(payload["id"])) or not re.fullmatch(r"[a-f0-9]{64}", str(payload["finding_id"])):
        raise ValueError("id")
    issued, expires = payload["issued_at"], payload["expires_at"]
    if not isinstance(issued, int) or not isinstance(expires, int):
        raise ValueError("time")
    if not current - 300 <= issued <= current + 30 or not current < expires <= issued + 3600:
        raise ValueError("expired")
    actions = payload["actions"]
    if not isinstance(actions, list) or not 1 <= len(actions) <= 10:
        raise ValueError("actions")
    for item in actions:
        if not isinstance(item, dict) or item.get("action") not in ACTIONS:
            raise ValueError("action")
        param = ACTIONS[item["action"]]
        if set(item) != {"action"} | ({param} if param else set()) or (param and not PACKAGE.fullmatch(str(item[param]))):
            raise ValueError("parameters")
    return payload


def argv_for(item):
    if item["action"] == "dpkg_source":
        return ["/usr/bin/dpkg-query", "-W", "-f=${binary:Package} ${Version} ${source:Package} ${source:Version}\\n",
                item["package"]]
    if item["action"] == "apt_policy":
        return ["/usr/bin/apt-cache", "policy", item["package"]]
    return None


def run_action(item, runner=subprocess.run, os_release=Path("/etc/os-release")):
    if item["action"] == "os_release":
        lines = [line for line in os_release.read_text(encoding="utf-8", errors="replace").splitlines()
                 if re.match(r"(ID|VERSION_ID|VERSION_CODENAME)=", line)]
        return {"ok": True, "output": "\n".join(lines)[:MAX_OUTPUT]}
    result = runner(argv_for(item), env=ENV, stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False)
    output = (result.stdout or b"")[:MAX_OUTPUT].decode("utf-8", errors="replace")
    return {"ok": result.returncode == 0, "output": output} if result.returncode == 0 else \
        {"ok": False, "error": f"exit_{result.returncode}"}


def key_of(item):
    return item["action"]


def upload(policy, body, opener=urllib.request.urlopen):
    url = str(policy.get("upload_url") or "")
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+(:\d{1,5})?/soar-api/agent-context/[0-9]{3,8}", url) \
            or not url.endswith("/" + str(policy.get("agent_id"))):
        raise ValueError("upload_url")
    token = Path(policy.get("token_file", "/etc/eyemole-agent/token")).read_text().strip()
    context = ssl.create_default_context(cafile=policy.get("ca_file") or None)
    request = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
    with opener(request, timeout=30, context=context) as response:
        return response.status


def main():
    if os.geteuid() != 0:
        return 1
    try:
        stat = POLICY.stat()
        if POLICY.is_symlink() or stat.st_uid != 0 or stat.st_mode & 0o077:
            raise ValueError("policy_permissions")
        policy = json.loads(POLICY.read_text())
        message = json.loads(sys.stdin.readline(20000))
        if message.get("command") != "add":
            return 0
        args = message.get("parameters", {}).get("extra_args", [])
        if len(args) != 1:
            raise ValueError("arguments")
        payload = verify(args[0], policy)
        STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
        marker = STATE / payload["id"]
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # single use (replay protection)
        os.close(fd)
        results = {}
        for item in payload["actions"]:
            try:
                results[key_of(item)] = run_action(item)
            except (OSError, subprocess.SubprocessError) as exc:
                results[key_of(item)] = {"ok": False, "error": type(exc).__name__}
        body = {"request_id": payload["id"], "agent_id": payload["agent_id"],
                "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "results": results}
        status = upload(policy, body)
        print(json.dumps({"eyemole_collection": payload["id"], "state": "uploaded", "http": status}))
        return 0
    except Exception as exc:
        # Never emit packet, policy, token or key material.
        print(json.dumps({"state": "rejected", "reason": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
