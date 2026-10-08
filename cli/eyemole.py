#!/usr/bin/python3
"""EyeMole administration CLI. Installed root-owned, outside service-writable code.

Checks public GitHub metadata; upgrades run the pinned repository installer.
No shell evaluation, credential upload, or installation through the web API.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

REPOSITORY = "HianSoares/EyeMole"
API = f"https://api.github.com/repos/{REPOSITORY}"
REMOTE = f"https://github.com/{REPOSITORY}.git"
STATE_FILE = Path("/etc/hmg-soar/installed-version.json")
STATUS_FILE = Path("/var/www/wazuh-soar/data/update_status.json")
UPDATE_ROOT = Path("/var/lib/eyemole/updates")
BACKUP_ROOT = Path("/opt")
WEB_RUN_FLAG = Path("/opt/hmg-soar/config/web_run.enabled")
SHA = re.compile(r"^[0-9a-f]{40}$")


class UpdateError(RuntimeError):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def atomic_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".eyemole-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def github_json(resource: str) -> dict:
    request = urllib.request.Request(API + resource, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "EyeMole-update-check",
    })
    with urllib.request.urlopen(request, timeout=15) as response:
        if not response.geturl().startswith(API + "/"):
            raise UpdateError("Redirecionamento inesperado do GitHub.")
        payload = response.read(1_000_001)
    if len(payload) > 1_000_000:
        raise UpdateError("Resposta do GitHub excedeu o limite.")
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise UpdateError("Resposta inválida do GitHub.")
    return data


def check_update(state: dict, fetch=github_json) -> dict:
    installed = state.get("installed_commit", "")
    result = {"checked_at": now(), "installed_commit": installed,
              "latest_commit": "", "state": "unknown", "update_available": False}
    if not isinstance(installed, str) or not SHA.fullmatch(installed):
        result["state"] = "unmanaged"
        return result
    if state.get("last_update_failed"):
        result["state"] = "install_failed"
        return result
    if state.get("custom_layout"):
        result["state"] = "custom_layout"
        return result
    if state.get("local_changes"):
        result["state"] = "local_changes"
        return result
    try:
        latest = fetch("/git/ref/heads/main").get("object", {}).get("sha", "")
        if not isinstance(latest, str) or not SHA.fullmatch(latest):
            raise UpdateError("SHA inválido do GitHub.")
        result["latest_commit"] = latest
        if installed == latest:
            result["state"] = "up_to_date"
        else:
            comparison = fetch(f"/compare/{installed}...{latest}")
            if comparison.get("status") == "ahead" and comparison.get("ahead_by", 0) > 0:
                result.update(state="available", update_available=True)
            else:
                result["state"] = "different_history"
    except Exception:
        # Do not expose proxy URLs, response bodies, or exception credentials.
        result["state"] = "check_failed"
    return result


def describe(status: dict) -> str:
    messages = {
        "up_to_date": "EyeMole já está atualizado.",
        "available": "Atualização disponível. Execute: sudo eyemole update",
        "unmanaged": "Versão não registrada. Instale esta versão uma vez com install.sh.",
        "local_changes": "Instalação de uma árvore modificada; atualização automática bloqueada.",
        "different_history": "Instalação fora do histórico da main; atualização bloqueada.",
        "check_failed": "Não foi possível consultar o GitHub. Nenhuma atualização foi aplicada.",
        "install_failed": "A instalação anterior falhou; restaure o backup antes de tentar novamente.",
        "custom_layout": "Instalação com caminhos personalizados; use o instalador com os mesmos parâmetros.",
    }
    return messages.get(status.get("state"), "Versão ainda não verificada.")


def run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, check=True, timeout=kwargs.pop("timeout", 180),
                              text=True, **kwargs)
    except (subprocess.SubprocessError, OSError) as exc:
        raise UpdateError(f"Falha ao executar {Path(argv[0]).name}.") from exc


def record_install(repo: Path, state_file: Path, status_file: Path, custom_layout=False) -> None:
    try:
        git = ["git", "-c", f"safe.directory={repo.resolve()}", "-C", str(repo)]
        sha = run([*git, "rev-parse", "HEAD"], capture_output=True).stdout.strip()
        dirty = bool(run([*git, "status", "--porcelain", "--untracked-files=no"],
                         capture_output=True).stdout.strip())
    except UpdateError:
        sha, dirty = "", False
    if not SHA.fullmatch(sha):
        sha = ""
    state = {"schema_version": 1, "installed_commit": sha, "local_changes": dirty,
             "installed_at": now(), "repository": REPOSITORY, "custom_layout": custom_layout}
    atomic_json(state_file, state)
    # The check runs again after installation. Do not mark a feature branch current.
    status = {"state": "unknown", "update_available": False, "checked_at": now(),
              "installed_commit": sha, "latest_commit": ""}
    atomic_json(status_file, status)


def credentials(path: Path) -> dict:
    """Read EnvironmentFile assignments without sourcing executable shell code."""
    import shlex
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise UpdateError("Formato não suportado em credentials.env.")
        parts = shlex.split(value, comments=False)
        values[key] = " ".join(parts)
    return values


def tls_preflight(cred_file: Path = Path("/etc/hmg-soar/credentials.env")) -> None:
    if not cred_file.is_file():
        raise UpdateError("Credenciais ausentes; conclua a primeira instalação.")
    values = credentials(cred_file)
    if not values.get("OPENSEARCH_PASS") or not values.get("WAZUH_API_PASS"):
        raise UpdateError("Credenciais incompletas; conclua a primeira instalação.")
    if values.get("HMG_USE_HTTPS", "true").lower() == "false":
        return
    if values.get("HMG_INTERNAL_TLS_INSECURE", "false").lower() == "true":
        print("TLS interno sem validação: mantendo o opt-in de laboratório existente.")
        return
    ca = values.get("HMG_INTERNAL_CA_BUNDLE", "")
    # Check as the service user, including CA access and hostname/SAN matching.
    probe = ("import ssl,socket,sys; c=ssl.create_default_context(cafile=sys.argv[3] or None); "
             "s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=10); "
             "s.settimeout(10); c.wrap_socket(s,server_hostname=sys.argv[1]).close()")
    for host_key, port_key, default_port in (
        ("OPENSEARCH_HOST", "OPENSEARCH_PORT", "9200"),
        ("WAZUH_API_HOST", "WAZUH_API_PORT", "55000"),
    ):
        host = values.get(host_key, "127.0.0.1")
        port = values.get(port_key, default_port)
        try:
            run(["runuser", "-u", "hmg-soar", "--", "/usr/bin/python3", "-c", probe,
                 host, port, ca], capture_output=True, timeout=30)
        except UpdateError as exc:
            raise UpdateError(f"TLS/conectividade inválida para {host_key}. "
                              "Confira a CA, permissões e o nome/IP no certificado. "
                              "O código instalado não foi alterado.") from exc


@contextlib.contextmanager
def update_lock(path: Path = Path("/run/lock/eyemole-update.lock")):
    import fcntl
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise UpdateError("Já existe uma atualização do EyeMole em execução.") from exc
        yield
    finally:
        os.close(fd)


def checkout(target: str, destination: Path) -> None:
    if not SHA.fullmatch(target):
        raise UpdateError("Revisão de atualização inválida.")
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(destination.parent),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_TERMINAL_PROMPT": "0"}
    run(["git", "clone", "--no-checkout", "--single-branch", "--branch", "main",
         REMOTE, str(destination)], env=env, timeout=300)
    run(["git", "-C", str(destination), "checkout", "--detach", target], env=env)
    sha = run(["git", "-C", str(destination), "rev-parse", "HEAD"],
              env=env, capture_output=True).stdout.strip()
    if sha != target:
        raise UpdateError("O código baixado não corresponde à revisão solicitada.")


def validate_checkout(repo: Path) -> None:
    run(["bash", "-n", str(repo / "install.sh")], capture_output=True)
    # Compile without creating caches or importing downloaded code before deployment.
    for path in (repo / "opt/hmg-soar").rglob("*.py"):
        if "tests" not in path.parts:
            compile(path.read_bytes(), str(path), "exec")
    if not (repo / "cli/eyemole.py").is_file():
        raise UpdateError("A revisão de destino não contém a CLI de atualização.")


@contextlib.contextmanager
def pause_collection_timers():
    """Avoid concurrent collection while replacing code; preserve timer activation."""
    active = []
    try:
        for timer in ("hmg-soar-report.timer", "hmg-soar-grype.timer"):
            probe = run(["systemctl", "show", timer, "--property=ActiveState", "--value"],
                        capture_output=True, timeout=15)
            if probe.stdout.strip() == "active":
                run(["systemctl", "stop", timer], timeout=30)
                active.append(timer)
        for service in ("hmg-soar-report.service", "hmg-soar-grype.service"):
            probe = run(["systemctl", "show", service, "--property=ActiveState", "--value"],
                        capture_output=True, timeout=15)
            if probe.stdout.strip() in {"active", "activating", "deactivating", "reloading"}:
                raise UpdateError("Coleta em execução. Aguarde terminar e execute eyemole update novamente.")
        yield
    finally:
        for timer in active:
            run(["systemctl", "start", timer], timeout=30)


def update(state_file: Path = STATE_FILE, status_file: Path = STATUS_FILE) -> int:
    if os.geteuid() != 0:
        raise UpdateError("Execute como administrador: sudo eyemole update")
    with update_lock():
        state = read_json(state_file)
        status = check_update(state)
        atomic_json(status_file, status)
        print(describe(status))
        if status["state"] == "up_to_date":
            return 0
        if not status["update_available"]:
            return 1
        if not shutil.which("git"):
            raise UpdateError("git não está instalado; execute o instalador desta versão uma vez.")
        tls_preflight()
        target = status["latest_commit"]
        print(f"Atualizando {state['installed_commit'][:7]} → {target[:7]}.")
        # Private durable working directory holds the deployment log and metadata.
        root = UPDATE_ROOT
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root, 0o700)
        work = Path(tempfile.mkdtemp(prefix="update-", dir=root))
        repo = work / "source"
        checkout(target, repo)
        validate_checkout(repo)
        # Preserve the existing mode. install.sh defaults to disabling web-run.
        args = ["bash", str(repo / "install.sh")]
        if WEB_RUN_FLAG.is_file():
            args.append("--enable-web-run")
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = BACKUP_ROOT / f"backup-eyemole-update-{stamp}-{work.name}"
        env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
               "HOME": str(work), "EYEMOLE_BACKUP_DIR": str(backup),
               "EYEMOLE_DEFER_COLLECTION_TIMERS": "1"}
        print(f"Backup: {backup}\nLog: {work / 'install.log'}", flush=True)
        with (work / "install.log").open("w", encoding="utf-8") as log:
            installation_started = False
            try:
                with pause_collection_timers():
                    installation_started = True
                    run(args, cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=3600)
            except UpdateError as exc:
                if not installation_started:
                    raise
                # Never advertise success after a partial installer failure.
                atomic_json(state_file, dict(state, last_update_failed=True, attempted_commit=target))
                failed = dict(status, state="install_failed", update_available=False)
                atomic_json(status_file, failed)
                raise UpdateError(f"Instalação falhou. Consulte {work / 'install.log'} e "
                                  f"restaure o backup {backup} conforme OPERATIONS.md. "
                                  "A atualização não foi registrada como concluída.") from exc
        installed = read_json(state_file)
        if installed.get("installed_commit") != target:
            raise UpdateError("Instalação terminou sem registrar a revisão esperada. Consulte o log.")
        atomic_json(status_file, check_update(installed))
        shutil.rmtree(repo)
        print(f"EyeMole atualizado para {target[:7]}. Relatório e serviços validados pelo instalador.")
        return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="eyemole", description="Administração do EyeMole")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="Mostrar a revisão instalada")
    check = sub.add_parser("check-update", help="Consultar atualizações sem instalar")
    check.add_argument("--write-status", action="store_true", help="Publicar status local para o painel")
    sub.add_parser("update", help="Atualizar a instalação existente (requer sudo)")
    record = sub.add_parser("record-install", help="Uso interno do instalador")
    record.add_argument("repo", type=Path)
    record.add_argument("--state-file", type=Path, default=STATE_FILE)
    record.add_argument("--status-file", type=Path, default=STATUS_FILE)
    record.add_argument("--custom-layout", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "record-install":
            if os.geteuid() != 0:
                raise UpdateError("Registro de instalação exige root.")
            record_install(args.repo, args.state_file, args.status_file, args.custom_layout)
            return 0
        if args.command == "version":
            state = read_json(STATE_FILE)
            print("EyeMole " + (state.get("installed_commit") or "versão não registrada"))
            return 0
        if args.command == "update":
            return update()
        status = check_update(read_json(STATE_FILE))
        if args.write_status:
            atomic_json(STATUS_FILE, status)
        print(describe(status))
        return 1 if status["state"] == "check_failed" else 0
    except (UpdateError, OSError, ValueError, SyntaxError, subprocess.SubprocessError):
        # UpdateError messages contain only operator-safe diagnostics.
        exc = sys.exc_info()[1]
        print(str(exc) if isinstance(exc, UpdateError) else "Falha local; confira permissões e configuração.",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
