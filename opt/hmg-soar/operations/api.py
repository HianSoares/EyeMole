"""Small API router kept separate from the legacy report API."""
import base64
import json
from urllib.parse import parse_qs, urlsplit

from .security import load_config, principal, legacy_allowed, OperationError
from .service import Operations
from .store import Store
from remediation.rate_limiter import SlidingWindowLog

_READ_LIMIT = SlidingWindowLog(max_tokens=120, window_seconds=60)
_WRITE_LIMIT = SlidingWindowLog(max_tokens=30, window_seconds=60)


def handle(handler, method, path):
    if not path.startswith("/platform/"):
        return False
    try:
        from pathlib import Path
        if Path("/run/eyemole-maintenance").exists() and path != "/platform/access":
            raise OperationError("Atualização em andamento; tente novamente após a manutenção.", 503)
        cfg = load_config()
        username = handler._get_remote_user()
        if path == "/platform/access":
            # Nginx runs this internal subrequest alongside Basic authentication.
            # Its incoming identity headers are always overwritten by the proxy.
            if not username or username == "unknown":
                auth = handler.headers.get("Authorization", "")
                if auth.startswith("Basic "):
                    try:
                        username = base64.b64decode(auth[6:], validate=True).decode().split(":", 1)[0]
                    except (ValueError, UnicodeError):
                        username = "unknown"
            resource = handler.headers.get("X-Original-URI", "").split("?", 1)[0]
            if cfg.get("enabled"):
                p = principal(cfg, username)
                allowed = {"/soar/assets/operations.html", "/soar/assets/operations.js", "/soar/assets/operations.css", "/soar/assets/eyemole.png"}
                if resource not in allowed and not resource.startswith("/soar-api/platform/") and not legacy_allowed(cfg, username):
                    raise OperationError("Use /soar/assets/operations.html para seu escopo de ativos.", 403)
            handler._send_json(200, {"allowed": True})
            return True
        if path == "/platform/config-status" and method == "GET":
            handler._send_json(200, {"enabled": bool(cfg.get("enabled"))})
            return True
        p = principal(cfg, username)
        limiter = _WRITE_LIMIT if method == "POST" else _READ_LIMIT
        if not limiter.is_allowed(username):
            raise OperationError("Limite de requisições; aguarde um minuto.", 429)
        project = parse_qs(urlsplit(handler.path).query).get("project", [""])[0]
        if path == "/platform/me" and method == "GET":
            handler._send_json(200, {"user": p.name, "role": p.role,
                                   "projects": [k for k in cfg.get("projects", {}) if k in p.projects or "*" in p.projects],
                                   "legacy_dashboard": legacy_allowed(cfg, username)})
            return True
        service = Operations(Store(), cfg, p)
        service.context(project)
        body = {}
        if method == "POST":
            if not handler._origin_is_allowed():
                raise OperationError("Origem não permitida.", 403)
            if handler.headers.get("Sec-Fetch-Site") == "cross-site":
                raise OperationError("Requisição entre sites bloqueada.", 403)
            if handler.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                raise OperationError("Content-Type deve ser application/json.", 415)
            size = int(handler.headers.get("Content-Length", "0"))
            if not 0 < size <= 128 * 1024:
                raise OperationError("Tamanho do corpo inválido.", 413)
            body = json.loads(handler.rfile.read(size))
            if not isinstance(body, dict):
                raise OperationError("Corpo deve ser objeto JSON.")
        parts = path.strip("/").split("/")
        result, status = None, 200
        if method == "GET" and path == "/platform/overview":
            result = service.overview(project)
        elif method == "GET" and path == "/platform/proposals":
            result = service.proposals(project)
        elif method == "GET" and path == "/platform/jobs":
            campaigns = {c["id"] for c in service.store.list(project, "campaign") if service.visible(c)}
            result = {"items": [j for j in service.store.jobs(project) if j["object_id"].split(":")[0] in campaigns]}
        elif method == "GET" and path in {"/platform/inventory", "/platform/incidents", "/platform/evidence", "/platform/executions"}:
            kind = {"incidents": "incident", "executions": "execution"}.get(parts[-1], parts[-1])
            result = {"items": [r for r in service.store.list(project, kind) if service.visible(r)]}
        elif method == "GET" and path == "/platform/audit":
            p.require("read", project)
            if p.agents:
                raise OperationError("Auditoria integral exige escopo completo do projeto.", 403)
            result = {"items": service.store.audit_entries(project)}
        elif method == "GET" and len(parts) == 3 and parts[1] == "campaigns":
            result = service.get_campaign(project, parts[2])
        elif method == "POST" and path == "/platform/campaigns":
            result, status = service.create_campaign(project, body), 201
        elif method == "POST" and len(parts) == 3 and parts[1] == "inventory":
            result = service.inventory(project, parts[2], body)
        elif method == "POST" and len(parts) == 4 and parts[1] == "campaigns":
            actions = {"transition": service.transition, "verify": service.verify, "accept": service.accept, "approve": service.approve}
            if parts[3] in actions:
                result = actions[parts[3]](project, parts[2], body)
            elif parts[3] in {"plans", "kiro", "ticket", "sync", "execute", "evidence"}:
                result, status = service.queue(project, parts[2], parts[3], body), 202
        if result is None:
            raise OperationError("Endpoint operacional não encontrado.", 404)
        handler._send_json(status, result)
    except OperationError as exc:
        handler._send_json(exc.status, {"error": str(exc)})
    except (ValueError, TypeError, KeyError):
        handler._send_json(400, {"error": "Parâmetros inválidos."})
    except Exception:
        handler._send_json(503, {"error": "Plataforma indisponível; consulte o log do serviço."})
    return True


def authorize_legacy(handler, path):
    from pathlib import Path
    if Path("/run/eyemole-maintenance").exists() and handler.command == "POST":
        handler._send_json(503, {"error": "Atualização em andamento."})
        return False
    if path in {"/health", "/update-status"} or path.startswith("/sbom/"):
        return True
    try:
        if legacy_allowed(load_config(), handler._get_remote_user()):
            return True
        handler._send_json(403, {"error": "Endpoint sem filtro de escopo; use a plataforma operacional."})
    except OperationError as exc:
        handler._send_json(exc.status, {"error": str(exc)})
    return False
