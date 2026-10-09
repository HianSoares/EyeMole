"""Root-configured identity, project and asset authorization."""
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

CONFIG_PATH = Path("/etc/hmg-soar/platform.json")
PERMISSIONS = {
    "admin": {"read", "write", "approve", "accept", "integrate", "execute"},
    "analyst": {"read", "write", "integrate"},
    "owner": {"read", "write"},
    "auditor": {"read"},
}


class OperationError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def load_config(path=None):
    try:
        data = json.loads((path or CONFIG_PATH).read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("users", {}), dict):
            raise ValueError()
        return data
    except FileNotFoundError:
        return {"enabled": False, "users": {}, "projects": {}}
    except (OSError, ValueError):
        # An invalid access policy never disables enforcement.
        raise OperationError("Política de acesso inválida; administrador deve verificar platform.json.", 503)


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    projects: tuple
    agents: tuple

    def require(self, permission, project=None, agents=()):
        if permission not in PERMISSIONS.get(self.role, set()):
            raise OperationError("Permissão insuficiente.", 403)
        if project and project not in self.projects and "*" not in self.projects:
            raise OperationError("Projeto fora do escopo do usuário.", 403)
        if self.agents and any(str(a) not in self.agents for a in agents):
            raise OperationError("Ativo fora do escopo do usuário.", 403)


def principal(config, username):
    if not config.get("enabled"):
        raise OperationError("Configure os usuários e habilite a plataforma em platform.json.", 503)
    entry = config.get("users", {}).get(username)
    if not isinstance(entry, dict) or entry.get("role") not in PERMISSIONS:
        raise OperationError("Usuário não autorizado na plataforma.", 403)
    projects = entry.get("projects", [])
    agents = entry.get("agent_ids", [])
    if not isinstance(projects, list) or not isinstance(agents, list):
        raise OperationError("Escopo de acesso inválido.", 403)
    return Principal(username, entry["role"], tuple(projects), tuple(str(a) for a in agents))


def project_config(config, project):
    entry = config.get("projects", {}).get(project)
    if not isinstance(entry, dict):
        raise OperationError("Projeto não configurado.", 404)
    return entry


def legacy_allowed(config, username):
    """Old dashboards contain unfiltered snapshots: restricted users use Operations."""
    if not config.get("enabled"):
        return True
    p = principal(config, username)
    return p.role == "admin" and "*" in p.projects and not p.agents


def authenticated_identity(headers, config):
    auth = config.get("authentication", {})
    if auth.get("mode", "basic") == "basic":
        return headers.get("X-Remote-User", "unknown")
    if auth.get("mode") != "oidc":
        raise OperationError("Modo de autenticação inválido.", 503)
    endpoint = auth.get("auth_proxy_url", "http://127.0.0.1:4180/oauth2/auth")
    parsed = urlsplit(endpoint)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.path != "/oauth2/auth" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise OperationError("Auth proxy deve ser local e usar /oauth2/auth.", 503)
    cookie = headers.get("Cookie", "")
    if not cookie or len(cookie) > 16384:
        raise OperationError("Sessão corporativa necessária.", 401)
    try:
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        response = build_opener(ProxyHandler({}), NoRedirect()).open(Request(endpoint, headers={"Cookie": cookie}), timeout=5)
        with response:
            if response.geturl() != endpoint:
                raise OperationError("Auth proxy redirecionou a requisição.", 503)
            user = response.headers.get("X-Auth-Request-User")
            if not user or len(user) > 256:
                raise OperationError("Identidade corporativa ausente.", 401)
            return user
    except HTTPError as exc:
        raise OperationError("Sessão corporativa inválida.", 401 if exc.code in {401, 403} else 503)
    except (URLError, TimeoutError):
        raise OperationError("Auth proxy indisponível.", 503)
