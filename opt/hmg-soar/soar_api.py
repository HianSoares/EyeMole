#!/usr/bin/env python3
"""
soar_api.py - HMG Wazuh SOAR Brain API (Fase 1)

API local mínima para disparar análises sob demanda.
- Escuta APENAS em 127.0.0.1:8765 (não exposta na rede)
- Usa apenas bibliotecas padrão do Python
- Não acessa credenciais, Wazuh API ou OpenSearch diretamente
- STATUS: lido diretamente via `systemctl show` (somente leitura, SEM sudo)
- MODO SEGURO (padrão): sem sudoers; execução manual via web desabilitada (403)
- MODO OPT-IN (EYEMOLE_ENABLE_WEB_RUN): dispara análise via wrapper sudo restrito

Endpoints:
  GET  /health       → Healthcheck simples
  GET  /status       → Status do service, timer e relatórios
  POST /run-analysis → Disparar hmg-soar-report.service
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse, parse_qs, unquote

# ==========================================
# CONFIGURAÇÃO
# ==========================================

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8765

# Wrappers seguros (root-owned, sem argumentos)
WRAPPER_RUN_ANALYSIS = "/usr/local/sbin/hmg-soar-run-analysis"
WRAPPER_STATUS = "/usr/local/sbin/hmg-soar-status"

# Diretórios do relatório
WEB_DIR = Path("/var/www/wazuh-soar")
INDEX_HTML = WEB_DIR / "index.html"
LATEST_JSON = WEB_DIR / "data" / "latest.json"
REPORTS_DIR = WEB_DIR / "reports"

# Auditoria
AUDIT_DIR = Path("/var/www/wazuh-soar/data")
AUDIT_LOG = AUDIT_DIR / "audit_actions.jsonl"

# ==========================================
# CLASSIFICAÇÃO DE ATIVOS VIA WEB (somente edição de JSON local)
# ==========================================
APP_DIR = Path("/opt/hmg-soar")
CONFIG_DIR = APP_DIR / "config"
# ÚNICO arquivo autorizado para escrita de contexto de ativos.
ASSETS_CONTEXT_JSON = CONFIG_DIR / "assets_context.json"

# Auditoria específica de contexto (separada, conforme requisito de segurança).
CONTEXT_AUDIT_DIR = APP_DIR / "audit"
CONTEXT_AUDIT_LOG = CONTEXT_AUDIT_DIR / "audit_actions.jsonl"

# Limites e listas de validação (defesa em profundidade).
MAX_BODY_BYTES = 16 * 1024          # 16 KB
MAX_TEXT_LEN = 256                  # donos técnico/negócio
MAX_NOTES_LEN = 1000               # observações
MAX_AGENT_ID_LEN = 64

ALLOWED_CRITICALITY = {"critical", "high", "medium", "low", "unknown"}
ALLOWED_ENVIRONMENT = {"prod", "hmg", "dev", "test", "unknown"}
ALLOWED_EXPOSURE = {"internal", "dmz", "internet", "unknown"}
AGENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,%d}$" % MAX_AGENT_ID_LEN)

# Campos de texto (e seus limites) aceitos do payload.
TEXT_FIELDS = {"technical_owner": MAX_TEXT_LEN, "business_owner": MAX_TEXT_LEN, "notes": MAX_NOTES_LEN}
# Campos retornados (sanitizados) na leitura do contexto.
PUBLIC_AGENT_FIELDS = (
    "id", "asset_name", "hostname", "asset_type", "criticality", "environment",
    "exposure", "technical_owner", "business_owner", "is_critical_service",
    "notes", "classification_status", "tags",
)


# Lock para evitar execuções concorrentes via API
_run_lock = Lock()

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("hmg-soar-api")


# ==========================================
# AUDITORIA
# ==========================================

def audit_log(action: str, remote_user: str, client_ip: str,
              result: str, exit_code: int = None, message: str = "") -> None:
    """Registra ação em JSONL no arquivo de auditoria."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "remote_user": remote_user or "unknown",
        "client_ip": client_ip or "unknown",
        "result": result,
        "exit_code": exit_code,
        "message": message,
    }

    try:
        try:
            AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as e:
        logger.error(f"Falha ao gravar auditoria: {e}")


# ==========================================
# UTILIDADES
# ==========================================

def _get_file_mtime_iso(path: Path) -> str:
    """Retorna mtime de um arquivo em ISO 8601, ou 'N/A'."""
    try:
        if path.exists():
            mtime = path.stat().st_mtime
            return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
    except OSError:
        pass
    return "N/A"


def _get_latest_report() -> str:
    """Retorna o nome do relatório mais recente em reports/."""
    try:
        if REPORTS_DIR.exists():
            reports = sorted(REPORTS_DIR.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
            if reports:
                return reports[0].name
    except OSError:
        pass
    return "N/A"


def _run_wrapper(wrapper_path: str) -> tuple:
    """
    Executa um wrapper via sudo. Retorna (exit_code, stdout, stderr).
    Não aceita argumentos — o wrapper é fixo.
    """
    if not os.path.isfile(wrapper_path):
        return (-1, "", f"Wrapper não encontrado: {wrapper_path}")

    try:
        result = subprocess.run(
            ["sudo", "-n", wrapper_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return (result.returncode, result.stdout.strip(), result.stderr.strip())
    except subprocess.TimeoutExpired:
        return (-2, "", "Timeout ao executar wrapper")
    except OSError as e:
        return (-3, "", str(e))


def _systemctl_show(unit: str, properties: list) -> dict:
    """Lê propriedades de uma unit via 'systemctl show', SEM privilégio (somente leitura).

    Nunca usa sudo. Retorna dict {Propriedade: valor} ou None se o comando não
    puder ser executado (systemctl ausente, timeout, etc.).
    """
    try:
        cmd = ["systemctl", "show", unit, "--no-page"]
        for prop in properties:
            cmd.extend(["-p", prop])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    data = {}
    for line in result.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            data[key.strip()] = value.strip()
    return data or None


def _collect_status_direct() -> dict:
    """Coleta status do serviço e do timer diretamente via systemctl show (sem sudo).

    Retorna estrutura compatível com a usada pela API, ou None se indisponível
    (permitindo resposta degradada segura, sem erro 500).
    """
    svc = _systemctl_show(
        "hmg-soar-report.service",
        ["ActiveState", "SubState", "UnitFileState", "ExecMainStatus", "Result"],
    )
    timer = _systemctl_show(
        "hmg-soar-report.timer",
        ["ActiveState", "SubState", "UnitFileState", "LoadState",
         "NextElapseUSecRealtime", "LastTriggerUSec"],
    )

    if svc is None and timer is None:
        return None

    svc = svc or {}
    timer = timer or {}
    active_state = svc.get("ActiveState", "unknown")
    return {
        "report_service_active": active_state in ("active", "activating"),
        "active_state": active_state,
        "sub_state": svc.get("SubState", "unknown"),
        "unit_file_state": svc.get("UnitFileState", "unknown"),
        "exec_main_status": svc.get("ExecMainStatus", ""),
        "result": svc.get("Result", "unknown"),
        "timer_info": {
            "active_state": timer.get("ActiveState", "unknown"),
            "sub_state": timer.get("SubState", "unknown"),
            "unit_file_state": timer.get("UnitFileState", "unknown"),
            "load_state": timer.get("LoadState", "unknown"),
            "next_elapse": timer.get("NextElapseUSecRealtime", ""),
            "last_trigger": timer.get("LastTriggerUSec", ""),
        },
    }


def _web_run_enabled() -> bool:
    """Indica se a execução manual privilegiada via web está habilitada.

    Só é verdadeira no modo opt-in (EYEMOLE_ENABLE_WEB_RUN / --enable-web-run),
    quando o install.sh instalou o wrapper sudo. No modo seguro padrão (sem
    sudoers) retorna False e a API nunca tenta usar sudo.
    """
    return os.path.isfile(WRAPPER_RUN_ANALYSIS)


def _is_service_active() -> bool:
    """Verifica se hmg-soar-report.service está ativo (rodando), leitura direta sem sudo."""
    status = _collect_status_direct()
    if status:
        return bool(status.get("report_service_active", False))
    return False


# ==========================================
# CONTEXTO DE ATIVOS — utilidades seguras
# ==========================================

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_text(value, max_len: int) -> str:
    """Sanitiza um campo de texto livre: força str, remove caracteres de controle,
    normaliza espaços nas pontas e trunca no limite. Nunca executa nada."""
    if value is None:
        return ""
    if not isinstance(value, str):
        # Não tentamos interpretar tipos inesperados como texto executável.
        value = str(value)
    value = _CONTROL_CHARS_RE.sub("", value)
    value = value.replace("\r", " ").replace("\n", " ").strip()
    if len(value) > max_len:
        value = value[:max_len]
    return value


def _context_audit_log(remote_addr: str, user: str, agent_id: str,
                       changed_fields: list, result: str, message: str) -> None:
    """Registra evento de classificação em audit_actions.jsonl (JSONL).

    Nunca registra valores sensíveis: apenas nomes dos campos alterados.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "remote_addr": remote_addr or "unknown",
        "user": user or "unknown",
        "action": "update_asset_context",
        "agent_id": agent_id or "unknown",
        "changed_fields": changed_fields or [],
        "result": result,
        "message": message,
    }
    try:
        CONTEXT_AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    try:
        with open(CONTEXT_AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as e:
        logger.error(f"Falha ao gravar auditoria de contexto: {e}")


def _atomic_write_assets_context(data: dict) -> None:
    """Escreve o JSON de contexto de forma atômica e segura.

    - Só escreve em ASSETS_CONTEXT_JSON (caminho fixo; agent_id nunca vira path).
    - Faz backup do arquivo atual.
    - Grava em arquivo temporário no MESMO diretório, valida o JSON e troca com
      os.replace (atômico). Mantor permissões 0640 e owner/grupo do serviço.
    """
    target = ASSETS_CONTEXT_JSON
    # Garantia explícita: jamais escrever fora do arquivo autorizado.
    if Path(target).resolve() != Path(ASSETS_CONTEXT_JSON).resolve():
        raise ValueError("Caminho de escrita não autorizado")

    target.parent.mkdir(parents=True, exist_ok=True)

    # Backup do arquivo atual (se existir).
    if target.exists():
        try:
            shutil.copy2(target, target.with_name(target.name + ".bak"))
        except OSError as e:
            logger.warning(f"Não foi possível criar backup do contexto: {e}")

    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_assets_ctx_", suffix=".json",
                                    dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            json.dump(data, tmp, indent=4, ensure_ascii=False)
            tmp.flush()
            os.fsync(tmp.fileno())

        # Validar que o arquivo temporário é JSON válido antes de promover.
        with open(tmp_path, "r", encoding="utf-8") as f:
            json.load(f)

        os.replace(tmp_path, target)
        tmp_path = None  # promovido com sucesso

        try:
            os.chmod(target, 0o640)
        except OSError:
            pass

        # Melhor esforço para manter owner/grupo compatível com o serviço.
        try:
            import pwd
            import grp
            uid = pwd.getpwnam("hmg-soar").pw_uid
            gid = grp.getgrnam("www-data").gr_gid
            os.chown(target, uid, gid)
        except (KeyError, PermissionError, OSError):
            pass
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _sanitize_agent_for_output(agent_id: str, agent: dict) -> dict:
    """Retorna apenas campos públicos de um ativo (sem caminhos internos/segredos)."""
    out = {"agent_id": agent_id}
    if isinstance(agent, dict):
        for key in PUBLIC_AGENT_FIELDS:
            if key in agent:
                out[key] = agent[key]
    return out


# ==========================================
# HTTP HANDLER
# ==========================================

class SoarAPIHandler(BaseHTTPRequestHandler):
    """Handler HTTP para a API local do SOAR."""

    def _get_remote_user(self) -> str:
        return self.headers.get("X-Remote-User", "unknown")

    def _get_client_ip(self) -> str:
        return (
            self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or self.headers.get("X-Real-IP", "")
            or self.client_address[0]
        )

    def _send_json(self, status_code: int, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_method_not_allowed(self) -> None:
        self._send_json(405, {"error": "Método não permitido"})

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)

        if path == "/health":
            self._handle_health()
        elif path == "/status":
            self._handle_status()
        elif path == "/audit-actions":
            self._handle_audit_actions(query_params)
        elif path == "/risk-summary":
            self._handle_risk_summary()
        elif path == "/risk-delta":
            self._handle_risk_delta()
        elif path == "/asset-context":
            self._handle_asset_context()
        elif path in ("/assets-context", "/context/assets"):
            self._handle_get_assets_context()
        elif path == "/exposure-context":
            self._handle_exposure_context()
        elif path == "/sla-summary":
            self._handle_sla_summary()
        elif path == "/risk-acceptance":
            self._handle_risk_acceptance()
        elif path == "/trend-summary":
            self._handle_trend_summary()
        elif path == "/treatment-plan":
            self._handle_treatment_plan()
        else:
            self._send_json(404, {"error": "Endpoint não encontrado"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path

        if path == "/run-analysis":
            self._handle_run_analysis()
            return

        # POST /assets-context/<agent_id>  (ou /context/assets/<agent_id>)
        for prefix in ("/assets-context/", "/context/assets/"):
            if path.startswith(prefix):
                raw_agent_id = unquote(path[len(prefix):])
                self._handle_update_asset_context(raw_agent_id)
                return

        self._send_json(404, {"error": "Endpoint não encontrado"})

    def do_PUT(self) -> None:
        self._send_method_not_allowed()

    def do_DELETE(self) -> None:
        self._send_method_not_allowed()

    def do_PATCH(self) -> None:
        self._send_method_not_allowed()

    # --- Endpoints ---

    def _handle_health(self) -> None:
        self._send_json(200, {
            "status": "ok",
            "service": "hmg-soar-api",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def _handle_status(self) -> None:
        # Modo de operação: 'safe_no_sudoers' (padrão) ou 'web_run_enabled' (opt-in).
        action_mode = "web_run_enabled" if _web_run_enabled() else "safe_no_sudoers"

        # Status é lido diretamente via systemctl show (somente leitura, SEM sudo),
        # funcionando tanto no modo seguro quanto no opt-in.
        service_status = _collect_status_direct()

        if not service_status:
            # systemctl indisponível/sem permissão: degradar com segurança (sem erro 500).
            self._send_json(200, {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action_mode": action_mode,
                "service_info": {
                    "report_service_active": False,
                    "active_state": "unknown",
                    "sub_state": "unknown",
                    "unit_file_state": "unknown",
                    "exec_main_status": "",
                    "result": "unknown",
                },
                "timer_info": {
                    "active_state": "unknown",
                    "sub_state": "unknown",
                    "unit_file_state": "unknown",
                    "load_state": "unknown",
                    "next_elapse": "",
                    "last_trigger": "",
                },
                "report_status_label": "Indisponível",
                "report_status_class": "status-unknown",
                "timer_status_label": "Indisponível",
                "timer_status_class": "status-unknown",
                "index_html_mtime": _get_file_mtime_iso(INDEX_HTML),
                "latest_json_mtime": _get_file_mtime_iso(LATEST_JSON),
                "latest_report": _get_latest_report(),
                "wrapper_exit_code": None,
            })
            return

        # Extrair estados do serviço de relatório
        svc_active = service_status.get("active_state", "unknown")
        svc_sub = service_status.get("sub_state", "unknown")
        svc_unit_file_state = service_status.get("unit_file_state", "unknown")
        svc_exec_main_status = service_status.get("exec_main_status", "")
        svc_result = service_status.get("result", "unknown")

        # Extrair estados do timer
        timer_info = service_status.get("timer_info", {})
        timer_active = timer_info.get("active_state", "unknown")
        timer_sub = timer_info.get("sub_state", "unknown")
        timer_unit_file_state = timer_info.get("unit_file_state", "unknown")
        timer_load_state = timer_info.get("load_state", "unknown")
        timer_next_elapse = timer_info.get("next_elapse", "")
        timer_last_trigger = timer_info.get("last_trigger", "")

        # Código de saída lógico do último ExecMain do serviço oneshot (sem sudo).
        try:
            exit_code = int(svc_exec_main_status) if svc_exec_main_status != "" else 0
        except (ValueError, TypeError):
            exit_code = 0

        # Regra para serviço de relatório (unidade oneshot/pontual):
        # active/running                          => "Executando"
        # inactive/dead + result success/exit 0   => "Pronto (Ocioso)"
        # failed ou result de falha/exit != 0     => "Falha"
        # demais casos                            => "Desconhecido"
        if svc_active in ("active", "activating") and svc_sub in ("running", "start"):
            report_status_label = "Executando"
            report_status_class = "status-running"
        elif (svc_active == "inactive" and svc_sub == "dead"
              and svc_result in ("success", "") and exit_code == 0):
            report_status_label = "Pronto (Ocioso)"
            report_status_class = "status-ready"
        elif svc_active == "failed" or svc_result not in ("success", "") or exit_code != 0:
            report_status_label = "Falha"
            report_status_class = "status-failed"
        else:
            report_status_label = "Desconhecido"
            report_status_class = "status-unknown"

        # Regra para timer (independente do exit_code do wrapper do serviço):
        # active/waiting ou active/running => "Ativo"
        # inactive/dead                    => "Inativo"
        # failed                           => "Falha"
        # demais casos                     => "Desconhecido"
        if timer_active in ("active", "activating") and timer_sub in ("waiting", "running"):
            timer_status_label = "Ativo"
            timer_status_class = "status-active"
        elif timer_active == "inactive" and timer_sub == "dead":
            timer_status_label = "Inativo"
            timer_status_class = "status-inactive"
        elif timer_active == "failed":
            timer_status_label = "Falha"
            timer_status_class = "status-failed"
        else:
            timer_status_label = "Desconhecido"
            timer_status_class = "status-unknown"

        response = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_mode": action_mode,
            "service_info": {
                "report_service_active": service_status.get("report_service_active", False),
                "active_state": svc_active,
                "sub_state": svc_sub,
                "unit_file_state": svc_unit_file_state,
                "exec_main_status": svc_exec_main_status,
                "result": svc_result,
            },
            "timer_info": {
                "active_state": timer_active,
                "sub_state": timer_sub,
                "unit_file_state": timer_unit_file_state,
                "load_state": timer_load_state,
                "next_elapse": timer_next_elapse,
                "last_trigger": timer_last_trigger,
            },
            "report_status_label": report_status_label,
            "report_status_class": report_status_class,
            "timer_status_label": timer_status_label,
            "timer_status_class": timer_status_class,
            "index_html_mtime": _get_file_mtime_iso(INDEX_HTML),
            "latest_json_mtime": _get_file_mtime_iso(LATEST_JSON),
            "latest_report": _get_latest_report(),
            "wrapper_exit_code": exit_code,
        }

        self._send_json(200, response)

    def _handle_audit_actions(self, query_params: dict) -> None:
        limit = 10
        if "limit" in query_params:
            try:
                val = int(query_params["limit"][0])
                if val > 0:
                    limit = min(val, 50)
            except (ValueError, IndexError):
                pass

        actions = []
        if AUDIT_LOG.exists() and AUDIT_LOG.is_file():
            try:
                with open(AUDIT_LOG, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            actions.append(entry)
                        except json.JSONDecodeError:
                            continue
            except OSError as e:
                logger.error(f"Erro ao ler arquivo de auditoria: {e}")

        last_actions = actions[-limit:]
        last_actions.reverse()

        response = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source": str(AUDIT_LOG),
            "limit": limit,
            "count": len(last_actions),
            "actions": last_actions,
        }
        self._send_json(200, response)

    def _handle_risk_summary(self) -> None:
        risk_summary_path = WEB_DIR / "data" / "risk_summary.json"
        if risk_summary_path.exists() and risk_summary_path.is_file():
            try:
                with open(risk_summary_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._send_json(200, data)
                return
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Erro ao ler risk_summary.json: {e}")

        # Retorno degraded se não encontrar ou falhar ao ler
        self._send_json(200, {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "degraded",
            "source": str(risk_summary_path),
            "summary": {
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "kev_count": 0,
                "epss_high_count": 0,
                "affected_agents": 0,
                "packages_affected": 0,
                "report_age_minutes": 0
            },
            "top_priorities": [],
            "alerts": [
                {
                    "level": "warning",
                    "title": "Dados de Risco Indisponíveis",
                    "message": "O arquivo de inteligência de risco não foi encontrado ou está ilegível."
                }
            ]
        })

    def _handle_risk_delta(self) -> None:
        risk_delta_path = WEB_DIR / "data" / "risk_delta.json"
        if risk_delta_path.exists() and risk_delta_path.is_file():
            try:
                with open(risk_delta_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._send_json(200, data)
                return
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Erro ao ler risk_delta.json: {e}")

        # Retorno no_baseline/degraded se não encontrar ou falhar ao ler
        self._send_json(200, {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "no_baseline",
            "baseline_available": False,
            "current_snapshot": None,
            "previous_snapshot": None,
            "delta": {
                "new_vulnerabilities": 0,
                "resolved_vulnerabilities": 0,
                "persistent_vulnerabilities": 0,
                "new_kev": 0,
                "resolved_kev": 0,
                "new_critical": 0,
                "resolved_critical": 0,
                "agents_worsened": 0,
                "agents_improved": 0
            },
            "new_items": [],
            "resolved_items": [],
            "worsened_agents": [],
            "improved_agents": []
        })

    def _handle_asset_context(self) -> None:
        asset_context_path = WEB_DIR / "data" / "asset_context_summary.json"
        if asset_context_path.exists() and asset_context_path.is_file():
            try:
                with open(asset_context_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._send_json(200, data)
                return
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Erro ao ler asset_context_summary.json: {e}")

        # Retorno degraded se não encontrar ou falhar ao ler
        self._send_json(200, {
            "status": "degraded",
            "message": "Ativo pendente de classificação",
            "assets": {
                "total_seen": 0,
                "classified": 0,
                "unclassified": 0
            }
        })

    # --- Classificação de ativos via web (somente edição de JSON local) ---

    def _read_assets_context_file(self):
        """Lê ASSETS_CONTEXT_JSON. Retorna (data, error_dict, http_status)."""
        if not ASSETS_CONTEXT_JSON.exists() or not ASSETS_CONTEXT_JSON.is_file():
            return None, {"status": "error",
                          "message": "Arquivo de contexto de ativos não encontrado."}, 404
        try:
            with open(ASSETS_CONTEXT_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            return None, {"status": "error",
                          "message": "JSON de contexto de ativos inválido."}, 422
        except OSError as e:
            logger.error(f"Erro ao ler assets_context.json: {e}")
            return None, {"status": "error",
                          "message": "Falha ao ler o contexto de ativos."}, 500
        if not isinstance(data, dict):
            return None, {"status": "error",
                          "message": "Estrutura de contexto inválida."}, 422
        return data, None, 200

    def _handle_get_assets_context(self) -> None:
        data, error, status = self._read_assets_context_file()
        if error is not None:
            self._send_json(status, error)
            return

        agents = data.get("agents", {})
        if not isinstance(agents, dict):
            agents = {}

        sanitized = {}
        for agent_id, agent in agents.items():
            # Ignora chaves de ativo com formato inesperado.
            if not isinstance(agent_id, str) or not AGENT_ID_RE.match(agent_id):
                continue
            sanitized[agent_id] = _sanitize_agent_for_output(agent_id, agent)

        defaults = data.get("defaults", {})
        if not isinstance(defaults, dict):
            defaults = {}

        self._send_json(200, {
            "status": "ok",
            "action_mode": "web_run_enabled" if _web_run_enabled() else "safe_no_sudoers",
            "count": len(sanitized),
            "agents": sanitized,
            "defaults": defaults,
            "allowed": {
                "criticality": sorted(ALLOWED_CRITICALITY),
                "environment": sorted(ALLOWED_ENVIRONMENT),
                "exposure": sorted(ALLOWED_EXPOSURE),
            },
        })

    def _origin_is_allowed(self) -> bool:
        """Proteção mínima contra CSRF: se Origin/Referer estiver presente, seu host
        deve bater com o Host da requisição. Ausência é tolerada (cliente curl/SSR)."""
        host = (self.headers.get("Host") or "").strip().lower()
        for header in ("Origin", "Referer"):
            value = self.headers.get(header)
            if not value:
                continue
            try:
                netloc = urlparse(value).netloc.lower()
            except ValueError:
                return False
            if not netloc:
                continue
            if host and netloc != host:
                return False
        return True

    def _handle_update_asset_context(self, raw_agent_id: str) -> None:
        remote_user = self._get_remote_user()
        client_ip = self._get_client_ip()

        def fail(http_status, message, changed=None, audit=True):
            if audit:
                _context_audit_log(client_ip, remote_user, raw_agent_id[:MAX_AGENT_ID_LEN],
                                   changed or [], "failure", message)
            self._send_json(http_status, {"status": "error", "message": message})

        # 1) agent_id seguro (sem path traversal / caracteres perigosos).
        agent_id = raw_agent_id.strip()
        if not AGENT_ID_RE.match(agent_id):
            fail(400, "agent_id inválido (use apenas letras, números, hífen e underscore).")
            return

        # 2) CSRF / Origin.
        if not self._origin_is_allowed():
            fail(403, "Origem da requisição não permitida.")
            return

        # 3) Content-Type estritamente application/json.
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            fail(415, "Content-Type deve ser application/json.")
            return

        # 4) Tamanho do payload (<= 16 KB).
        try:
            content_length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            fail(400, "Content-Length inválido.")
            return
        if content_length <= 0:
            fail(400, "Corpo da requisição vazio.")
            return
        if content_length > MAX_BODY_BYTES:
            fail(413, "Payload excede o limite de 16 KB.")
            return

        raw_body = self.rfile.read(content_length)
        if len(raw_body) > MAX_BODY_BYTES:
            fail(413, "Payload excede o limite de 16 KB.")
            return

        # 5) Parse JSON.
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            fail(400, "JSON do corpo inválido.")
            return
        if not isinstance(payload, dict):
            fail(400, "Payload deve ser um objeto JSON.")
            return

        # 6) Validar campos (apenas os permitidos são considerados).
        updates = {}
        changed_fields = []

        if "criticality" in payload:
            crit = payload["criticality"]
            if not isinstance(crit, str) or crit not in ALLOWED_CRITICALITY:
                fail(400, "criticality inválida.")
                return
            updates["criticality"] = crit
            changed_fields.append("criticality")

        if "environment" in payload:
            env = payload["environment"]
            if not isinstance(env, str) or env not in ALLOWED_ENVIRONMENT:
                fail(400, "environment inválido.")
                return
            updates["environment"] = env
            changed_fields.append("environment")

        if "exposure" in payload:
            expo = payload["exposure"]
            if not isinstance(expo, str) or expo not in ALLOWED_EXPOSURE:
                fail(400, "exposure inválida.")
                return
            updates["exposure"] = expo
            updates["exposure_level"] = expo
            changed_fields.append("exposure")
            changed_fields.append("exposure_level")

        if "is_critical_service" in payload:
            ics = payload["is_critical_service"]
            if not isinstance(ics, bool):
                fail(400, "is_critical_service deve ser booleano.")
                return
            updates["is_critical_service"] = ics
            changed_fields.append("is_critical_service")

        for field, max_len in TEXT_FIELDS.items():
            if field in payload:
                updates[field] = _sanitize_text(payload[field], max_len)
                changed_fields.append(field)

        if not updates:
            fail(400, "Nenhum campo válido para atualização.")
            return

        # 7) Carregar contexto atual (ou estrutura mínima).
        if ASSETS_CONTEXT_JSON.exists():
            data, error, status = self._read_assets_context_file()
            if error is not None:
                self._send_json(status, error)
                _context_audit_log(client_ip, remote_user, agent_id, changed_fields,
                                   "failure", error.get("message", "leitura inválida"))
                return
        else:
            data = {}

        if not isinstance(data.get("agents"), dict):
            data["agents"] = {}

        agent = data["agents"].get(agent_id)
        if not isinstance(agent, dict):
            agent = {
                "id": agent_id,
                "asset_name": f"agent-{agent_id}",
                "hostname": f"agent-{agent_id}",
                "criticality": "unknown",
                "environment": "unknown",
                "exposure": "unknown",
                "technical_owner": "unknown",
                "business_owner": "unknown",
                "is_critical_service": False,
                "notes": "",
                "classification_status": "pending",
                "tags": [],
            }

        agent.update(updates)

        # 8) classification_status derivado da criticidade final.
        final_crit = agent.get("criticality", "unknown")
        agent["classification_status"] = "pending" if final_crit == "unknown" else "classified"

        data["agents"][agent_id] = agent

        # Metadados (sem segredos).
        if not isinstance(data.get("metadata"), dict):
            data["metadata"] = {}
        data["metadata"]["updated_at"] = datetime.now(timezone.utc).isoformat()
        data["metadata"]["updated_by"] = f"web:{remote_user}" if remote_user and remote_user != "unknown" else "web"

        # 9) Escrita atômica e segura no único arquivo autorizado.
        try:
            _atomic_write_assets_context(data)
        except (OSError, ValueError) as e:
            logger.error(f"Falha ao gravar contexto de ativos: {e}")
            fail(500, "Falha ao gravar o contexto de ativos.", changed=changed_fields)
            return

        _context_audit_log(client_ip, remote_user, agent_id, changed_fields,
                           "success", f"Contexto do ativo {agent_id} atualizado via web.")

        self._send_json(200, {
            "status": "success",
            "message": "Contexto salvo. A priorização completa será refletida no próximo "
                       "relatório automático ou após execução manual via SSH.",
            "agent_id": agent_id,
            "classification_status": agent["classification_status"],
            "changed_fields": changed_fields,
            "agent": _sanitize_agent_for_output(agent_id, agent),
        })

    def _handle_exposure_context(self) -> None:
        exposure_context_path = WEB_DIR / "data" / "exposure_context_summary.json"
        if exposure_context_path.exists() and exposure_context_path.is_file():
            try:
                with open(exposure_context_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._send_json(200, data)
                return
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Erro ao ler exposure_context_summary.json: {e}")

        # Retorno degraded se não encontrar ou falhar ao ler
        self._send_json(200, {
            "status": "degraded",
            "message": "Contexto de exposição pendente",
            "assets": {
                "total_seen": 0,
                "with_exposure_context": 0,
                "without_exposure_context": 0
            }
        })

    def _handle_sla_summary(self) -> None:
        sla_summary_path = WEB_DIR / "data" / "sla_summary.json"
        if sla_summary_path.exists() and sla_summary_path.is_file():
            try:
                with open(sla_summary_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._send_json(200, data)
                return
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Erro ao ler sla_summary.json: {e}")

        # Retorno degraded se não encontrar ou falhar ao ler
        self._send_json(200, {
            "status": "degraded",
            "message": "Owner técnico pendente",
            "summary": {
                "total_open": 0,
                "overdue": 0,
                "due_soon": 0,
                "within_sla": 0,
                "unknown": 0
            }
        })

    def _handle_risk_acceptance(self) -> None:
        risk_acceptance_summary_path = WEB_DIR / "data" / "risk_acceptance_summary.json"
        if risk_acceptance_summary_path.exists() and risk_acceptance_summary_path.is_file():
            try:
                with open(risk_acceptance_summary_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._send_json(200, data)
                return
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Erro ao ler risk_acceptance_summary.json: {e}")

        # Retorno degraded se não encontrar ou falhar ao ler
        self._send_json(200, {
            "status": "degraded",
            "message": "Risk acceptance summary not available yet",
            "summary": {
                "rules_total": 0,
                "matched_vulnerabilities": 0,
                "accepted": 0,
                "false_positive": 0,
                "expired": 0
            }
        })

    def _handle_trend_summary(self) -> None:
        trend_summary_path = WEB_DIR / "data" / "trend_summary.json"
        if trend_summary_path.exists() and trend_summary_path.is_file():
            try:
                with open(trend_summary_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._send_json(200, data)
                return
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Erro ao ler trend_summary.json: {e}")

        # Retorno degraded se não encontrar ou falhar ao ler
        self._send_json(200, {
            "status": "degraded",
            "message": "Trend summary not available yet",
            "summary": {
                "snapshots_analyzed": 0,
                "trend_status": "unknown",
                "risk_direction": "unknown"
            }
        })

    def _handle_treatment_plan(self) -> None:
        treatment_plan_path = WEB_DIR / "data" / "treatment_plan_summary.json"
        if treatment_plan_path.exists() and treatment_plan_path.is_file():
            try:
                with open(treatment_plan_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._send_json(200, data)
                return
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Erro ao ler treatment_plan_summary.json: {e}")

        # Retorno degraded se não encontrar ou falhar ao ler
        self._send_json(200, {
            "status": "degraded",
            "message": "Treatment plan summary not available yet",
            "summary": {
                "total_actionable_items": 0,
                "owners": 0,
                "critical_actions": 0,
                "due_soon_actions": 0
            }
        })

    def _handle_run_analysis(self) -> None:
        remote_user = self._get_remote_user()
        client_ip = self._get_client_ip()

        # Modo seguro (padrão, sem sudoers): execução manual via web desabilitada.
        # NÃO tenta sudo nem systemctl start. Retorna 403 com JSON claro.
        if not _web_run_enabled():
            audit_log(
                action="run-analysis",
                remote_user=remote_user,
                client_ip=client_ip,
                result="disabled",
                message="Execução manual via web desabilitada em modo seguro.",
            )
            self._send_json(403, {
                "status": "disabled",
                "message": "Execução manual via web desabilitada em modo seguro.",
            })
            return

        # Verificar se já está rodando
        if _is_service_active():
            audit_log(
                action="run-analysis",
                remote_user=remote_user,
                client_ip=client_ip,
                result="rejected",
                message="Análise já em execução (service active)",
            )
            self._send_json(409, {
                "status": "conflict",
                "message": "Já existe uma análise em execução. Aguarde a conclusão.",
            })
            return

        # Tentar adquirir lock (proteção contra cliques duplos rápidos)
        if not _run_lock.acquire(blocking=False):
            audit_log(
                action="run-analysis",
                remote_user=remote_user,
                client_ip=client_ip,
                result="rejected",
                message="Lock de concorrência ativo",
            )
            self._send_json(409, {
                "status": "conflict",
                "message": "Requisição de análise já em processamento. Aguarde.",
            })
            return

        try:
            logger.info(f"Disparando análise. Usuário: {remote_user}, IP: {client_ip}")

            exit_code, stdout, stderr = _run_wrapper(WRAPPER_RUN_ANALYSIS)

            if exit_code == 0:
                audit_log(
                    action="run-analysis",
                    remote_user=remote_user,
                    client_ip=client_ip,
                    result="success",
                    exit_code=exit_code,
                    message="Análise disparada com sucesso",
                )
                self._send_json(202, {
                    "status": "accepted",
                    "message": "Análise iniciada com sucesso. O relatório será atualizado em breve.",
                    "triggered_by": remote_user,
                })
            else:
                audit_log(
                    action="run-analysis",
                    remote_user=remote_user,
                    client_ip=client_ip,
                    result="error",
                    exit_code=exit_code,
                    message=f"Falha ao disparar análise: {stderr}",
                )
                self._send_json(500, {
                    "status": "error",
                    "message": "Falha ao iniciar análise. Verifique os logs do servidor.",
                    "exit_code": exit_code,
                })
        finally:
            _run_lock.release()

    def log_message(self, format, *args) -> None:
        """Override para usar logging ao invés de stderr."""
        logger.info(f"{self.client_address[0]} - {format % args}")


# ==========================================
# MAIN
# ==========================================

def main() -> int:
    # API local: classificação de ativos via web edita apenas JSON local (sem sudo).
    logger.info(f"Iniciando HMG SOAR API em {LISTEN_HOST}:{LISTEN_PORT}")
    logger.info(f"Wrapper run-analysis: {WRAPPER_RUN_ANALYSIS}")
    logger.info(f"Wrapper status: {WRAPPER_STATUS}")
    logger.info(f"Audit log: {AUDIT_LOG}")

    # Garantir que diretório de auditoria existe
    try:
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.error(f"Não foi possível criar diretório de auditoria: {e}")
        return 1

    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), SoarAPIHandler)
    logger.info("API pronta. Aguardando requisições...")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Desligando API...")
        server.shutdown()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
