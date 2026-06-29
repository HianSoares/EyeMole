#!/usr/bin/env python3
"""
soar_api.py - HMG Wazuh SOAR Brain API (Fase 1)

API local mínima para disparar análises sob demanda.
- Escuta APENAS em 127.0.0.1:8765 (não exposta na rede)
- Usa apenas bibliotecas padrão do Python
- Não acessa credenciais, Wazuh API ou OpenSearch diretamente
- Dispara análises via wrapper sudo restrito

Endpoints:
  GET  /health       → Healthcheck simples
  GET  /status       → Status do service, timer e relatórios
  POST /run-analysis → Disparar hmg-soar-report.service
"""

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse, parse_qs

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


def _is_service_active() -> bool:
    """Verifica se hmg-soar-report.service está ativo (rodando) via wrapper."""
    exit_code, stdout, _ = _run_wrapper(WRAPPER_STATUS)
    if exit_code == 0 and stdout:
        try:
            data = json.loads(stdout)
            return data.get("report_service_active", False)
        except (json.JSONDecodeError, KeyError):
            pass
    return False


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
        if self.path == "/run-analysis":
            self._handle_run_analysis()
        else:
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
        # Obter status via wrapper
        exit_code, stdout, stderr = _run_wrapper(WRAPPER_STATUS)

        service_status = {}
        if exit_code == 0 and stdout:
            try:
                service_status = json.loads(stdout)
            except json.JSONDecodeError:
                service_status = {"raw": stdout}

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

        # Regra para serviço de relatório (unidade oneshot/pontual):
        # active/running               => "Executando"
        # inactive/dead + exit_code==0 => "Pronto (Ocioso)"
        # failed ou exit_code != 0     => "Falha"
        # demais casos                 => "Desconhecido"
        if svc_active in ("active", "activating") and svc_sub in ("running", "start"):
            report_status_label = "Executando"
            report_status_class = "status-running"
        elif svc_active == "inactive" and svc_sub == "dead" and exit_code == 0:
            report_status_label = "Pronto (Ocioso)"
            report_status_class = "status-ready"
        elif svc_active == "failed" or exit_code != 0:
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

        if exit_code != 0:
            response["wrapper_error"] = stderr

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
