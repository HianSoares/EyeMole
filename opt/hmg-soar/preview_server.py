#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EyeMole / hmg-soar — PREVIEW MOCK SERVER  (DESENVOLVIMENTO VISUAL APENAS)
========================================================================
*** TODOS OS DADOS SERVIDOS POR ESTE ARQUIVO SÃO FICTÍCIOS (MOCK) ***

Serve os arquivos estáticos de var-www-wazuh-soar/ e responde os endpoints
/soar-api/* com payloads FICTÍCIOS compatíveis com o JavaScript do dashboard,
para que os gráficos e tabelas apareçam no preview local — SEM tocar em
produção, APIs reais, credenciais, coleta ou priorização.

Somente biblioteca padrão: http.server, json, pathlib, urllib.parse, datetime.
Sem Flask/FastAPI/requests, sem CDN, sem dependências externas, sem rede externa.

Uso (PowerShell):
    python .\\opt\\hmg-soar\\preview_dashboard.py     # gera o index.html estático
    python .\\opt\\hmg-soar\\preview_server.py         # sobe o mock em :8088
    # abrir:  http://127.0.0.1:8088/index.html

Parâmetros opcionais:
    python .\\opt\\hmg-soar\\preview_server.py --port 8088 --root <dir>

POST /soar-api/run-analysis  -> retorna 200 com mensagem simulada; NÃO executa nada.
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ─────────────────────────────────────────────────────────────────────────────
# Banner / aviso MOCK
# ─────────────────────────────────────────────────────────────────────────────
MOCK_BANNER = "*** PREVIEW MOCK — DADOS FICTÍCIOS — NÃO É PRODUÇÃO ***"

# ─────────────────────────────────────────────────────────────────────────────
# Diretório estático: var-www-wazuh-soar/ relativo à raiz do projeto.
# Estrutura assumida:  <root>/opt/hmg-soar/preview_server.py
#                      <root>/var-www-wazuh-soar/index.html
# ─────────────────────────────────────────────────────────────────────────────
def resolve_static_root(cli_root: str | None) -> Path:
    if cli_root:
        p = Path(cli_root).expanduser().resolve()
        return p
    here = Path(__file__).resolve()
    # sobe de opt/hmg-soar até a raiz do projeto e entra em var-www-wazuh-soar
    project_root = here.parent.parent.parent  # .../opt/hmg-soar -> .../opt -> raiz
    candidate = project_root / "var-www-wazuh-soar"
    if candidate.is_dir():
        return candidate
    # fallback: procura var-www-wazuh-soar subindo na árvore
    for parent in [here.parent, *here.parents]:
        c = parent / "var-www-wazuh-soar"
        if c.is_dir():
            return c
    return candidate  # devolve o palpite, erro tratado adiante

# ─────────────────────────────────────────────────────────────────────────────
# Helpers de tempo (ISO) para datas fictícias coerentes
# ─────────────────────────────────────────────────────────────────────────────
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()

def ago(**kw) -> str:
    return iso(now_utc() - timedelta(**kw))

def ahead(**kw) -> str:
    return iso(now_utc() + timedelta(**kw))

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOADS FICTÍCIOS  (compatíveis com os consumidores JS do template real)
# Cada função retorna um dict que vira JSON. Campo "_mock": True em todos.
# ─────────────────────────────────────────────────────────────────────────────

def mock_health() -> dict:
    return {"_mock": True, "status": "ok", "version": "MOCK-preview-1.0.0"}

def mock_status() -> dict:
    # JS lê: index_html_mtime, latest_json_mtime, latest_report, wrapper_exit_code,
    #        service_info{report_service_active, report_service_status, timer_status,
    #                     next_trigger}
    return {
        "_mock": True,
        "index_html_mtime": iso(now_utc()),
        "latest_json_mtime": ago(minutes=12),
        "latest_report": "[MOCK] analysis_preview.json",
        "wrapper_exit_code": 0,
        "service_info": {
            "report_service_active": False,
            "report_service_status": "inactive",
            "timer_status": "active",
            "next_trigger": ahead(hours=6),
        },
    }

def mock_run_analysis() -> dict:
    # NÃO executa nada. Retorna 200 + mensagem simulada (ver do_POST).
    return {
        "_mock": True,
        "status": "mock",
        "message": "[MOCK] Preview local — nenhuma análise real foi executada.",
    }

def mock_audit_actions(limit: int = 10) -> dict:
    base = [
        {"timestamp": ago(minutes=5),  "remote_user": "mock.analyst", "client_ip": "10.0.0.21",
         "action": "run-analysis", "result": "success",  "exit_code": 0,
         "message": "[MOCK] Execução simulada concluída."},
        {"timestamp": ago(hours=2),    "remote_user": "mock.admin",   "client_ip": "10.0.0.10",
         "action": "run-analysis", "result": "rejected", "exit_code": -1,
         "message": "[MOCK] Rejeitado: janela de manutenção."},
        {"timestamp": ago(hours=9),    "remote_user": "mock.system",  "client_ip": "127.0.0.1",
         "action": "run-analysis", "result": "error",    "exit_code": 3,
         "message": "[MOCK] Falha simulada de coleta (exemplo)."},
        {"timestamp": ago(days=1),     "remote_user": "mock.analyst", "client_ip": "10.0.0.21",
         "action": "run-analysis", "result": "success",  "exit_code": 0,
         "message": "[MOCK] Execução diária simulada."},
    ]
    return {"_mock": True, "actions": base[:max(0, limit)]}

def _priorities(n=10) -> list:
    rows = []
    sev_cycle = ["critical", "high", "high", "medium", "critical"]
    prio_cycle = ["Priority 1+", "Priority 1", "Priority 2", "Priority 3", "Priority 4"]
    for i in range(n):
        rows.append({
            "rank": i + 1,
            "cve": f"CVE-2025-{1000 + i}",
            "package": ["openssl", "glibc", "log4j", "curl", "nginx"][i % 5],
            "severity": sev_cycle[i % len(sev_cycle)],
            "priority": prio_cycle[i % len(prio_cycle)],
            "kev": (i % 3 == 0),
            "epss": round(0.92 - i * 0.06, 4),
            "cvss": round(9.8 - i * 0.4, 1),
            "affected_agents": 12 - i,
            "priority_score": max(5, 96 - i * 8),
            "reason": "[MOCK] Justificativa fictícia de priorização para preview.",
        })
    return rows

def mock_risk_summary() -> dict:
    # JS lê: summary{total_vulnerabilities,critical,high,medium,low,kev_count,
    #                 epss_high_count,affected_agents}, timestamp, alerts[],
    #                 top_priorities[]
    return {
        "_mock": True,
        "timestamp": ago(minutes=12),
        "summary": {
            "total_vulnerabilities": 640,
            "critical": 58, "high": 142, "medium": 280, "low": 160,
            "kev_count": 23, "epss_high_count": 47, "affected_agents": 36,
        },
        "alerts": [
            {"level": "critical", "title": "[MOCK] KEV ativo",
             "message": "23 vulnerabilidades em catálogo KEV (dado fictício)."},
            {"level": "warning",  "title": "[MOCK] EPSS alto",
             "message": "47 itens com EPSS >= 20% (dado fictício)."},
        ],
        "top_priorities": _priorities(10),
    }

def mock_risk_delta() -> dict:
    # JS lê: delta{new_vulnerabilities,resolved_vulnerabilities,
    #              persistent_vulnerabilities,new_kev,new_critical,
    #              agents_worsened,agents_improved}, status
    return {
        "_mock": True,
        "status": "ok",
        "delta": {
            "new_vulnerabilities": 14, "resolved_vulnerabilities": 9,
            "persistent_vulnerabilities": 121, "new_kev": 2,
            "new_critical": 4, "agents_worsened": 3, "agents_improved": 5,
        },
    }

def _assets(prefix, crit, expo, n=5) -> list:
    out = []
    for i in range(n):
        out.append({
            "agent_id": f"00{i+1}",
            "agent_name": f"{prefix}-host-{i+1:02d}",
            "criticality": crit[i % len(crit)],
            "exposure": expo[i % len(expo)],
            "asset_type": ["server", "workstation", "db", "appliance", "container"][i % 5],
            "risk_score": 95 - i * 9,
        })
    return out

def mock_asset_context() -> dict:
    # JS lê: status, assets{total_seen,classified,unclassified,critical,unknown,
    #        high,medium,low}, exposure{internet,dmz}, top_risky_assets[],
    #        unclassified_assets[]
    return {
        "_mock": True,
        "status": "ok",
        "assets": {
            "total_seen": 48, "classified": 41, "unclassified": 7,
            "critical": 9, "high": 14, "medium": 12, "low": 6, "unknown": 7,
        },
        "exposure": {"internet": 5, "dmz": 8},
        "top_risky_assets": _assets("crit", ["critical", "high"], ["internet", "dmz", "internal"]),
        "unclassified_assets": [
            {"agent_id": "090", "agent_name": "mock-unclassified-01"},
            {"agent_id": "091", "agent_name": "mock-unclassified-02"},
        ],
    }

def mock_exposure_context() -> dict:
    # JS lê: assets{with_exposure_context,without_exposure_context,internet_facing,dmz},
    #        services{critical_services,internet_exposed_services},
    #        external_assets{without_wazuh_agent}, exposure_alerts[],
    #        top_exposed_assets[], assets_missing_exposure_context[],
    #        external_assets_list[]
    return {
        "_mock": True,
        "assets": {
            "with_exposure_context": 41, "without_exposure_context": 7,
            "internet_facing": 5, "dmz": 8,
        },
        "services": {"critical_services": 11, "internet_exposed_services": 6},
        "external_assets": {"without_wazuh_agent": 3},
        "exposure_alerts": [
            {"level": "warning", "title": "[MOCK] Serviço exposto",
             "message": "6 serviços expostos à internet (fictício)."},
        ],
        "top_exposed_assets": _assets("exp", ["critical", "high"], ["internet", "dmz"]),
        "assets_missing_exposure_context": [
            {"agent_id": "092", "agent_name": "mock-missing-expo-01"},
        ],
        "external_assets_list": [
            {"asset_name": "mock-ext-api", "ip": "203.0.113.10", "hostname": "api.mock.example",
             "exposure_level": "internet", "network_zone": "edge", "source": "[MOCK] inventory",
             "confidence": "média", "has_wazuh_agent": False},
        ],
    }

def _sla_items(n, key_extra, color_field=None) -> list:
    out = []
    for i in range(n):
        item = {
            "cve": f"CVE-2025-{2000 + i}",
            "agent_id": f"01{i}", "agent_name": f"mock-sla-host-{i+1:02d}",
            "package_name": ["openssl", "glibc", "curl", "nginx", "log4j"][i % 5],
            "severity": ["critical", "high", "medium"][i % 3],
        }
        item.update(key_extra(i))
        out.append(item)
    return out

def mock_sla_summary() -> dict:
    # JS lê: summary{total_open,overdue,due_soon,within_sla,unknown,average_age_days,
    #        max_age_days,persistent_vulnerabilities,recurring_vulnerabilities},
    #        sla_alerts[], top_overdue[], top_due_soon[], top_persistent_cves[],
    #        top_recurring_cves[], top_backlog_assets[], top_backlog_owners[]
    return {
        "_mock": True,
        "summary": {
            "total_open": 312, "overdue": 28, "due_soon": 41, "within_sla": 219,
            "unknown": 24, "average_age_days": 37, "max_age_days": 184,
            "persistent_vulnerabilities": 53, "recurring_vulnerabilities": 17,
        },
        "sla_alerts": [
            {"level": "critical", "title": "[MOCK] SLAs vencidos",
             "message": "28 vulnerabilidades vencidas (fictício)."},
        ],
        "top_overdue": _sla_items(5, lambda i: {
            "days_overdue": 30 - i * 4, "due_date": ago(days=30 - i * 4)}),
        "top_due_soon": _sla_items(5, lambda i: {
            "days_to_due": 2 + i, "due_date": ahead(days=2 + i)}),
        "top_persistent_cves": _sla_items(5, lambda i: {"age_days": 120 - i * 10}),
        "top_recurring_cves": _sla_items(5, lambda i: {"snapshot_occurrences": 8 - i}),
        "top_backlog_assets": [
            {"agent_id": f"02{i}", "agent_name": f"mock-backlog-host-{i+1:02d}",
             "total": 40 - i * 6, "overdue": 8 - i, "due_soon": 6, "within_sla": 26 - i * 5}
            for i in range(5)
        ],
        "top_backlog_owners": [
            {"technical_owner": f"mock-owner-{i+1}", "total": 50 - i * 8,
             "overdue": 9 - i, "due_soon": 7, "within_sla": 34 - i * 7}
            for i in range(5)
        ],
    }

def mock_risk_acceptance() -> dict:
    # JS lê: summary{rules_total,rules_invalid,accepted,false_positive,
    #        planned_remediation,compensating_control,waiting_change_window,
    #        expired,actionable_after_acceptance}, acceptance_alerts[],
    #        expired_acceptances[], expiring_soon[], invalid_rules[],
    #        matched_items_sample[]
    return {
        "_mock": True,
        "summary": {
            "rules_total": 34, "rules_invalid": 2, "accepted": 18,
            "false_positive": 7, "planned_remediation": 11,
            "compensating_control": 4, "waiting_change_window": 3,
            "expired": 5, "actionable_after_acceptance": 196,
        },
        "acceptance_alerts": [
            {"level": "warning", "title": "[MOCK] Exceções vencidas",
             "message": "5 exceções de risco vencidas (fictício)."},
        ],
        "expired_acceptances": [
            {"cve": f"CVE-2024-{900 + i}", "agent_id": f"03{i}",
             "agent_name": f"mock-ra-host-{i+1:02d}", "rule_id": f"RA-{100 + i}",
             "valid_until": ago(days=5 + i), "days_overdue": 5 + i} for i in range(3)
        ],
        "expiring_soon": [
            {"cve": f"CVE-2024-{950 + i}", "agent_id": f"04{i}",
             "agent_name": f"mock-ra-soon-{i+1:02d}", "rule_id": f"RA-{200 + i}",
             "valid_until": ahead(days=3 + i), "days_to_expire": 3 + i,
             "status": "accepted"} for i in range(3)
        ],
        "invalid_rules": [
            {"rule_id": "RA-999", "reason": "[MOCK] Campo obrigatório ausente."},
        ],
        "matched_items_sample": [
            {"cve": "CVE-2024-1001", "agent_id": "050", "agent_name": "mock-ra-sample-01",
             "package_name": "openssl", "rule_id": "RA-101", "status": "accepted",
             "valid_until": ahead(days=30)},
        ],
    }

def mock_treatment_plan() -> dict:
    # JS lê: summary{now,next_7_days,next_15_days,next_30_days,monitor,
    #        accepted_or_exception,false_positive,owners,quick_wins,
    #        change_window_candidates}, by_owner[], by_bucket[], by_effort[],
    #        quick_wins[], change_window_candidates[], top_treatment_items[],
    #        owner_workload[], treatment_alerts[]
    owners = []
    for i in range(5):
        owners.append({
            "technical_owner": f"mock-owner-{i+1}",
            "total_actionable": 60 - i * 9, "now": 8 - i,
            "next_7_days": 10, "next_15_days": 9, "next_30_days": 7,
            "overdue": 6 - i, "due_soon": 5,
            "critical": 7 - i, "high": 12 - i,
            "estimated_effort": {"low": 20 - i * 3, "medium": 14, "high": 6},
            "top_assets": [
                {"agent_name": f"mock-host-{i+1}-a", "total_vulnerabilities": 18},
                {"agent_name": f"mock-host-{i+1}-b", "total_vulnerabilities": 11},
            ],
            "top_cves": [
                {"cve": f"CVE-2025-{3000 + i}", "count": 5},
                {"cve": f"CVE-2025-{3100 + i}", "count": 3},
            ],
        })
    top_items = []
    for i in range(8):
        top_items.append({
            "cve": f"CVE-2025-{4000 + i}", "agent_id": f"05{i}",
            "agent_name": f"mock-treat-host-{i+1:02d}",
            "package_name": ["openssl", "glibc", "curl", "nginx", "log4j"][i % 5],
            "technical_owner": f"mock-owner-{(i % 5) + 1}",
            "asset_criticality": ["critical", "high", "medium"][i % 3],
            "exposure_level": ["internet", "dmz", "internal"][i % 3],
            "treatment_score": max(10, 92 - i * 9),
            "treatment_bucket": ["now", "next_7_days", "next_15_days", "next_30_days"][i % 4],
            "suggested_action_type": ["patch", "mitigar", "isolar"][i % 3],
            "effort": ["low", "medium", "high"][i % 3],
            "reason": "[MOCK] Racional fictício de tratativa para preview.",
        })
    return {
        "_mock": True,
        "summary": {
            "now": 22, "next_7_days": 38, "next_15_days": 31, "next_30_days": 44,
            "monitor": 61, "accepted_or_exception": 18, "false_positive": 7,
            "owners": 5, "quick_wins": 12, "change_window_candidates": 6,
        },
        "by_owner": [{"technical_owner": o["technical_owner"],
                      "count": o["total_actionable"]} for o in owners],
        "by_bucket": [
            {"bucket": "now", "count": 22}, {"bucket": "next_7_days", "count": 38},
            {"bucket": "next_15_days", "count": 31}, {"bucket": "next_30_days", "count": 44},
            {"bucket": "monitor", "count": 61},
        ],
        "by_effort": [
            {"effort": "low", "count": 70}, {"effort": "medium", "count": 52},
            {"effort": "high", "count": 24},
        ],
        "quick_wins": [
            {"title": f"[MOCK] Quick win {i+1}", "owner": f"mock-owner-{(i%5)+1}",
             "affected_assets": 6 - i, "suggested_window": "imediata",
             "treatment_score": 70 - i * 5,
             "reason": "[MOCK] Baixo esforço, alto impacto (fictício)."} for i in range(4)
        ],
        "change_window_candidates": [
            {"title": f"[MOCK] Janela {i+1}", "owner": f"mock-owner-{(i%5)+1}",
             "affected_assets": 9 - i, "effort": "high", "suggested_window": "fim de semana",
             "reason": "[MOCK] Alta complexidade (fictício)."} for i in range(3)
        ],
        "top_treatment_items": top_items,
        "owner_workload": owners,
        "treatment_alerts": [
            {"level": "warning", "title": "[MOCK] Carga concentrada",
             "message": "Owner mock-owner-1 com maior backlog (fictício)."},
        ],
    }

def _severity_series(n=8) -> list:
    out = []
    for i in range(n):
        out.append({
            "timestamp": ago(days=(n - i) * 3),
            "critical": 50 + (i % 4) * 5 - (i // 2),
            "high": 130 + (i % 3) * 8,
            "medium": 270 + (i % 5) * 6,
            "low": 150 + (i % 2) * 10,
        })
    return out

def _sla_series(n=8) -> list:
    return [{"timestamp": ago(days=(n - i) * 3),
             "overdue": 35 - i, "due_soon": 40 + (i % 3) * 2,
             "within_sla": 200 + i * 4} for i in range(n)]

def _accept_series(n=8) -> list:
    return [{"timestamp": ago(days=(n - i) * 3),
             "accepted_risks": 12 + i, "false_positive_risks": 5 + (i % 3),
             "expired_acceptances": max(0, 6 - i),
             "actionable_priorities": 210 - i * 3} for i in range(n)]

def mock_trend_summary() -> dict:
    # JS lê: summary{executive_health,risk_direction,period_days,snapshots_analyzed,
    #        trend_status}, current{}, delta{total_vulnerabilities,critical,high,
    #        sla_overdue,kev_count}, executive_alerts[], top_worsening_assets[],
    #        top_improving_assets[], owner_trend[], top_persistent_cves[],
    #        severity_trend[], sla_trend[], acceptance_trend[]
    def asset_trend(prefix, sign):
        out = []
        for i in range(4):
            pc, cc = 6 + i, 6 + i + (2 if sign > 0 else -2)
            pt, ct = 30 + i * 4, 30 + i * 4 + (5 if sign > 0 else -5)
            out.append({
                "agent_id": f"06{i}", "agent_name": f"{prefix}-{i+1:02d}",
                "technical_owner": f"mock-owner-{(i % 5) + 1}",
                "previous_critical": pc, "current_critical": cc,
                "delta_critical": cc - pc,
                "previous_total": pt, "current_total": ct,
                "delta_total": ct - pt,
                "risk_direction": "worsening" if sign > 0 else "improving",
            })
        return out
    return {
        "_mock": True,
        "summary": {
            "executive_health": "attention", "risk_direction": "worsening",
            "period_days": 30, "snapshots_analyzed": 8, "trend_status": "ok",
        },
        "current": {},
        "delta": {
            "total_vulnerabilities": 14, "critical": 4, "high": 9,
            "sla_overdue": 3, "kev_count": 2,
        },
        "executive_alerts": [
            {"level": "warning", "title": "[MOCK] Risco em alta",
             "message": "Tendência de piora no período (fictício)."},
        ],
        "top_worsening_assets": asset_trend("mock-worse", +1),
        "top_improving_assets": asset_trend("mock-better", -1),
        "owner_trend": [
            {"technical_owner": f"mock-owner-{i+1}",
             "previous_total": 40 + i, "current_total": 40 + i + (3 - i),
             "delta_total": (3 - i),
             "previous_overdue": 8, "current_overdue": 8 + (2 - i),
             "delta_overdue": (2 - i),
             "risk_direction": ["worsening", "improving", "stable"][i % 3]}
            for i in range(4)
        ],
        "top_persistent_cves": [
            {"cve": f"CVE-2024-{700 + i}", "agent_id": f"07{i}",
             "agent_name": f"mock-persist-{i+1:02d}", "severity": ["critical", "high"][i % 2],
             "age_days": 150 - i * 12, "sla_status": ["overdue", "due_soon", "within_sla"][i % 3]}
            for i in range(5)
        ],
        "severity_trend": _severity_series(8),
        "sla_trend": _sla_series(8),
        "acceptance_trend": _accept_series(8),
    }

# Mapa GET endpoint -> função (sem o prefixo /soar-api/)
GET_ROUTES = {
    "health":           lambda q: mock_health(),
    "status":           lambda q: mock_status(),
    "audit-actions":    lambda q: mock_audit_actions(int((q.get("limit") or ["10"])[0])),
    "risk-summary":     lambda q: mock_risk_summary(),
    "risk-delta":       lambda q: mock_risk_delta(),
    "asset-context":    lambda q: mock_asset_context(),
    "exposure-context": lambda q: mock_exposure_context(),
    "sla-summary":      lambda q: mock_sla_summary(),
    "risk-acceptance":  lambda q: mock_risk_acceptance(),
    "treatment-plan":   lambda q: mock_treatment_plan(),
    "trend-summary":    lambda q: mock_trend_summary(),
}

# ─────────────────────────────────────────────────────────────────────────────
# HANDLER
# ─────────────────────────────────────────────────────────────────────────────
class PreviewHandler(SimpleHTTPRequestHandler):
    # static_root é injetado via classe (set em main)
    static_root: Path = Path(".")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(self.static_root), **kwargs)

    # silencia log padrão verboso; mantém um log enxuto com marca MOCK
    def log_message(self, fmt, *args):
        sys.stderr.write("  [MOCK] %s - %s\n" % (self.address_string(), fmt % args))

    def _send_json(self, payload: dict, status: int = 200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Mock-Server", "eyemole-preview")  # marca explícita
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _is_api(self, path: str) -> bool:
        return path.startswith("/soar-api/")

    def do_GET(self):
        parsed = urlparse(self.path)
        if self._is_api(parsed.path):
            name = parsed.path[len("/soar-api/"):].strip("/")
            route = GET_ROUTES.get(name)
            if route is None:
                self._send_json({"_mock": True, "status": "not_found",
                                 "message": f"[MOCK] Endpoint '{name}' não mapeado no preview."},
                                status=404)
                return
            try:
                q = parse_qs(parsed.query)
                self._send_json(route(q))
            except Exception as e:  # nunca derruba o preview
                self._send_json({"_mock": True, "status": "error",
                                 "message": f"[MOCK] Erro ao gerar payload fictício: {e}"},
                                status=500)
            return
        # Arquivos estáticos
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/soar-api/run-analysis":
            # NÃO executa nada real — apenas resposta simulada.
            self._send_json(mock_run_analysis(), status=200)
            return
        if self._is_api(parsed.path):
            self._send_json({"_mock": True, "status": "mock",
                             "message": "[MOCK] POST simulado — nenhuma ação real executada."},
                            status=200)
            return
        self.send_error(405, "Method Not Allowed (mock)")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="EyeMole preview MOCK server (dados fictícios).")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--root", default=None, help="Diretório estático (default: var-www-wazuh-soar)")
    args = ap.parse_args()

    static_root = resolve_static_root(args.root)

    print()
    print("  " + "=" * 60)
    print("  " + MOCK_BANNER)
    print("  " + "=" * 60)
    if not static_root.is_dir():
        print(f"  [x] Diretório estático não encontrado: {static_root}")
        print("      Rode antes: python .\\opt\\hmg-soar\\preview_dashboard.py")
        print("      ou informe:  --root <caminho_para_var-www-wazuh-soar>")
        sys.exit(1)

    index = static_root / "index.html"
    print(f"  [i] Servindo estáticos de : {static_root}")
    print(f"  [i] index.html presente   : {'sim' if index.is_file() else 'NÃO (gere com preview_dashboard.py)'}")
    print(f"  [i] Endpoints mock        : {len(GET_ROUTES)} GET + POST /soar-api/run-analysis")
    print(f"  [i] Todos os dados        : FICTÍCIOS (marca _mock=true e header X-Mock-Server)")
    print()
    print(f"  >>> Abra:  http://{args.host}:{args.port}/index.html")
    print(f"  >>> Ctrl+C para encerrar.")
    print("  " + "=" * 60)
    print()

    PreviewHandler.static_root = static_root
    httpd = ThreadingHTTPServer((args.host, args.port), PreviewHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  [i] Encerrando preview mock. Nenhuma alteração foi feita em produção.\n")
        httpd.server_close()

if __name__ == "__main__":
    main()
