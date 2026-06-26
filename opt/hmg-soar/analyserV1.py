#!/usr/bin/env python3
"""
analyserV1.py - Versão Refatorada e Segura

HMG Vulnerability Intelligence + Wazuh SOAR Brain.
- Cruzar vulnerabilidades do Wazuh/OpenSearch com CISA KEV e EPSS.
- Classificar as vulnerabilidades em 5 níveis de prioridade (Priority 1+, 1, 2, 3, 4).
- Exportar relatórios em CSV, PDF e HTML.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import gzip
import hashlib
import io
import json
import logging
import os
import re
import shlex
import shutil
import stat
import sys
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# grp é Unix-only; importar condicionalmente para permitir dev em Windows
try:
    import grp as _grp
except ImportError:
    _grp = None  # type: ignore

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuração do Logging Estruturado
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
logger = logging.getLogger("HMG_SOAR")

# ==========================================
# CONFIGURAÇÕES BASE
# ==========================================
INDEXER_IP = os.getenv("OPENSEARCH_HOST", "127.0.0.1")
INDEXER_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
INDEXER_USER = os.getenv("OPENSEARCH_USER", "admin")

WAZUH_MANAGER_IP = os.getenv("WAZUH_API_HOST", "127.0.0.1")
WAZUH_API_PORT = os.getenv("WAZUH_API_PORT", "55000")
WAZUH_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")

USE_HTTPS = os.getenv("HMG_USE_HTTPS", "true").lower() != "false"
SCHEME = "https" if USE_HTTPS else "http"

# --- Intelligence Sources (Phase 3I.1 v2: Resilience & Cache) ---
# KEV: primary CISA.gov official feed; fallback cisagov/kev-data (CISA-maintained GitHub mirror)
# Schema: catalogVersion, dateReleased, count, vulnerabilities[] — identical in both sources.
CISA_KEV_URL           = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_FALLBACK_URL  = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"

# EPSS: primary daily CSV (streamed + cached to disk); fallback FIRST API per-CVE
EPSS_URL               = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_API_URL           = "https://api.first.org/data/v1/epss"   # fallback: paginable REST API

# Name of the raw daily EPSS CSV cache file (stored inside CACHE_DIR)
EPSS_CSV_CACHE_FILENAME = "epss_daily_raw.csv.gz"
# TTL dedicated to the daily EPSS CSV (may differ from generic CACHE_TTL_HOURS)
EPSS_CSV_CACHE_TTL_HOURS = int(os.getenv("HMG_EPSS_CSV_TTL_HOURS", "24"))


DEFAULT_EPSS_THRESHOLD = 0.20
DEFAULT_CVSS_THRESHOLD = 6.0

KNOWN_AGENTS = {
    "001": "windows-server-sscapps",
    "003": "linux-server-asc-linux-02",
    "004": "linux-server-asc-linux-01",
    "005": "linux-siemapps",
}

VULN_INDEX_PATTERN = os.getenv("WAZUH_VULN_INDEX", "wazuh-states-vulnerabilities-*")
REQUEST_TIMEOUT = int(os.getenv("HMG_REQUEST_TIMEOUT", "60"))
CACHE_DIR = Path(os.getenv("HMG_CACHE_DIR", ".hmg_cache"))
CACHE_TTL_HOURS = int(os.getenv("HMG_CACHE_TTL_HOURS", "6"))
SCROLL_TIMEOUT = "3m"
SCROLL_PAGE_SIZE = 5000
WAZUH_TOKEN_TTL_SECONDS = 840  # Token Wazuh expira em 900s; renovar com 60s de margem

# Caminhos do Contexto de Ativos (Fase 3B)
ASSETS_CONTEXT_PATH_PREF = Path("/opt/hmg-soar/config/assets_context.json")
ASSETS_CONTEXT_PATH_FALLBACK = Path("./config/assets_context.json")

# Pesos de Risco de Contexto de Ativos (Fase 3B)
WEIGHT_CRITICALITY = {
    "critical": 20,
    "high": 15,
    "medium": 7,
    "low": 0,
    "unknown": 5
}

WEIGHT_EXPOSURE = {
    "internet": 20,
    "dmz": 15,
    "internal": 5,
    "isolated": 0,
    "unknown": 5
}

WEIGHT_ENVIRONMENT = {
    "production": 15,
    "hmg": 3,
    "development": 2,
    "lab": 0,
    "unknown": 3
}

WEIGHT_ASSET_TYPE = {
    "domain_controller": 20,
    "database": 18,
    "cyberark": 18,
    "qradar": 15,
    "siem": 15,
    "wazuh": 15,
    "firewall": 15,
    "vpn": 12,
    "web_server": 10,
    "application_server": 10,
    "file_server": 8,
    "linux_server": 5,
    "windows_server": 5,
    "endpoint": 3,
    "unknown": 3
}

def load_assets_context() -> dict:
    """Carrega o mapa de contexto dos ativos de /opt/hmg-soar/config/assets_context.json ou fallback local."""
    paths = [ASSETS_CONTEXT_PATH_PREF, ASSETS_CONTEXT_PATH_FALLBACK]
    for p in paths:
        if p.exists() and p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                logger.info(f"[+] Contexto de ativos carregado de: {p}")
                return data
            except Exception as e:
                logger.warning(f"[AVISO] Falha ao ler arquivo de contexto em {p}: {e}")
    
    logger.info("[-] Arquivo de contexto de ativos não encontrado ou ilegível. Usando defaults.")
    return {}

def get_asset_context(assets_data: dict, agent_id: str, agent_name: str) -> dict:
    """
    Retorna o contexto do ativo a partir do mapa carregado.
    Busca preferencialmente por agent_id, agent_name ou hostname.
    """
    defaults = {
        "criticality": "unknown",
        "environment": "unknown",
        "exposure": "unknown",
        "asset_type": "unknown",
        "business_owner": "unknown",
        "technical_owner": "unknown",
        "tags": []
    }
    
    if not assets_data:
        # Normalizar defaults antes de retornar
        for key in ["criticality", "environment", "exposure", "asset_type"]:
            if key in defaults and isinstance(defaults[key], str):
                defaults[key] = defaults[key].lower().strip()
        return defaults.copy()
        
    json_defaults = assets_data.get("defaults", {})
    for k, v in json_defaults.items():
        if k in defaults:
            defaults[k] = v
            
    # Normalizar defaults de ativos
    for key in ["criticality", "environment", "exposure", "asset_type"]:
        if key in defaults and isinstance(defaults[key], str):
            defaults[key] = defaults[key].lower().strip()
            
    agents_map = assets_data.get("agents", {})
    
    # 1. Busca por agent_id exato
    if agent_id and agent_id in agents_map:
        return _merge_asset_context(agents_map[agent_id], defaults)
        
    # 2. Busca por agent_name exato
    if agent_name and agent_name in agents_map:
        return _merge_asset_context(agents_map[agent_name], defaults)
        
    # 3. Busca por hostname exato ou correspondência parcial
    agent_id_lower = str(agent_id).lower() if agent_id else ""
    agent_name_lower = str(agent_name).lower() if agent_name else ""
    
    for key, val in agents_map.items():
        key_lower = str(key).lower()
        asset_name_lower = str(val.get("asset_name", "")).lower()
        
        if (agent_id_lower and key_lower == agent_id_lower) or \
           (agent_name_lower and key_lower == agent_name_lower) or \
           (agent_name_lower and asset_name_lower == agent_name_lower):
            return _merge_asset_context(val, defaults)
            
    return defaults.copy()

def _merge_asset_context(asset_info: dict, defaults: dict) -> dict:
    res = defaults.copy()
    for k in defaults.keys():
        if k in asset_info:
            res[k] = asset_info[k]
    # Normalização robusta de strings de ativos
    for key in ["criticality", "environment", "exposure", "asset_type"]:
        if key in res and isinstance(res[key], str):
            res[key] = res[key].lower().strip()
    return res

# Caminhos da Política de SLA (Fase 3D)
SLA_POLICY_PATH_PREF = Path("/opt/hmg-soar/config/sla_policy.json")
SLA_POLICY_PATH_FALLBACK = Path("./config/sla_policy.json")

DEFAULT_SLA_POLICY = {
    "defaults": {
        "critical": 15,
        "high": 30,
        "medium": 60,
        "low": 90
    },
    "kev": {
        "critical": 7,
        "high": 15,
        "medium": 30,
        "low": 60
    },
    "internet_facing": {
        "critical": 7,
        "high": 15,
        "medium": 30,
        "low": 60
    },
    "dmz": {
        "critical": 10,
        "high": 20,
        "medium": 45,
        "low": 75
    },
    "critical_asset": {
        "critical": 7,
        "high": 15,
        "medium": 30,
        "low": 60
    },
    "high_asset": {
        "critical": 10,
        "high": 20,
        "medium": 45,
        "low": 75
    },
    "sensitive_service": {
        "critical": 7,
        "high": 15,
        "medium": 30,
        "low": 60
    },
    "near_due_threshold_days": 5,
    "persistent_threshold_days": 30,
    "recurring_threshold_count": 3,
    "business_days_only": False
}

def load_sla_policy() -> dict:
    """Carrega a política de SLA de /opt/hmg-soar/config/sla_policy.json ou fallback local."""
    paths = [SLA_POLICY_PATH_PREF, SLA_POLICY_PATH_FALLBACK]
    for p in paths:
        if p.exists() and p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                logger.info(f"[+] Política de SLA carregada de: {p}")
                return data
            except Exception as e:
                logger.warning(f"[AVISO] Falha ao ler arquivo de política de SLA em {p}: {e}")
    logger.info("[-] Arquivo de política de SLA não encontrado ou ilegível. Usando defaults.")
    return DEFAULT_SLA_POLICY.copy()

# Caminhos do Contexto de Exposição (Fase 3C)
EXPOSURE_CONTEXT_PATH_PREF = Path("/opt/hmg-soar/config/exposure_context.json")
EXPOSURE_CONTEXT_PATH_FALLBACK = Path("./config/exposure_context.json")


# Pesos de Nível de Exposição (Fase 3C)
WEIGHT_EXPOSURE_LEVEL = {
    "internet": 25,
    "dmz": 18,
    "internal": 5,
    "isolated": 0,
    "unknown": 7
}

# Pesos de Zonas de Rede (Fase 3C)
WEIGHT_NETWORK_ZONE = {
    "external": 25,
    "dmz": 18,
    "management": 15,
    "security": 12,
    "database": 12,
    "server_vlan": 8,
    "lan": 5,
    "endpoint": 3,
    "isolated": 0,
    "unknown": 5
}

# Pesos de Serviços Abertos por Exposição (Fase 3C)
WEIGHT_SERVICES = {
    ("rdp", "internet"): 20, ("rdp", "internal"): 8,
    ("ssh", "internet"): 15, ("ssh", "internal"): 5,
    ("vpn", "internet"): 20,
    ("https", "internet"): 10, ("https", "internal"): 3,
    ("http", "internet"): 12, ("http", "internal"): 4,
    ("database", "internet"): 25, ("database", "internal"): 10,
    ("smb", "internet"): 25, ("smb", "internal"): 8,
    ("ldap", "internet"): 20, ("ldap", "internal"): 8,
    ("winrm", "internet"): 18, ("winrm", "internal"): 6,
    ("admin_ui", "internet"): 18, ("admin_ui", "internal"): 8,
    ("kibana", "internet"): 18, ("kibana", "internal"): 8,
    ("wazuh", "internet"): 18, ("wazuh", "internal"): 8,
    ("qradar", "internet"): 18, ("qradar", "internal"): 8,
    ("cyberark", "internet"): 20, ("cyberark", "internal"): 10,
}

def load_exposure_context() -> dict:
    """Carrega o mapa de contexto de exposição de /opt/hmg-soar/config/exposure_context.json ou fallback local."""
    paths = [EXPOSURE_CONTEXT_PATH_PREF, EXPOSURE_CONTEXT_PATH_FALLBACK]
    for p in paths:
        if p.exists() and p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                logger.info(f"[+] Contexto de exposição carregado de: {p}")
                return data
            except Exception as e:
                logger.warning(f"[AVISO] Falha ao ler arquivo de contexto de exposição em {p}: {e}")
    
    logger.info("[-] Arquivo de contexto de exposição não encontrado ou ilegível. Usando defaults.")
    return {}

def get_exposure_context(exposure_data: dict, agent_id: str, agent_name: str) -> dict:
    """
    Retorna o contexto de exposição do ativo a partir do mapa carregado.
    Busca por agent_id, agent_name ou hostname.
    """
    defaults = {
        "exposure_level": "unknown",
        "network_zone": "unknown",
        "internet_facing": False,
        "dmz": False,
        "has_public_ip": False,
        "has_public_dns": False,
        "source": "manual",
        "confidence": "low",
        "open_services": [],
        "external_identifiers": [],
        "notes": ""
    }
    
    if not exposure_data:
        # Normalizar defaults antes de retornar
        for key in ["exposure_level", "network_zone", "confidence"]:
            if key in defaults and isinstance(defaults[key], str):
                defaults[key] = defaults[key].lower().strip()
        return defaults.copy()
        
    json_defaults = exposure_data.get("defaults", {})
    for k, v in json_defaults.items():
        if k in defaults:
            defaults[k] = v
            
    # Normalizar defaults de exposição
    for key in ["exposure_level", "network_zone", "confidence"]:
        if key in defaults and isinstance(defaults[key], str):
            defaults[key] = defaults[key].lower().strip()
            
    agents_map = exposure_data.get("agents", {})
    
    # 1. Busca por agent_id exato
    if agent_id and agent_id in agents_map:
        return _merge_exposure_context(agents_map[agent_id], defaults)
        
    # 2. Busca por agent_name exato
    if agent_name and agent_name in agents_map:
        return _merge_exposure_context(agents_map[agent_name], defaults)
        
    # 3. Busca por hostname exato ou correspondência parcial
    agent_id_lower = str(agent_id).lower() if agent_id else ""
    agent_name_lower = str(agent_name).lower() if agent_name else ""
    
    for key, val in agents_map.items():
        key_lower = str(key).lower()
        asset_name_lower = str(val.get("asset_name", "")).lower()
        
        if (agent_id_lower and key_lower == agent_id_lower) or \
           (agent_name_lower and key_lower == agent_name_lower) or \
           (agent_name_lower and asset_name_lower == agent_name_lower):
            return _merge_exposure_context(val, defaults)
            
    return defaults.copy()

# Caminhos da Gestão de Exceções / Risk Acceptance (Fase 3E)
RISK_ACCEPTANCE_PATH_PREF = Path("/opt/hmg-soar/config/risk_acceptance.json")
RISK_ACCEPTANCE_PATH_FALLBACK = Path("./config/risk_acceptance.json")

# Status permitidos de risk acceptance
ALLOWED_RISK_ACCEPTANCE_STATUSES = {
    "none", "accepted", "false_positive", "planned_remediation",
    "compensating_control", "waiting_change_window", "out_of_scope",
    "duplicate", "under_review", "expired", "invalid"
}

def load_risk_acceptance() -> dict:
    """Carrega o mapa declarativo de exceções de /opt/hmg-soar/config/risk_acceptance.json ou fallback local."""
    paths = [RISK_ACCEPTANCE_PATH_PREF, RISK_ACCEPTANCE_PATH_FALLBACK]
    for p in paths:
        if p.exists() and p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                logger.info(f"[+] Risk Acceptance carregado de: {p}")
                return data
            except Exception as e:
                logger.warning(f"[AVISO] Falha ao ler arquivo de risk acceptance em {p}: {e}")
    
    logger.info("[-] Arquivo de risk acceptance não encontrado ou ilegível. Usando defaults vazios.")
    return {}

def validate_risk_acceptance_rules(data: dict) -> Tuple[List[dict], List[dict], List[dict]]:
    """
    Valida as regras de risk acceptance com base nos defaults.
    Retorna (valid_rules, invalid_rules, alerts).
    """
    valid_rules = []
    invalid_rules = []
    alerts = []
    
    if not data or "rules" not in data:
        return valid_rules, invalid_rules, alerts

    defaults = data.get("defaults", {})
    require_expiration = defaults.get("require_expiration", True)
    require_approver = defaults.get("require_approver", True)
    require_reason = defaults.get("require_reason", True)
    max_acceptance_days = defaults.get("max_acceptance_days", None)

    seen_ids = set()

    for idx, rule in enumerate(data.get("rules", [])):
        rule_copy = dict(rule)
        rule_id = rule_copy.get("id")
        
        # 1. Validar ID
        if not rule_id:
            msg = f"Regra no índice {idx} sem campo 'id' obrigatório."
            alerts.append({"level": "warning", "title": "Regra Inválida", "message": msg})
            rule_copy["validation_error"] = msg
            rule_copy["status"] = "invalid"
            invalid_rules.append(rule_copy)
            continue
            
        if rule_id in seen_ids:
            msg = f"Regra '{rule_id}' com ID duplicado."
            alerts.append({"level": "warning", "title": "Regra Inválida", "message": msg})
            rule_copy["validation_error"] = msg
            rule_copy["status"] = "invalid"
            invalid_rules.append(rule_copy)
            continue
        seen_ids.add(rule_id)

        # 2. Validar Enabled
        enabled = rule_copy.get("enabled", True)
        if not isinstance(enabled, bool):
            msg = f"Regra '{rule_id}' com campo 'enabled' inválido (deve ser booleano)."
            alerts.append({"level": "warning", "title": "Regra Inválida", "message": msg})
            rule_copy["validation_error"] = msg
            rule_copy["status"] = "invalid"
            invalid_rules.append(rule_copy)
            continue

        # 3. Validar Status
        status = rule_copy.get("status")
        allowed_statuses = {
            "accepted", "false_positive", "planned_remediation", "compensating_control",
            "waiting_change_window", "out_of_scope", "duplicate", "under_review"
        }
        if status not in allowed_statuses:
            msg = f"Regra '{rule_id}' possui status inválido: '{status}'."
            alerts.append({"level": "warning", "title": "Regra Inválida", "message": msg})
            rule_copy["validation_error"] = msg
            rule_copy["status"] = "invalid"
            invalid_rules.append(rule_copy)
            continue

        # 4. Validar Match
        match_criteria = rule_copy.get("match")
        if not match_criteria or not isinstance(match_criteria, dict):
            msg = f"Regra '{rule_id}' possui bloco 'match' vazio ou inválido."
            alerts.append({"level": "warning", "title": "Regra Inválida", "message": msg})
            rule_copy["validation_error"] = msg
            rule_copy["status"] = "invalid"
            invalid_rules.append(rule_copy)
            continue

        # 5. Validar Reason
        reason = rule_copy.get("reason")
        if require_reason and not reason:
            msg = f"Regra '{rule_id}' exige justificativa ('reason'), mas o campo está vazio."
            alerts.append({"level": "warning", "title": "Regra Inválida", "message": msg})
            rule_copy["validation_error"] = msg
            rule_copy["status"] = "invalid"
            invalid_rules.append(rule_copy)
            continue

        # 6. Validar Approver
        approved_by = rule_copy.get("approved_by")
        if require_approver and not approved_by:
            msg = f"Regra '{rule_id}' exige aprovador ('approved_by'), mas o campo está vazio."
            alerts.append({"level": "warning", "title": "Regra Inválida", "message": msg})
            rule_copy["validation_error"] = msg
            rule_copy["status"] = "invalid"
            invalid_rules.append(rule_copy)
            continue

        # 7. Validar Expiration e datas em formato ISO 8601
        valid_until_str = rule_copy.get("valid_until")
        if require_expiration and not valid_until_str:
            msg = f"Regra '{rule_id}' exige expiração ('valid_until'), mas o campo está vazio."
            alerts.append({"level": "warning", "title": "Regra Inválida", "message": msg})
            rule_copy["validation_error"] = msg
            rule_copy["status"] = "invalid"
            invalid_rules.append(rule_copy)
            continue

        valid_until_dt = None
        if valid_until_str:
            try:
                clean_date = valid_until_str.replace("Z", "+00:00")
                valid_until_dt = datetime.fromisoformat(clean_date)
            except Exception:
                msg = f"Regra '{rule_id}' possui valid_until em formato inválido (deve ser ISO 8601)."
                alerts.append({"level": "warning", "title": "Regra Inválida", "message": msg})
                rule_copy["validation_error"] = msg
                rule_copy["status"] = "invalid"
                invalid_rules.append(rule_copy)
                continue

        approved_at_str = rule_copy.get("approved_at")
        approved_at_dt = None
        if approved_at_str:
            try:
                clean_date = approved_at_str.replace("Z", "+00:00")
                approved_at_dt = datetime.fromisoformat(clean_date)
            except Exception:
                msg = f"Regra '{rule_id}' possui approved_at em formato inválido."
                alerts.append({"level": "warning", "title": "Regra Inválida", "message": msg})
                rule_copy["validation_error"] = msg
                rule_copy["status"] = "invalid"
                invalid_rules.append(rule_copy)
                continue

        # 8. Validar max_acceptance_days
        if max_acceptance_days is not None and valid_until_dt:
            ref_dt = approved_at_dt if approved_at_dt else datetime.now(timezone.utc)
            if valid_until_dt.tzinfo is None:
                valid_until_dt = valid_until_dt.replace(tzinfo=timezone.utc)
            if ref_dt.tzinfo is None:
                ref_dt = ref_dt.replace(tzinfo=timezone.utc)
                
            delta_days = (valid_until_dt - ref_dt).days
            if delta_days > max_acceptance_days:
                msg = f"Regra '{rule_id}' possui validade de {delta_days} dias, ultrapassando o limite máximo de {max_acceptance_days} dias."
                alerts.append({"level": "warning", "title": "Regra Inválida", "message": msg})
                rule_copy["validation_error"] = msg
                rule_copy["status"] = "invalid"
                invalid_rules.append(rule_copy)
                continue

        valid_rules.append(rule_copy)

    return valid_rules, invalid_rules, alerts

SPECIFICITY_WEIGHTS = {
    "cve": 5,
    "agent_id": 5,
    "agent_name": 4,
    "package": 4,
    "severity": 2,
    "asset_type": 2,
    "technical_owner": 2,
    "business_owner": 2,
    "environment": 1,
    "criticality": 2,
    "exposure_level": 2,
    "network_zone": 1,
    "tag": 1
}

def calculate_rule_specificity(rule: dict) -> int:
    """Calcula a especificidade de uma regra baseada nos pesos definidos."""
    match_criteria = rule.get("match", {})
    score = 0
    for key in match_criteria.keys():
        score += SPECIFICITY_WEIGHTS.get(key, 0)
    return score

def find_matching_acceptance_rule(
    cve: str,
    agent_id: str,
    agent_name: str,
    package_name: str,
    severity: str,
    asset_ctx: dict,
    expo_ctx: dict,
    valid_rules: List[dict]
) -> Tuple[Optional[dict], str, bool]:
    """Procura a regra de exceção mais específica aplicável."""
    matched_rules = []
    
    for rule in valid_rules:
        if not rule.get("enabled", True):
            continue
            
        match_criteria = rule.get("match", {})
        is_match = True
        
        for key, val in match_criteria.items():
            if val is None:
                is_match = False
                break
                
            val_str = str(val).lower().strip()
            
            if key == "cve":
                if str(cve).lower().strip() != val_str:
                    is_match = False
                    break
            elif key == "agent_id":
                aid_norm = str(agent_id).zfill(3) if str(agent_id).isdigit() else str(agent_id)
                val_norm = val_str.zfill(3) if val_str.isdigit() else val_str
                if aid_norm != val_norm:
                    is_match = False
                    break
            elif key == "agent_name":
                if str(agent_name).lower().strip() != val_str:
                    is_match = False
                    break
            elif key == "package":
                if str(package_name).lower().strip() != val_str:
                    is_match = False
                    break
            elif key == "severity":
                if str(severity).lower().strip() != val_str:
                    is_match = False
                    break
            elif key == "asset_type":
                if str(asset_ctx.get("asset_type", "")).lower().strip() != val_str:
                    is_match = False
                    break
            elif key == "technical_owner":
                if str(asset_ctx.get("technical_owner", "")).lower().strip() != val_str:
                    is_match = False
                    break
            elif key == "business_owner":
                if str(asset_ctx.get("business_owner", "")).lower().strip() != val_str:
                    is_match = False
                    break
            elif key == "environment":
                if str(asset_ctx.get("environment", "")).lower().strip() != val_str:
                    is_match = False
                    break
            elif key == "criticality":
                if str(asset_ctx.get("criticality", "")).lower().strip() != val_str:
                    is_match = False
                    break
            elif key == "exposure_level":
                if str(expo_ctx.get("exposure_level", "")).lower().strip() != val_str:
                    is_match = False
                    break
            elif key == "network_zone":
                if str(expo_ctx.get("network_zone", "")).lower().strip() != val_str:
                    is_match = False
                    break
            elif key == "tag":
                asset_tags = [str(t).lower().strip() for t in asset_ctx.get("tags", [])]
                if val_str not in asset_tags:
                    is_match = False
                    break
            else:
                is_match = False
                break
                
        if is_match:
            matched_rules.append(rule)
            
    if not matched_rules:
        return None, "none", False

    now_dt = datetime.now(timezone.utc)
    
    def sorting_key(rule_data):
        spec = calculate_rule_specificity(rule_data)
        valid_until_str = rule_data.get("valid_until")
        diff_ms = float('inf')
        if valid_until_str:
            try:
                clean_date = valid_until_str.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_date)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                diff_ms = abs((dt - now_dt).total_seconds())
            except Exception:
                pass
        
        idx = -1
        try:
            idx = valid_rules.index(rule_data)
        except ValueError:
            pass
            
        return (-spec, diff_ms, idx)

    matched_rules.sort(key=sorting_key)
    best_rule = matched_rules[0]
    
    valid_until_str = best_rule.get("valid_until")
    expired = False
    if valid_until_str:
        try:
            clean_date = valid_until_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_date)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt < now_dt:
                expired = True
        except Exception:
            pass
            
    rule_status = best_rule.get("status", "none")
    if expired:
        return best_rule, "expired", True
    return best_rule, rule_status, False

def get_days_to_expiration(valid_until_str: str) -> Optional[int]:
    if not valid_until_str:
        return None
    try:
        clean_date = valid_until_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_date)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now_dt = datetime.now(timezone.utc)
        return (dt.date() - now_dt.date()).days
    except Exception:
        return None

def _merge_exposure_context(exposure_info: dict, defaults: dict) -> dict:
    res = defaults.copy()
    for k in defaults.keys():
        if k in exposure_info:
            res[k] = exposure_info[k]
    # Normalização robusta de strings de exposição
    for key in ["exposure_level", "network_zone", "confidence"]:
        if key in res and isinstance(res[key], str):
            res[key] = res[key].lower().strip()
    return res

def generate_vulnerability_key(cve: str, agent_id: str, package: str, severity: str) -> str:
    """Gera uma chave SHA-256 estável para cada ocorrência de vulnerabilidade."""
    raw_str = f"{cve or ''}|{agent_id or ''}|{package or ''}|{severity or ''}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

def add_days(start_date_iso: str, days: int, business_days_only: bool = False) -> str:
    """Adiciona dias (úteis ou civis) a uma data ISO 8601 e retorna em ISO 8601."""
    try:
        clean_iso = start_date_iso.replace("Z", "")
        if "." in clean_iso:
            clean_iso = clean_iso.split(".")[0]
        dt = datetime.fromisoformat(clean_iso)
    except Exception:
        dt = datetime.now()
        
    if not business_days_only:
        res_dt = dt + timedelta(days=days)
    else:
        added = 0
        res_dt = dt
        while added < days:
            res_dt += timedelta(days=1)
            if res_dt.weekday() < 5:
                added += 1
    return res_dt.isoformat() + "Z"

def calculate_days_difference(start_date_iso: str, end_date_iso: str, business_days_only: bool = False) -> int:
    """Calcula a diferença (end - start) em dias (úteis ou civis)."""
    try:
        s_clean = start_date_iso.replace("Z", "")
        if "." in s_clean:
            s_clean = s_clean.split(".")[0]
        s_dt = datetime.fromisoformat(s_clean)
    except Exception:
        s_dt = datetime.now()
        
    try:
        e_clean = end_date_iso.replace("Z", "")
        if "." in e_clean:
            e_clean = e_clean.split(".")[0]
        e_dt = datetime.fromisoformat(e_clean)
    except Exception:
        e_dt = datetime.now()
        
    s_date = s_dt.date()
    e_date = e_dt.date()
    
    if not business_days_only:
        return (e_date - s_date).days
    else:
        if s_date == e_date:
            return 0
        is_negative = s_date > e_date
        if is_negative:
            s_date, e_date = e_date, s_date
        
        work_days = 0
        curr = s_date
        while curr < e_date:
            curr += timedelta(days=1)
            if curr.weekday() < 5:
                work_days += 1
        return -work_days if is_negative else work_days

def calculate_sla_days(severity: str, is_kev: bool, asset_ctx: dict, expo_ctx: dict, sla_policy: dict) -> int:
    """Calcula o menor SLA aplicável com base na severidade e contextos."""
    sev = str(severity).lower().strip()
    if sev not in ["critical", "high", "medium", "low"]:
        sev = "medium"
        
    defaults = sla_policy.get("defaults", {"critical": 15, "high": 30, "medium": 60, "low": 90})
    sla_candidates = [defaults.get(sev, 60)]
    
    if is_kev:
        kev_policy = sla_policy.get("kev", {})
        if sev in kev_policy:
            sla_candidates.append(kev_policy[sev])
            
    if expo_ctx.get("internet_facing", False):
        if_policy = sla_policy.get("internet_facing", {})
        if sev in if_policy:
            sla_candidates.append(if_policy[sev])
            
    if expo_ctx.get("dmz", False):
        dmz_policy = sla_policy.get("dmz", {})
        if sev in dmz_policy:
            sla_candidates.append(dmz_policy[sev])
            
    asset_crit = str(asset_ctx.get("criticality", "")).lower().strip()
    if asset_crit == "critical":
        ca_policy = sla_policy.get("critical_asset", {})
        if sev in ca_policy:
            sla_candidates.append(ca_policy[sev])
    elif asset_crit == "high":
        ha_policy = sla_policy.get("high_asset", {})
        if sev in ha_policy:
            sla_candidates.append(ha_policy[sev])
            
    # Verificar serviços sensíveis
    sensitive_list = {"rdp", "ssh", "vpn", "database", "smb", "ldap", "winrm", "admin_ui", "kibana", "wazuh", "qradar", "cyberark"}
    has_sensitive_svc = False
    for svc in expo_ctx.get("open_services", []):
        svc_name = str(svc.get("service", "")).lower().strip()
        if svc_name in sensitive_list:
            has_sensitive_svc = True
            break
            
    if has_sensitive_svc:
        ss_policy = sla_policy.get("sensitive_service", {})
        if sev in ss_policy:
            sla_candidates.append(ss_policy[sev])
            
    return min(sla_candidates)

def calculate_sla_operational_score(
    sla_status: str,
    persistent: bool,
    recurring: bool,
    asset_crit: str,
    is_kev: bool,
    internet_facing: bool
) -> float:
    """Calcula o acréscimo operacional no score de risco."""
    score = 0.0
    if sla_status == "overdue":
        score += 15.0
        if asset_crit == "critical":
            score += 10.0
        if is_kev:
            score += 10.0
        if internet_facing:
            score += 10.0
    elif sla_status == "due_soon":
        score += 8.0
        
    if persistent:
        score += 10.0
    if recurring:
        score += 5.0
        
    return score

def calculate_agent_risk_modifiers(agent_id: str, agent_name: str, assets_data: dict, exposure_data: dict) -> Tuple[float, dict, float, dict, List[str]]:
    """Calcula a pontuação de criticidade (Fase 3B) e a pontuação de exposição (Fase 3C) de um ativo."""
    # 1. Asset Context Score (Fase 3B)
    ctx_info = get_asset_context(assets_data, agent_id, agent_name)
    crit = ctx_info.get("criticality", "unknown")
    expo = ctx_info.get("exposure", "unknown")
    env = ctx_info.get("environment", "unknown")
    atype = ctx_info.get("asset_type", "unknown")
    
    crit_val = WEIGHT_CRITICALITY.get(crit, WEIGHT_CRITICALITY["unknown"])
    expo_val = WEIGHT_EXPOSURE.get(expo, WEIGHT_EXPOSURE["unknown"])
    env_val = WEIGHT_ENVIRONMENT.get(env, WEIGHT_ENVIRONMENT["unknown"])
    atype_val = WEIGHT_ASSET_TYPE.get(atype, WEIGHT_ASSET_TYPE["unknown"])
    
    asset_score = crit_val + expo_val + env_val + atype_val
    
    # 2. Exposure Context Score (Fase 3C)
    expo_ctx = get_exposure_context(exposure_data, agent_id, agent_name)
    expo_level = expo_ctx.get("exposure_level", "unknown")
    net_zone = expo_ctx.get("network_zone", "unknown")
    
    level_weight = WEIGHT_EXPOSURE_LEVEL.get(expo_level, WEIGHT_EXPOSURE_LEVEL["unknown"])
    zone_weight = WEIGHT_NETWORK_ZONE.get(net_zone, WEIGHT_NETWORK_ZONE["unknown"])
    
    flags_weight = 0
    if expo_ctx.get("internet_facing", False):
        flags_weight += 15
    if expo_ctx.get("dmz", False):
        flags_weight += 10
    if expo_ctx.get("has_public_ip", False):
        flags_weight += 10
    if expo_ctx.get("has_public_dns", False):
        flags_weight += 8
    if expo_level == "unknown":
        flags_weight += 5
        
    services_sum = 0
    for svc in expo_ctx.get("open_services", []):
        svc_name = svc.get("service", "").lower()
        svc_expo = svc.get("exposure", "").lower()
        if not svc_expo:
            svc_expo = "internet" if expo_ctx.get("internet_facing", False) or expo_level in ["internet", "dmz"] else "internal"
        weight = WEIGHT_SERVICES.get((svc_name, svc_expo), 0)
        services_sum += weight
        
    services_weight = min(services_sum, 25)
    exposure_score = level_weight + zone_weight + flags_weight + services_weight
    
    # Gerar motivos contextuais
    reasons = []
    if crit in ["critical", "high", "medium"]:
        reasons.append(f"Ativo {crit.capitalize()}")
    elif crit == "unknown":
        reasons.append("Ativo sem classificação")
        
    if expo_level in ["internet", "dmz"]:
        reasons.append(f"Exposição {expo_level.upper()}")
    elif expo in ["internet", "dmz"]:
        reasons.append(f"Exposição {expo.upper()}")
        
    if env == "production":
        reasons.append("Ambiente Produção")
        
    if atype not in ["unknown", "linux_server", "windows_server", "endpoint"]:
        reasons.append(f"Tipo {atype.upper()}")
        
    if expo_ctx.get("internet_facing", False):
        reasons.append("Exposição Internet")
    if expo_ctx.get("dmz", False):
        reasons.append("Zona DMZ")
    
    if services_sum > 0:
        critical_declared = [s.get("service", "").upper() for s in expo_ctx.get("open_services", []) if s.get("critical")]
        if critical_declared:
            reasons.append(f"Serviço {critical_declared[0]} exposto")
            
    return asset_score, ctx_info, exposure_score, expo_ctx, reasons

SCRIPT_NAME = "HMG Wazuh SOAR Brain"
SCRIPT_VERSION = "2.0.0"

# Padrões de segredos que BLOQUEIAM a publicação
_SECRETS_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]+", re.IGNORECASE),
    re.compile(r"Authorization\s*[:=]\s*", re.IGNORECASE),
    re.compile(r"OPENSEARCH_PASS\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"WAZUH_API_PASS\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"password\s*[:=]\s*[\"']?[^\s\"']{4,}", re.IGNORECASE),
    re.compile(r"token\s*[:=]\s*[\"']?[A-Za-z0-9\-_\.]{20,}", re.IGNORECASE),
]

DEFAULT_WEB_GROUP = os.getenv("HMG_WEB_GROUP", "www-data")

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


@dataclass
class AppContext:
    indexer_pass: Optional[str] = os.getenv("OPENSEARCH_PASS")
    wazuh_pass: Optional[str] = os.getenv("WAZUH_API_PASS")
    wazuh_token: Optional[str] = None
    wazuh_token_obtained_at: Optional[float] = None
    cvss_threshold: float = DEFAULT_CVSS_THRESHOLD
    epss_threshold: float = DEFAULT_EPSS_THRESHOLD
    session: requests.Session = field(default_factory=lambda: requests.Session())
    use_cache: bool = True
    timings: Dict[str, float] = field(default_factory=dict)

    def __post_init__(self):
        self.session.verify = False
        # Retry automático com backoff exponencial para resiliência em rede
        retry_strategy = Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def record_timing(self, label: str, elapsed: float) -> None:
        self.timings[label] = elapsed


@dataclass
class VulnRecord:
    agent_id: str
    agent_name: str
    cve: str
    package_name: str
    version: str
    severity: str
    cvss_score: Optional[float]
    is_kev: bool
    is_ransomware: bool
    epss_score: Optional[float]
    priority: str = "Priority 4"



def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _cache_path(name: str) -> Path:
    """Retorna o caminho do arquivo de cache para uma dada chave."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = hashlib.md5(name.encode()).hexdigest()
    return CACHE_DIR / f"{safe_name}.json"


def _cache_is_valid(path: Path) -> bool:
    """Verifica se o cache existe e ainda está dentro do TTL."""
    if not path.exists():
        return False
    mtime = datetime.fromtimestamp(path.stat().st_mtime)
    return datetime.now() - mtime < timedelta(hours=CACHE_TTL_HOURS)


def _read_cache(name: str) -> Optional[dict]:
    """Lê dados do cache local se válido (dentro do TTL)."""
    path = _cache_path(name)
    if _cache_is_valid(path):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


def _read_stale_cache(name: str) -> Optional[dict]:
    """Lê dados do cache local *ignorando TTL* (stale fallback de emergência).

    Usado quando todas as fontes primárias e fallback falharam.
    Retorna os dados mais recentes disponíveis no disco, independentemente da idade.
    """
    path = _cache_path(name)
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            age_hours = (datetime.now() - datetime.fromtimestamp(path.stat().st_mtime)).total_seconds() / 3600
            logger.warning(
                f"[STALE CACHE] Usando cache expirado de '{name}' "
                f"(idade: {age_hours:.1f}h, TTL: {CACHE_TTL_HOURS}h). "
                "Dados podem não refletir a inteligência mais recente."
            )
            return data
        except (json.JSONDecodeError, OSError):
            return None
    return None


def _write_cache(name: str, data: dict) -> None:
    """Persiste dados no cache local."""
    path = _cache_path(name)
    try:
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        logger.warning(f"Não foi possível gravar cache '{name}': {e}")


def _epss_csv_cache_path() -> Path:
    """Retorna o caminho do arquivo CSV bruto do EPSS no cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / EPSS_CSV_CACHE_FILENAME


def _epss_csv_cache_is_valid() -> bool:
    """Verifica se o CSV diário do EPSS ainda está dentro do TTL dedicado."""
    path = _epss_csv_cache_path()
    if not path.exists():
        return False
    mtime = datetime.fromtimestamp(path.stat().st_mtime)
    return datetime.now() - mtime < timedelta(hours=EPSS_CSV_CACHE_TTL_HOURS)


# ==========================================
# FUNÇÕES DE PUBLICAÇÃO WEB
# ==========================================

def _validate_no_secrets(content: str, label: str) -> bool:
    """
    Valida que o conteúdo NÃO contém credenciais ou tokens.
    Retorna True se seguro, False se detectar segredos (BLOQUEANTE).
    """
    for pattern in _SECRETS_PATTERNS:
        match = pattern.search(content)
        if match:
            logger.error(
                f"[BLOQUEADO] Segredo detectado em '{label}': padrão '{pattern.pattern}' "
                f"encontrou '{match.group()[:20]}...'. Publicação CANCELADA."
            )
            return False
    return True


def _atomic_write(content: str, dest_path: Path, web_group: Optional[str] = None) -> None:
    """
    Escrita atômica: cria temp no mesmo diretório, fsync, os.replace().
    Se falhar, o arquivo original permanece intacto.
    """
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    fd = None
    tmp_path = None
    try:
        # Criar temp no mesmo filesystem para garantir atomicidade do rename
        fd = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(dest_path.parent),
            prefix=".hmg_tmp_",
            suffix=dest_path.suffix or ".tmp",
            delete=False,
        )
        tmp_path = Path(fd.name)
        fd.write(content)
        fd.flush()
        os.fsync(fd.fileno())
        fd.close()
        fd = None

        # Permissões: owner rw, group r, others r (0o644)
        os.chmod(str(tmp_path), stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

        # Ajustar grupo do web server se especificado
        if web_group:
            try:
                if _grp is None:
                    logger.warning("Módulo 'grp' indisponível (Windows). Pulando ajuste de grupo.")
                else:
                    gid = _grp.getgrnam(web_group).gr_gid
                    os.chown(str(tmp_path), -1, gid)
            except (KeyError, PermissionError) as e:
                logger.warning(f"Não foi possível definir grupo '{web_group}': {e}")

        # Rename atômico
        os.replace(str(tmp_path), str(dest_path))

    except Exception:
        # Limpar temp se falhar
        if fd is not None:
            fd.close()
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise


def _build_report_metadata(
    ctx: AppContext,
    records: List["VulnRecord"],
    agent_ids: List[str],
    mode: str,
) -> dict:
    """Monta dicionário de metadados do relatório, reutilizado em HTML e JSON."""
    unique_cves = set(r.cve for r in records)
    unique_agents = set(r.agent_id for r in records)

    p_counts = {"Priority 1+": 0, "Priority 1": 0, "Priority 2": 0, "Priority 3": 0, "Priority 4": 0}
    for r in records:
        if r.priority in p_counts:
            p_counts[r.priority] += 1

    return {
        "script_name": SCRIPT_NAME,
        "script_version": SCRIPT_VERSION,
        "generated_at": now(),
        "agents_analyzed": agent_ids,
        "execution_mode": mode,
        "cvss_threshold": ctx.cvss_threshold,
        "epss_threshold": ctx.epss_threshold,
        "total_records": len(records),
        "total_unique_cves": len(unique_cves),
        "total_agents": len(unique_agents),
        "priority_counts": p_counts,
    }


def export_json(
    ctx: AppContext,
    records: List["VulnRecord"],
    agent_ids: List[str],
    mode: str,
    output_path: str,
    web_group: Optional[str] = None,
) -> bool:
    """Gera JSON com dados do relatório + metadados. Retorna True se sucesso."""
    metadata = _build_report_metadata(ctx, records, agent_ids, mode)

    vuln_list = []
    for r in records:
        vuln_list.append({
            "agent_id": r.agent_id,
            "agent_name": r.agent_name,
            "cve": r.cve,
            "priority": r.priority,
            "cvss": r.cvss_score,
            "severity": r.severity,
            "epss": r.epss_score,
            "package": r.package_name,
            "version": r.version,
            "is_kev": r.is_kev,
            "is_ransomware": r.is_ransomware,
        })

    payload = {
        "metadata": metadata,
        "vulnerabilities": vuln_list,
    }

    json_content = json.dumps(payload, indent=2, ensure_ascii=False)

    # Validação bloqueante de segredos
    if not _validate_no_secrets(json_content, output_path):
        return False

    try:
        dest = Path(output_path)
        _atomic_write(json_content, dest, web_group)
        print(f"[+] JSON exportado com sucesso: {output_path}")
        return True
    except PermissionError as e:
        logger.error(f"[ERRO] Permissão negada ao gravar JSON em '{output_path}': {e}")
        logger.error("       Verifique as permissões do diretório ou execute com sudo.")
        return False
    except OSError as e:
        logger.error(f"[ERRO] Falha ao gravar JSON: {e}")
        return False


def publish_to_web(
    html_content: str,
    json_content: Optional[str],
    web_dir: str,
    web_group: Optional[str] = None,
) -> bool:
    """
    Publica HTML e JSON atomicamente no diretório web.
    Preserva cópia histórica em reports/.
    Retorna True se publicação foi bem-sucedida.
    """
    web_path = Path(web_dir)

    # Validação bloqueante de segredos no HTML
    if not _validate_no_secrets(html_content, "index.html"):
        return False

    # Validação bloqueante de segredos no JSON
    if json_content and not _validate_no_secrets(json_content, "data/latest.json"):
        return False

    try:
        # Criar estrutura de diretórios
        web_path.mkdir(parents=True, exist_ok=True)
        (web_path / "data").mkdir(parents=True, exist_ok=True)
        (web_path / "reports").mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        logger.error(
            f"[ERRO] Permissão negada ao criar diretórios em '{web_dir}': {e}\n"
            f"       Sugestão: sudo mkdir -p {web_dir} && sudo chown $USER:{web_group or 'www-data'} {web_dir}"
        )
        return False

    # Copiar assets estáticos (logo) para web
    assets_src = Path(__file__).resolve().parent / "assets"
    assets_dst = web_path / "assets"
    if assets_src.exists():
        assets_dst.mkdir(parents=True, exist_ok=True)
        for asset_file in assets_src.iterdir():
            if asset_file.is_file():
                dst_file = assets_dst / asset_file.name
                try:
                    shutil.copy2(asset_file, dst_file)
                    # ponytail: usa _atomic_write pattern para permissões; aqui basta 644
                    os.chmod(str(dst_file), stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
                except (PermissionError, OSError) as e:
                    logger.warning(f"[AVISO] Falha ao copiar asset {asset_file.name}: {e}")
    else:
        logger.info("[INFO] Diretório assets/ não encontrado. Logo não será publicada.")

    # Publicar index.html atomicamente
    index_path = web_path / "index.html"
    try:
        _atomic_write(html_content, index_path, web_group)
    except PermissionError as e:
        logger.error(
            f"[ERRO] Permissão negada ao publicar '{index_path}': {e}\n"
            f"       O arquivo index.html anterior permanece intacto."
        )
        return False
    except OSError as e:
        logger.error(f"[ERRO] Falha ao publicar index.html: {e}")
        return False

    # Publicar data/latest.json atomicamente
    if json_content:
        json_path = web_path / "data" / "latest.json"
        try:
            _atomic_write(json_content, json_path, web_group)
        except (PermissionError, OSError) as e:
            logger.warning(f"[AVISO] Falha ao publicar JSON: {e}. HTML foi publicado com sucesso.")

    # Cópia histórica
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    history_path = web_path / "reports" / f"relatorio_wazuh_{timestamp}.html"
    try:
        _atomic_write(html_content, history_path, web_group)
    except (PermissionError, OSError) as e:
        logger.warning(f"[AVISO] Falha ao criar cópia histórica: {e}. Publicação principal OK.")

    print(f"[+] Relatório publicado com sucesso em: {index_path}")
    print(f"    JSON: {web_path / 'data' / 'latest.json'}")
    print(f"    Histórico: {history_path}")
    return True


def generate_risk_intelligence(
    ctx: AppContext,
    records: List[VulnRecord],
    agent_ids: List[str],
    web_dir: str,
    web_group: Optional[str] = None
) -> None:
    """
    Fase 3C: Gera snapshots sanitizados de risco, calcula Top 10 prioridades,
    monta deltas comparativos com a execução anterior, gera alertas passivos,
    e incorpora o Asset Criticality Score (Fase 3B) e o Exposure Context/Superfície de Ataque (Fase 3C).
    """
    try:
        web_path = Path(web_dir)
        snapshots_dir = web_path / "data" / "snapshots"
        snapshots_dir.mkdir(parents=True, exist_ok=True)
        # 0. Carregar o contexto de ativos, de exposição, política de SLA e risk acceptance
        assets_data = load_assets_context()
        exposure_data = load_exposure_context()
        sla_policy = load_sla_policy()
        risk_acceptance_data = load_risk_acceptance()
        valid_rules, invalid_rules, validation_alerts = validate_risk_acceptance_rules(risk_acceptance_data)
        
        # 1. Gerar snapshot atual com contexto de ativos e de exposição (não-sensível)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        snapshot_filename = f"snapshot_{timestamp_str}.json"
        snapshot_path = snapshots_dir / snapshot_filename
        latest_snapshot_path = snapshots_dir / "latest_snapshot.json"
        previous_snapshot_path = snapshots_dir / "previous_snapshot.json"
        
        # Filtrar vulnerabilidades válidas para snapshot
        vulns_data = []
        for r in records:
            if not r.cve:
                continue
            key = f"{r.agent_id or r.agent_name}|{r.cve}|{r.package_name or 'unknown_package'}"
            context = get_asset_context(assets_data, r.agent_id, r.agent_name)
            expo_ctx = get_exposure_context(exposure_data, r.agent_id, r.agent_name)
            open_svcs = expo_ctx.get("open_services", [])
            top_svcs = [f"{s.get('service')}/{s.get('exposure')}" for s in open_svcs if s.get('service') and s.get('exposure')]
            
            # Executar o matching da Fase 3E
            matched_rule, acceptance_status, is_expired = find_matching_acceptance_rule(
                r.cve, r.agent_id, r.agent_name, r.package_name, r.severity, context, expo_ctx, valid_rules
            )
            
            vulns_data.append({
                "key": key,
                "agent_id": r.agent_id or "unknown",
                "agent_name": r.agent_name or "unknown",
                "cve": r.cve,
                "package_name": r.package_name or "unknown_package",
                "severity": r.severity or "unknown",
                "cvss_score": r.cvss_score,
                "epss_score": r.epss_score,
                "is_kev": bool(r.is_kev),
                "is_ransomware": bool(r.is_ransomware),
                "criticality": context.get("criticality", "unknown"),
                "environment": context.get("environment", "unknown"),
                "exposure": context.get("exposure", "unknown"),
                "asset_type": context.get("asset_type", "unknown"),
                "tags": context.get("tags", []),
                "hostname": context.get("asset_name", r.agent_name),
                # Campos da Fase 3C
                "exposure_level": expo_ctx.get("exposure_level", "unknown"),
                "network_zone": expo_ctx.get("network_zone", "unknown"),
                "internet_facing": bool(expo_ctx.get("internet_facing", False)),
                "dmz": bool(expo_ctx.get("dmz", False)),
                "has_public_ip": bool(expo_ctx.get("has_public_ip", False)),
                "has_public_dns": bool(expo_ctx.get("has_public_dns", False)),
                "source": expo_ctx.get("source", "manual"),
                "confidence": expo_ctx.get("confidence", "low"),
                "top_services": top_svcs,
                # Campos da Fase 3E
                "risk_acceptance_status": acceptance_status,
                "risk_acceptance_rule_id": matched_rule.get("id") if matched_rule else None,
                "risk_acceptance_expired": is_expired,
                "risk_acceptance_valid_until": matched_rule.get("valid_until") if matched_rule else None,
                "risk_acceptance_ticket": matched_rule.get("ticket") if matched_rule else None,
            })
            
        current_snapshot = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "agent_vulnerabilities": vulns_data
        }
        
        # Se o latest_snapshot.json atual existe, ele vira o previous_snapshot.json
        baseline_available = False
        previous_snapshot_data = None
        if latest_snapshot_path.exists():
            try:
                with open(latest_snapshot_path, "r", encoding="utf-8") as f:
                    previous_snapshot_data = json.load(f)
                previous_snapshot_json = json.dumps(previous_snapshot_data, indent=2, ensure_ascii=False)
                _atomic_write(previous_snapshot_json, previous_snapshot_path, web_group)
                baseline_available = True
            except Exception as e:
                logger.warning(f"[AVISO] Falha ao rotacionar latest_snapshot para previous_snapshot: {e}")
                
        # Calcular first_seen, occurrences e first_seen_estimated a partir dos snapshots anteriores
        first_seen_map = {}
        occurrences_map = {}
        first_seen_estimated_map = {}
        
        current_timestamp = current_snapshot["timestamp"]
        for v in current_snapshot["agent_vulnerabilities"]:
            v_key = generate_vulnerability_key(v["cve"], v["agent_id"], v["package_name"], v["severity"])
            first_seen_map[v_key] = current_timestamp
            occurrences_map[v_key] = 1
            first_seen_estimated_map[v_key] = True
            
        # Analisar snapshots históricos existentes
        snapshot_files = sorted(snapshots_dir.glob("snapshot_*.json"))
        vuln_timestamps = defaultdict(list)
        for f in snapshot_files:
            if not re.match(r"^snapshot_\d{8}_\d{6}\.json$", f.name):
                continue
            try:
                with open(f, "r", encoding="utf-8") as file:
                    data = json.load(file)
                ts = data.get("timestamp")
                if not ts:
                    continue
                for v in data.get("agent_vulnerabilities", []):
                    v_key = generate_vulnerability_key(v.get("cve"), v.get("agent_id"), v.get("package_name"), v.get("severity"))
                    vuln_timestamps[v_key].append(ts)
            except Exception as e:
                logger.warning(f"[AVISO] Falha ao ler snapshot histórico {f.name} para análise de SLA: {e}")
                
        # Atualizar mapas para as vulns correntes
        for v in current_snapshot["agent_vulnerabilities"]:
            v_key = generate_vulnerability_key(v["cve"], v["agent_id"], v["package_name"], v["severity"])
            ts_list = vuln_timestamps.get(v_key, [])
            if ts_list:
                ts_list.sort()
                first_seen_map[v_key] = ts_list[0]
                first_seen_estimated_map[v_key] = (ts_list[0] == current_timestamp)
                unique_ts = set(ts_list)
                unique_ts.add(current_timestamp)
                occurrences_map[v_key] = len(unique_ts)
                
        near_due_threshold = sla_policy.get("near_due_threshold_days", 5)
        persistent_threshold = sla_policy.get("persistent_threshold_days", 30)
        recurring_threshold = sla_policy.get("recurring_threshold_count", 3)
        business_days = bool(sla_policy.get("business_days_only", False))
        
        # Enriquecer vulnerabilidades do snapshot corrente
        for v in current_snapshot["agent_vulnerabilities"]:
            v_key = generate_vulnerability_key(v["cve"], v["agent_id"], v["package_name"], v["severity"])
            f_seen = first_seen_map[v_key]
            occ_count = occurrences_map[v_key]
            est_flag = first_seen_estimated_map[v_key]
            
            age_days = calculate_days_difference(f_seen, current_timestamp, business_days)
            if age_days < 0:
                age_days = 0
                
            v_agent_id = v["agent_id"]
            v_agent_name = v["agent_name"]
            v_asset_ctx = get_asset_context(assets_data, v_agent_id, v_agent_name)
            v_expo_ctx = get_exposure_context(exposure_data, v_agent_id, v_agent_name)
            
            sla_days = calculate_sla_days(v["severity"], v["is_kev"], v_asset_ctx, v_expo_ctx, sla_policy)
            due_date = add_days(f_seen, sla_days, business_days)
            days_to_due = calculate_days_difference(current_timestamp, due_date, business_days)
            
            if days_to_due < 0:
                sla_status = "overdue"
            elif 0 <= days_to_due <= near_due_threshold:
                sla_status = "due_soon"
            else:
                sla_status = "within_sla"
                
            persistent = (age_days >= persistent_threshold)
            recurring = (occ_count >= recurring_threshold)
            
            v["first_seen"] = f_seen
            v["last_seen"] = current_timestamp
            v["age_days"] = age_days
            v["sla_days"] = sla_days
            v["due_date"] = due_date
            v["days_to_due"] = days_to_due
            v["sla_status"] = sla_status
            v["first_seen_estimated"] = est_flag
            v["persistent"] = persistent
            v["recurring"] = recurring
            v["snapshot_occurrences"] = occ_count
            
            v_agent_id = v["agent_id"]
            v_agent_name = v["agent_name"]
            v_asset_ctx = get_asset_context(assets_data, v_agent_id, v_agent_name)
            v_expo_ctx = get_exposure_context(exposure_data, v_agent_id, v_agent_name)
            
            matched_rule, acceptance_status, is_expired = find_matching_acceptance_rule(
                v["cve"], v_agent_id, v_agent_name, v["package_name"], v["severity"], v_asset_ctx, v_expo_ctx, valid_rules
            )
            
            v["risk_accepted"] = (acceptance_status == "accepted")
            v["acceptance_status"] = acceptance_status
            v["acceptance_reason"] = matched_rule.get("reason") if matched_rule else None
            v["accepted_until"] = matched_rule.get("valid_until") if matched_rule else None
            
            v["risk_acceptance"] = {
                "status": acceptance_status,
                "rule_id": matched_rule.get("id") if matched_rule else None,
                "reason": matched_rule.get("reason") if matched_rule else None,
                "approved_by": matched_rule.get("approved_by") if matched_rule else None,
                "valid_until": matched_rule.get("valid_until") if matched_rule else None,
                "days_to_expiration": get_days_to_expiration(matched_rule.get("valid_until")) if matched_rule else None,
                "expired": is_expired,
                "ticket": matched_rule.get("ticket") if matched_rule else None,
                "owner": matched_rule.get("owner") if matched_rule else None
            }
            
        current_snapshot_json = json.dumps(current_snapshot, indent=2, ensure_ascii=False)
        _atomic_write(current_snapshot_json, snapshot_path, web_group)
        _atomic_write(current_snapshot_json, latest_snapshot_path, web_group)
        
        # 2. Calcular Delta
        delta_info = {
            "new_vulnerabilities": 0,
            "resolved_vulnerabilities": 0,
            "persistent_vulnerabilities": 0,
            "new_kev": 0,
            "resolved_kev": 0,
            "new_critical": 0,
            "resolved_critical": 0,
            "agents_worsened": 0,
            "agents_improved": 0
        }
        new_items = []
        resolved_items = []
        worsened_agents = []
        improved_agents = []
        
        if baseline_available and previous_snapshot_data:
            curr_dict = {v["key"]: v for v in current_snapshot["agent_vulnerabilities"]}
            prev_dict = {v["key"]: v for v in previous_snapshot_data.get("agent_vulnerabilities", [])}
            
            curr_keys = set(curr_dict.keys())
            prev_keys = set(prev_dict.keys())
            
            new_keys = curr_keys - prev_keys
            resolved_keys = prev_keys - curr_keys
            persistent_keys = curr_keys & prev_keys
            
            new_items = [curr_dict[k] for k in new_keys]
            resolved_items = [prev_dict[k] for k in resolved_keys]
            
            delta_info["new_vulnerabilities"] = len(new_keys)
            delta_info["resolved_vulnerabilities"] = len(resolved_keys)
            delta_info["persistent_vulnerabilities"] = len(persistent_keys)
            
            delta_info["new_kev"] = sum(1 for v in new_items if v.get("is_kev"))
            delta_info["resolved_kev"] = sum(1 for v in resolved_items if v.get("is_kev"))
            delta_info["new_critical"] = sum(1 for v in new_items if str(v.get("severity")).lower() == "critical")
            delta_info["resolved_critical"] = sum(1 for v in resolved_items if str(v.get("severity")).lower() == "critical")
            
            # Calcular alteração por agente
            curr_agent_counts = defaultdict(int)
            for v in current_snapshot["agent_vulnerabilities"]:
                curr_agent_counts[v["agent_id"]] += 1
                
            prev_agent_counts = defaultdict(int)
            for v in previous_snapshot_data.get("agent_vulnerabilities", []):
                prev_agent_counts[v["agent_id"]] += 1
                
            all_agents = set(curr_agent_counts.keys()) | set(prev_agent_counts.keys())
            
            # Mapeamento de id -> nome
            agent_names = {}
            for v in current_snapshot["agent_vulnerabilities"]:
                agent_names[v["agent_id"]] = v["agent_name"]
            for v in previous_snapshot_data.get("agent_vulnerabilities", []):
                agent_names[v["agent_id"]] = v["agent_name"]
                
            for aid in all_agents:
                if aid == "unknown":
                    continue
                cnt_c = curr_agent_counts[aid]
                cnt_p = prev_agent_counts[aid]
                if cnt_c > cnt_p:
                    delta_info["agents_worsened"] += 1
                    worsened_agents.append({
                        "agent_id": aid,
                        "agent_name": agent_names.get(aid, "unknown"),
                        "previous_count": cnt_p,
                        "current_count": cnt_c
                    })
                elif cnt_c < cnt_p:
                    delta_info["agents_improved"] += 1
                    improved_agents.append({
                        "agent_id": aid,
                        "agent_name": agent_names.get(aid, "unknown"),
                        "previous_count": cnt_p,
                        "current_count": cnt_c
                    })
                    
        risk_delta = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "ok" if baseline_available else "no_baseline",
            "baseline_available": baseline_available,
            "current_snapshot": snapshot_filename,
            "previous_snapshot": "snapshot_previous.json" if baseline_available else None,
            "delta": delta_info,
            "new_items": new_items,
            "resolved_items": resolved_items,
            "worsened_agents": worsened_agents,
            "improved_agents": improved_agents
        }
        
        # 2.1 Coletar todos os agentes vistos nos registros de vulnerabilidade
        unique_agents_seen = {}
        for r in records:
            if not r.agent_id or r.agent_id == "N/A":
                continue
            unique_agents_seen[r.agent_id] = r.agent_name
            
        # Calcular estatísticas do contexto de ativos
        total_seen = len(unique_agents_seen)
        classified_count = 0
        unclassified_count = 0
        
        crit_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        expo_counts = {"internet": 0, "dmz": 0, "internal": 0, "isolated": 0, "unknown": 0}
        
        unclassified_assets = []
        agent_risk_scores = defaultdict(float)
        agent_vuln_counts = defaultdict(int)
        
        for aid, aname in unique_agents_seen.items():
            ctx_info = get_asset_context(assets_data, aid, aname)
            crit = ctx_info.get("criticality", "unknown")
            expo = ctx_info.get("exposure", "unknown")
            
            if crit == "unknown":
                unclassified_count += 1
                unclassified_assets.append({
                    "agent_id": aid,
                    "agent_name": aname
                })
            else:
                classified_count += 1
                
            crit_counts[crit] = crit_counts.get(crit, 0) + 1
            expo_counts[expo] = expo_counts.get(expo, 0) + 1
            
        # 3. Calcular Prioridades (Top 10) e Risco por Ativo
        curr_vulns_dict = {
            generate_vulnerability_key(v["cve"], v["agent_id"], v["package_name"], v["severity"]): v 
            for v in current_snapshot["agent_vulnerabilities"]
        }
        
        vuln_groups = defaultdict(list)
        for r in records:
            if not r.cve:
                continue
            vuln_groups[(r.cve, r.package_name or "unknown_package")].append(r)
            
        priorities = []
        sensitive_packages = {
            "openssl", "curl", "sudo", "openssh", "openssh-server", "kernel", "linux-image", 
            "glibc", "libc", "apache", "nginx", "php", "python", "java", "log4j", "docker", 
            "containerd", "kubernetes"
        }
        
        for (cve, package_name), group_records in vuln_groups.items():
            sample = group_records[0]
            severity = sample.severity or "unknown"
            cvss_score = sample.cvss_score
            epss_score = sample.epss_score
            is_kev = bool(sample.is_kev)
            is_ransomware = bool(sample.is_ransomware)
            
            affected_ids = list(set(r.agent_id for r in group_records if r.agent_id))
            affected_count = len(affected_ids)
            
            # Base técnica
            score_rec = 0.0
            reasons = []
            
            if is_kev:
                score_rec += 40
                reasons.append("KEV ativo")
            if str(severity).lower() == "critical":
                score_rec += 25
                reasons.append("Severidade Crítica")
            elif str(severity).lower() == "high":
                score_rec += 15
                reasons.append("Severidade Alta")
                
            if epss_score is not None:
                if epss_score >= 0.50:
                    score_rec += 30
                    reasons.append("EPSS muito alto")
                elif epss_score >= 0.20:
                    score_rec += 20
                    reasons.append("EPSS alto")
                    
            if affected_count > 0:
                score_rec += min(affected_count * 3, 15)
                if affected_count > 1:
                    reasons.append(f"Múltiplos agentes ({affected_count})")
                    
            if str(package_name).lower() in sensitive_packages:
                score_rec += 10
                reasons.append("Pacote sensível")
                
            # Escolher o agente com a maior pontuação ajustada (Contexto + Exposição + SLA)
            best_agent_id = None
            best_final_score = -1
            best_asset_ctx = None
            best_expo_ctx = None
            best_contextual_reasons = []
            best_v_enriched = None
            
            for r in group_records:
                asset_score, asset_ctx, expo_score, expo_ctx, ctx_reasons = calculate_agent_risk_modifiers(
                    r.agent_id, r.agent_name, assets_data, exposure_data
                )
                
                v_key = generate_vulnerability_key(r.cve, r.agent_id, r.package_name, r.severity)
                v_enriched = curr_vulns_dict.get(v_key, {})
                
                sla_status = v_enriched.get("sla_status", "within_sla")
                persistent = bool(v_enriched.get("persistent", False))
                recurring = bool(v_enriched.get("recurring", False))
                asset_crit = v_enriched.get("criticality", "unknown")
                is_kev_val = bool(v_enriched.get("is_kev", False))
                internet_facing = bool(v_enriched.get("internet_facing", False))
                
                sla_op_score = calculate_sla_operational_score(
                    sla_status, persistent, recurring, asset_crit, is_kev_val, internet_facing
                )
                
                # Matching de risk acceptance para ajustar a prioridade operacional
                cand_rule, cand_a_status, cand_expired = find_matching_acceptance_rule(
                    r.cve, r.agent_id, r.agent_name, r.package_name, r.severity, asset_ctx, expo_ctx, valid_rules
                )
                cand_score = score_rec + asset_score + expo_score + sla_op_score
                if cand_a_status == "accepted":
                    cand_score -= 30.0
                elif cand_a_status == "compensating_control":
                    cand_score -= 15.0
                elif cand_a_status == "expired" or cand_expired:
                    cand_score += 10.0
                cand_score = max(0.0, min(100.0, cand_score))
                if cand_score > best_final_score:
                    best_final_score = cand_score
                    best_agent_id = r.agent_id
                    best_asset_ctx = asset_ctx
                    best_expo_ctx = expo_ctx
                    best_v_enriched = v_enriched
                    
                    local_reasons = list(ctx_reasons)
                    if sla_status == "overdue":
                        local_reasons.append(f"SLA vencido há {abs(v_enriched.get('days_to_due', 0))} dias")
                    if persistent:
                        local_reasons.append("aging persistente")
                    if recurring:
                        local_reasons.append(f"recorrente em {v_enriched.get('snapshot_occurrences', 1)} snapshots")
                    best_contextual_reasons = local_reasons
                    
            # Combinar motivos
            all_reasons = reasons + best_contextual_reasons
            seen_reasons = set()
            uniq_reasons = []
            for rs in all_reasons:
                if rs not in seen_reasons:
                    seen_reasons.add(rs)
                    uniq_reasons.append(rs)
            reason_str = " + ".join(uniq_reasons) if uniq_reasons else "Prioridade geral"
            
            open_svcs = best_expo_ctx.get("open_services", [])
            top_svcs = [f"{s.get('service')}/{s.get('exposure')}" for s in open_svcs if s.get('service') and s.get('exposure')]
            
            sla_ctx = {}
            if best_v_enriched:
                sla_ctx = {
                    "first_seen": best_v_enriched.get("first_seen"),
                    "age_days": best_v_enriched.get("age_days"),
                    "sla_days": best_v_enriched.get("sla_days"),
                    "due_date": best_v_enriched.get("due_date"),
                    "days_to_due": best_v_enriched.get("days_to_due"),
                    "sla_status": best_v_enriched.get("sla_status"),
                    "persistent": best_v_enriched.get("persistent"),
                    "recurring": best_v_enriched.get("recurring"),
                    "snapshot_occurrences": best_v_enriched.get("snapshot_occurrences"),
                    "first_seen_estimated": best_v_enriched.get("first_seen_estimated")
                }
                
            cvss_val = cvss_score or 0.0
            epss_val = epss_score or 0.0
            p_level = "Priority 4"
            if is_kev:
                p_level = "Priority 1+"
            elif cvss_val >= ctx.cvss_threshold and epss_val >= ctx.epss_threshold:
                p_level = "Priority 1"
            elif cvss_val >= ctx.cvss_threshold:
                p_level = "Priority 2"
            elif epss_val >= ctx.epss_threshold:
                p_level = "Priority 3"

            priorities.append({
                "cve": cve,
                "package": package_name,
                "severity": severity,
                "kev": is_kev,
                "epss": epss_score,
                "affected_agents": affected_count,
                "priority_score": int(best_final_score),
                "reason": reason_str,
                "asset_context": {
                    "criticality": best_asset_ctx.get("criticality", "unknown"),
                    "environment": best_asset_ctx.get("environment", "unknown"),
                    "exposure": best_asset_ctx.get("exposure", "unknown"),
                    "asset_type": best_asset_ctx.get("asset_type", "unknown"),
                    "business_owner": best_asset_ctx.get("business_owner", "unknown"),
                    "technical_owner": best_asset_ctx.get("technical_owner", "unknown"),
                    "tags": best_asset_ctx.get("tags", [])
                },
                "exposure_context": {
                    "exposure_level": best_expo_ctx.get("exposure_level", "unknown"),
                    "network_zone": best_expo_ctx.get("network_zone", "unknown"),
                    "internet_facing": bool(best_expo_ctx.get("internet_facing", False)),
                    "dmz": bool(best_expo_ctx.get("dmz", False)),
                    "has_public_ip": bool(best_expo_ctx.get("has_public_ip", False)),
                    "has_public_dns": bool(best_expo_ctx.get("has_public_dns", False)),
                    "source": best_expo_ctx.get("source", "manual"),
                    "confidence": best_expo_ctx.get("confidence", "low"),
                    "top_services": top_svcs
                },
                "sla_context": sla_ctx,
                "cvss": cvss_val,
                "priority": p_level,
                "_cvss": cvss_val
            })
            
        # Enriquecer priorities com a info de risk_acceptance
        for item in priorities:
            cve = item["cve"]
            pkg = item["package"]
            # Encontrar no current_snapshot se existe a vulnerabilidade enriquecida correspondente
            match_v = None
            for v in current_snapshot["agent_vulnerabilities"]:
                if v["cve"] == cve and v["package_name"] == pkg:
                    match_v = v
                    break
            if match_v:
                item["risk_acceptance"] = match_v["risk_acceptance"]
            else:
                item["risk_acceptance"] = {"status": "none", "expired": False}

        priorities.sort(key=lambda x: (-x["priority_score"], -x["_cvss"]))
        
        top_priorities = []
        for idx, item in enumerate(priorities[:10]):
            item_copy = dict(item)
            item_copy["rank"] = idx + 1
            item_clean = {k: v for k, v in item_copy.items() if k != "_cvss"}
            top_priorities.append(item_clean)
            
        actionable_list = [p for p in priorities if not (p["risk_acceptance"]["status"] in ["accepted", "false_positive", "out_of_scope", "duplicate"] and not p["risk_acceptance"]["expired"])]
        top_actionable_priorities = []
        for idx, item in enumerate(actionable_list[:10]):
            item_copy = dict(item)
            item_copy["rank"] = idx + 1
            item_clean = {k: v for k, v in item_copy.items() if k != "_cvss"}
            top_actionable_priorities.append(item_clean)
            
        excluding_accepted_list = [p for p in priorities if not (p["risk_acceptance"]["status"] == "accepted" and not p["risk_acceptance"]["expired"])]
        top_priorities_excluding_accepted = []
        for idx, item in enumerate(excluding_accepted_list[:10]):
            item_copy = dict(item)
            item_copy["rank"] = idx + 1
            item_clean = {k: v for k, v in item_copy.items() if k != "_cvss"}
            top_priorities_excluding_accepted.append(item_clean)
            
        accepted_items = []
        for item in priorities:
            if item["risk_acceptance"]["status"] == "accepted" and not item["risk_acceptance"]["expired"]:
                item_copy = dict(item)
                item_clean = {k: v for k, v in item_copy.items() if k != "_cvss"}
                accepted_items.append(item_clean)
                
        false_positive_items = []
        for item in priorities:
            if item["risk_acceptance"]["status"] == "false_positive" and not item["risk_acceptance"]["expired"]:
                item_copy = dict(item)
                item_clean = {k: v for k, v in item_copy.items() if k != "_cvss"}
                false_positive_items.append(item_clean)
                
        expired_acceptances_list = []
        for item in priorities:
            if item["risk_acceptance"]["expired"]:
                item_copy = dict(item)
                item_clean = {k: v for k, v in item_copy.items() if k != "_cvss"}
                expired_acceptances_list.append(item_clean)
            
        # Calcular risco cumulativo para os top ativos por risco (com SLA)
        for r in records:
            if not r.agent_id or r.agent_id == "N/A":
                continue
            agent_vuln_counts[r.agent_id] += 1
            
            is_kev = bool(r.is_kev)
            sample_severity = r.severity or "unknown"
            epss_val = r.epss_score
            
            score_rec = 0
            if is_kev:
                score_rec += 40
            if str(sample_severity).lower() == "critical":
                score_rec += 25
            elif str(sample_severity).lower() == "high":
                score_rec += 15
            if epss_val is not None:
                if epss_val >= 0.50:
                    score_rec += 30
                elif epss_val >= 0.20:
                    score_rec += 20
            if str(r.package_name).lower() in sensitive_packages:
                score_rec += 10
                
            asset_score, asset_ctx, expo_score, expo_ctx, _ = calculate_agent_risk_modifiers(
                r.agent_id, r.agent_name, assets_data, exposure_data
            )
            
            v_key = generate_vulnerability_key(r.cve, r.agent_id, r.package_name, r.severity)
            v_enriched = curr_vulns_dict.get(v_key, {})
            sla_status = v_enriched.get("sla_status", "within_sla")
            persistent = bool(v_enriched.get("persistent", False))
            recurring = bool(v_enriched.get("recurring", False))
            asset_crit = v_enriched.get("criticality", "unknown")
            is_kev_val = bool(v_enriched.get("is_kev", False))
            internet_facing = bool(v_enriched.get("internet_facing", False))
            
            sla_op_score = calculate_sla_operational_score(
                sla_status, persistent, recurring, asset_crit, is_kev_val, internet_facing
            )
            
            # Matching de risk acceptance para ajustar score cumulativo do ativo
            m_rule, a_status, exp = find_matching_acceptance_rule(
                r.cve, r.agent_id, r.agent_name, r.package_name, r.severity, asset_ctx, expo_ctx, valid_rules
            )
            rec_score = score_rec + asset_score + expo_score + sla_op_score
            if a_status == "accepted":
                rec_score -= 30.0
            elif a_status == "compensating_control":
                rec_score -= 15.0
            elif a_status == "expired" or exp:
                rec_score += 10.0
            rec_score = max(0.0, min(100.0, rec_score))
            agent_risk_scores[r.agent_id] += rec_score
            
        top_risky_assets = []
        for aid, score_sum in agent_risk_scores.items():
            ctx_info = get_asset_context(assets_data, aid, unique_agents_seen[aid])
            top_risky_assets.append({
                "agent_id": aid,
                "agent_name": unique_agents_seen[aid],
                "criticality": ctx_info.get("criticality", "unknown"),
                "environment": ctx_info.get("environment", "unknown"),
                "exposure": ctx_info.get("exposure", "unknown"),
                "asset_type": ctx_info.get("asset_type", "unknown"),
                "risk_score": int(score_sum),
                "vuln_count": agent_vuln_counts[aid]
            })
            
        top_risky_assets.sort(key=lambda x: -x["risk_score"])
        
        # 4. Gerar Alertas Passivos e Detecção de Inconsistências
        alerts = []
        total_vulns = len(current_snapshot["agent_vulnerabilities"])
        critical_count = sum(1 for v in current_snapshot["agent_vulnerabilities"] if str(v.get("severity")).lower() == "critical")
        high_count = sum(1 for v in current_snapshot["agent_vulnerabilities"] if str(v.get("severity")).lower() == "high")
        medium_count = sum(1 for v in current_snapshot["agent_vulnerabilities"] if str(v.get("severity")).lower() == "medium")
        low_count = total_vulns - critical_count - high_count - medium_count
        kev_count = sum(1 for v in current_snapshot["agent_vulnerabilities"] if v.get("is_kev"))
        epss_high_count = sum(1 for v in current_snapshot["agent_vulnerabilities"] if v.get("epss_score") is not None and v.get("epss_score") >= 0.20)
        affected_agents_set = set(v["agent_id"] for v in current_snapshot["agent_vulnerabilities"])
        
        # Alertas de Ativos sem classificação (Fase 3B)
        if unclassified_count > 0:
            alerts.append({
                "level": "warning",
                "title": "Ativos sem classificação",
                "message": f"Existem {unclassified_count} ativo(s) com vulnerabilidades, mas sem criticidade definida no assets_context.json."
            })
            
        if kev_count > 0:
            alerts.append({
                "level": "critical",
                "title": "KEV Ativo Detectado",
                "message": f"Existem {kev_count} vulnerabilidade(s) ativas do catálogo CISA KEV."
            })
        if delta_info["new_critical"] > 0:
            alerts.append({
                "level": "critical",
                "title": "Nova CVE Crítica",
                "message": f"Foi identificada {delta_info['new_critical']} nova(s) vulnerabilidade(s) crítica(s) desde o último relatório."
            })
            
        if epss_high_count > 0:
            alerts.append({
                "level": "warning",
                "title": "Alto EPSS",
                "message": f"Existem {epss_high_count} vulnerabilidade(s) com probabilidade de exploração EPSS >= 20%."
            })
        if critical_count > 0:
            alerts.append({
                "level": "warning",
                "title": "Vulnerabilidades Críticas",
                "message": f"Existem {critical_count} vulnerabilidades críticas ativas."
            })
        if delta_info["new_vulnerabilities"] > delta_info["resolved_vulnerabilities"]:
            alerts.append({
                "level": "warning",
                "title": "Aumento no Total de Vulns",
                "message": f"O total de vulnerabilidades aumentou em {delta_info['new_vulnerabilities'] - delta_info['resolved_vulnerabilities']} desde a última análise."
            })
        if not baseline_available:
            alerts.append({
                "level": "warning",
                "title": "Sem Baseline de Histórico",
                "message": "Não foi encontrado snapshot anterior para cálculo de delta comparativo."
            })
            
        for (cve, package_name), group_records in vuln_groups.items():
            uniq_aids = set(r.agent_id for r in group_records if r.agent_id)
            if len(uniq_aids) >= 5:
                alerts.append({
                    "level": "warning",
                    "title": "CVE Amplamente Disseminada",
                    "message": f"A vulnerabilidade {cve} ({package_name}) afeta {len(uniq_aids)} agentes simultaneamente."
                })
                break
                
        if baseline_available and delta_info["new_vulnerabilities"] == 0:
            alerts.append({
                "level": "info",
                "title": "Estabilidade do Ambiente",
                "message": "Nenhuma nova vulnerabilidade foi detectada em relação à execução anterior."
            })
        if kev_count == 0:
            alerts.append({
                "level": "info",
                "title": "Livre de KEV",
                "message": "Nenhuma vulnerabilidade com exploração ativa conhecida (CISA KEV) está presente."
            })

        # --- Cálculos do Contexto de Exposição (Fase 3C) ---
        with_exposure_context = 0
        internet_facing_count = 0
        dmz_count = 0
        internal_count = 0
        unknown_exposure_count = 0
        
        total_declared_services = 0
        critical_services_count = 0
        internet_exposed_services_count = 0
        internal_sensitive_services_count = 0
        
        exposure_alerts = []
        assets_missing_exposure_context = []
        top_exposed_assets = []

        for aid, aname in unique_agents_seen.items():
            asset_ctx = get_asset_context(assets_data, aid, aname)
            expo_ctx = get_exposure_context(exposure_data, aid, aname)
            
            # Verificar presença na seção de agentes do exposure_context.json
            has_entry = False
            if exposure_data and "agents" in exposure_data:
                agents_map = exposure_data.get("agents", {})
                if aid in agents_map or aname in agents_map:
                    has_entry = True
                else:
                    aid_lower = aid.lower()
                    aname_lower = aname.lower()
                    for key, val in agents_map.items():
                        key_lower = key.lower()
                        asset_name_lower = str(val.get("asset_name", "")).lower()
                        if key_lower == aid_lower or key_lower == aname_lower or asset_name_lower == aname_lower:
                            has_entry = True
                            break
                            
            if has_entry:
                with_exposure_context += 1
            else:
                assets_missing_exposure_context.append({
                    "agent_id": aid,
                    "agent_name": aname
                })
                
            expo_level = expo_ctx.get("exposure_level", "unknown")
            if expo_level == "internet":
                internet_facing_count += 1
            elif expo_level == "dmz":
                dmz_count += 1
            elif expo_level == "internal":
                internal_count += 1
            elif expo_level == "unknown":
                unknown_exposure_count += 1
                
            # Serviços abertos
            open_services = expo_ctx.get("open_services", [])
            total_declared_services += len(open_services)
            for svc in open_services:
                if svc.get("critical", False):
                    critical_services_count += 1
                svc_expo = svc.get("exposure", "").lower()
                if not svc_expo:
                    svc_expo = "internet" if expo_ctx.get("internet_facing", False) or expo_level in ["internet", "dmz"] else "internal"
                if svc_expo == "internet":
                    internet_exposed_services_count += 1
                elif svc_expo == "internal" and svc.get("critical", False):
                    internal_sensitive_services_count += 1
                    
            # Pontuação de exposição
            _, _, expo_score, _, _ = calculate_agent_risk_modifiers(aid, aname, assets_data, exposure_data)
            
            top_exposed_assets.append({
                "agent_id": aid,
                "agent_name": aname,
                "exposure_level": expo_level,
                "network_zone": expo_ctx.get("network_zone", "unknown"),
                "internet_facing": bool(expo_ctx.get("internet_facing", False)),
                "dmz": bool(expo_ctx.get("dmz", False)),
                "exposure_score": int(expo_score)
            })
            
            # --- DETECÇÃO DE INCONSISTÊNCIAS (Cinco Casos da Fase 3C) ---
            # 1. asset_context exposure = internal + exposure_context internet_facing = true
            asset_expo = asset_ctx.get("exposure", "unknown")
            if asset_expo == "internal" and expo_ctx.get("internet_facing", False):
                exposure_alerts.append({
                    "level": "warning",
                    "title": "Inconsistência de Exposição",
                    "message": f"Ativo {aid} ({aname}) classificado como interno em assets_context.json, mas marcado como internet-facing em exposure_context.json."
                })
                
            # 2. asset_context criticality = critical/high + exposure_context exposure_level = unknown
            asset_crit = asset_ctx.get("criticality", "unknown")
            if asset_crit in ["critical", "high"] and expo_level == "unknown":
                exposure_alerts.append({
                    "level": "warning",
                    "title": "Exposição Desconhecida em Ativo Crítico",
                    "message": f"Ativo crítico/alto {aid} ({aname}) sem contexto de exposição definido (exposure_level = unknown)."
                })
                
            # 4. ativo vulnerável não existe em exposure_context.json
            if not has_entry:
                exposure_alerts.append({
                    "level": "warning",
                    "title": "Ativo sem Contexto de Exposição",
                    "message": f"Ativo vulnerável {aid} ({aname}) não possui registro em exposure_context.json."
                })
                
            # 5. ativo de infraestrutura crítica com exposição internet/dmz
            asset_type = asset_ctx.get("asset_type", "unknown")
            critical_types = ["siem", "qradar", "wazuh", "cyberark", "domain_controller", "database"]
            if asset_type in critical_types:
                is_exposed = (expo_level in ["internet", "dmz"] or 
                              asset_expo in ["internet", "dmz"] or 
                              bool(expo_ctx.get("internet_facing", False)) or 
                              bool(expo_ctx.get("dmz", False)))
                if is_exposed:
                    exposure_alerts.append({
                        "level": "critical",
                        "title": "Infraestrutura Crítica Exposta",
                        "message": f"Serviço crítico de infraestrutura {aid} ({aname}) do tipo {asset_type} está exposto (nível: {expo_level}, internet_facing: {expo_ctx.get('internet_facing')})."
                    })

        # 3. ativos externos sem agente em external_assets
        external_assets_list = exposure_data.get("external_assets", [])
        total_external_assets = len(external_assets_list)
        external_without_agent = 0
        
        for ext in external_assets_list:
            has_agent = ext.get("has_wazuh_agent", True)
            if not has_agent:
                external_without_agent += 1
                asset_name = ext.get("asset_name", "desconhecido")
                hostname = ext.get("hostname", "desconhecido")
                exposure_alerts.append({
                    "level": "info",
                    "title": "Ativo Externo sem Agente",
                    "message": f"Ativo externo autorizado {asset_name} ({hostname}) sem agente Wazuh instalado."
                })

        # Ordenar ativos expostos por pontuação de exposição
        top_exposed_assets.sort(key=lambda x: -x["exposure_score"])

        # Incorporar os alertas de exposição nos alertas do sumário de risco
        alerts.extend(exposure_alerts)
            
        risk_summary_path = web_path / "data" / "risk_summary.json"
        risk_delta_path = web_path / "data" / "risk_delta.json"
        asset_context_summary_path = web_path / "data" / "asset_context_summary.json"
        exposure_context_summary_path = web_path / "data" / "exposure_context_summary.json"
        sla_summary_path = web_path / "data" / "sla_summary.json"
        
        # Encontrar qual arquivo de contexto de ativos foi realmente utilizado
        actual_source = "none"
        for p in [ASSETS_CONTEXT_PATH_PREF, ASSETS_CONTEXT_PATH_FALLBACK]:
            if p.exists() and p.is_file():
                actual_source = str(p)
                break

        # Encontrar qual arquivo de contexto de exposição foi realmente utilizado
        actual_exposure_source = "none"
        for p in [EXPOSURE_CONTEXT_PATH_PREF, EXPOSURE_CONTEXT_PATH_FALLBACK]:
            if p.exists() and p.is_file():
                actual_exposure_source = str(p)
                break
        exposure_status = "ok" if actual_exposure_source != "none" else "degraded"
        
        # Encontrar qual arquivo de política de SLA foi realmente utilizado
        actual_sla_source = "none"
        for p in [SLA_POLICY_PATH_PREF, SLA_POLICY_PATH_FALLBACK]:
            if p.exists() and p.is_file():
                actual_sla_source = str(p)
                break
        sla_policy_status = "ok" if actual_sla_source != "none" else "degraded"
                
        # Gerar o asset_context_summary
        asset_context_summary = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "ok" if actual_source != "none" else "degraded",
            "source": actual_source,
            "assets": {
                "total_seen": total_seen,
                "classified": classified_count,
                "unclassified": unclassified_count,
                "critical": crit_counts["critical"],
                "high": crit_counts["high"],
                "medium": crit_counts["medium"],
                "low": crit_counts["low"],
                "unknown": crit_counts["unknown"]
            },
            "exposure": {
                "internet": expo_counts["internet"],
                "dmz": expo_counts["dmz"],
                "internal": expo_counts["internal"],
                "isolated": expo_counts["isolated"],
                "unknown": expo_counts["unknown"]
            },
            "top_risky_assets": top_risky_assets[:10],
            "unclassified_assets": unclassified_assets
        }

        # Gerar o exposure_context_summary
        exposure_context_summary = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": exposure_status,
            "source": actual_exposure_source,
            "assets": {
                "total_seen": total_seen,
                "with_exposure_context": with_exposure_context,
                "without_exposure_context": len(assets_missing_exposure_context),
                "internet_facing": internet_facing_count,
                "dmz": dmz_count,
                "internal": internal_count,
                "unknown": unknown_exposure_count
            },
            "services": {
                "total_declared": total_declared_services,
                "critical_services": critical_services_count,
                "internet_exposed_services": internet_exposed_services_count,
                "internal_sensitive_services": internal_sensitive_services_count
            },
            "external_assets": {
                "total": total_external_assets,
                "without_wazuh_agent": external_without_agent
            },
            "external_assets_list": external_assets_list,
            "top_exposed_assets": top_exposed_assets[:10],
            "assets_missing_exposure_context": assets_missing_exposure_context,
            "exposure_alerts": exposure_alerts
        }

        # Calcular estatísticas agregadas de exposição para os afetados
        internet_facing_affected = 0
        dmz_affected = 0
        unknown_exposure_affected = 0
        critical_exposed_svcs_affected = 0
        
        for aid, aname in unique_agents_seen.items():
            expo_ctx = get_exposure_context(exposure_data, aid, aname)
            expo_level = expo_ctx.get("exposure_level", "unknown")
            if expo_level == "internet" or expo_ctx.get("internet_facing", False):
                internet_facing_affected += 1
            elif expo_level == "dmz" or expo_ctx.get("dmz", False):
                dmz_affected += 1
            elif expo_level == "unknown":
                unknown_exposure_affected += 1
                
            for svc in expo_ctx.get("open_services", []):
                if svc.get("critical", False):
                    svc_expo = svc.get("exposure", "").lower()
                    if not svc_expo:
                        svc_expo = "internet" if expo_ctx.get("internet_facing", False) or expo_level in ["internet", "dmz"] else "internal"
                    if svc_expo == "internet":
                        critical_exposed_svcs_affected += 1
                        
        # Calcular estatísticas da gestão de SLA (Fase 3D)
        total_open = len(current_snapshot["agent_vulnerabilities"])
        overdue_count = 0
        due_soon_count = 0
        within_sla_count = 0
        unknown_sla_count = 0
        persistent_count = 0
        recurring_count = 0
        age_days_list = []
        oldest_first_seen = None

        by_severity = {
            "critical": {"total": 0, "overdue": 0, "due_soon": 0, "within_sla": 0},
            "high": {"total": 0, "overdue": 0, "due_soon": 0, "within_sla": 0},
            "medium": {"total": 0, "overdue": 0, "due_soon": 0, "within_sla": 0},
            "low": {"total": 0, "overdue": 0, "due_soon": 0, "within_sla": 0}
        }

        by_owner_map = defaultdict(lambda: {"total": 0, "overdue": 0, "due_soon": 0, "within_sla": 0})
        by_asset_map = defaultdict(lambda: {"total": 0, "overdue": 0, "due_soon": 0, "within_sla": 0, "agent_name": ""})
        by_owner_actionable_overdue = defaultdict(int)
        by_asset_actionable_overdue = defaultdict(int)

        for v in current_snapshot["agent_vulnerabilities"]:
            sev = str(v["severity"]).lower().strip()
            if sev not in by_severity:
                sev = "medium"
            status = v["sla_status"]
            
            ra = v.get("risk_acceptance", {})
            ra_status = ra.get("status", "none")
            ra_expired = ra.get("expired", False)
            is_valid_except = (ra_status in ["accepted", "false_positive", "out_of_scope", "duplicate"]) and not ra_expired
            
            if status == "overdue":
                overdue_count += 1
                by_severity[sev]["overdue"] += 1
            elif status == "due_soon":
                due_soon_count += 1
                by_severity[sev]["due_soon"] += 1
            elif status == "within_sla":
                within_sla_count += 1
                by_severity[sev]["within_sla"] += 1
            else:
                unknown_sla_count += 1
            by_severity[sev]["total"] += 1
            
            if v["persistent"]:
                persistent_count += 1
            if v["recurring"]:
                recurring_count += 1
            age_days_list.append(v["age_days"])
            
            f_seen = v["first_seen"]
            if oldest_first_seen is None or f_seen < oldest_first_seen:
                oldest_first_seen = f_seen
                
            v_agent_id = v["agent_id"]
            v_agent_name = v["agent_name"]
            v_asset_ctx = get_asset_context(assets_data, v_agent_id, v_agent_name)
            t_owner = v_asset_ctx.get("technical_owner", "unknown")
            if not t_owner:
                t_owner = "unknown"
            by_owner_map[t_owner]["total"] += 1
            if status == "overdue":
                by_owner_map[t_owner]["overdue"] += 1
                if not is_valid_except:
                    by_owner_actionable_overdue[t_owner] += 1
            elif status == "due_soon":
                by_owner_map[t_owner]["due_soon"] += 1
            elif status == "within_sla":
                by_owner_map[t_owner]["within_sla"] += 1

            by_asset_map[v_agent_id]["total"] += 1
            by_asset_map[v_agent_id]["agent_name"] = v_agent_name
            if status == "overdue":
                by_asset_map[v_agent_id]["overdue"] += 1
                if not is_valid_except:
                    by_asset_actionable_overdue[v_agent_id] += 1
            elif status == "due_soon":
                by_asset_map[v_agent_id]["due_soon"] += 1
            elif status == "within_sla":
                by_asset_map[v_agent_id]["within_sla"] += 1

        avg_age = 0.0
        med_age = 0.0
        max_age = 0
        if age_days_list:
            avg_age = sum(age_days_list) / len(age_days_list)
            max_age = max(age_days_list)
            sorted_ages = sorted(age_days_list)
            n = len(sorted_ages)
            if n % 2 == 1:
                med_age = sorted_ages[n // 2]
            else:
                med_age = (sorted_ages[n // 2 - 1] + sorted_ages[n // 2]) / 2.0

        by_owner_list = []
        for own, stats in by_owner_map.items():
            by_owner_list.append({
                "technical_owner": own,
                "total": stats["total"],
                "overdue": stats["overdue"],
                "due_soon": stats["due_soon"],
                "within_sla": stats["within_sla"]
            })
            
        by_asset_list = []
        for aid, stats in by_asset_map.items():
            by_asset_list.append({
                "agent_id": aid,
                "agent_name": stats["agent_name"],
                "total": stats["total"],
                "overdue": stats["overdue"],
                "due_soon": stats["due_soon"],
                "within_sla": stats["within_sla"]
            })

        overdue_vulns = [v for v in current_snapshot["agent_vulnerabilities"] if v["sla_status"] == "overdue"]
        overdue_vulns.sort(key=lambda x: x["days_to_due"])
        top_overdue = []
        for v in overdue_vulns[:10]:
            top_overdue.append({
                "agent_id": v["agent_id"],
                "agent_name": v["agent_name"],
                "cve": v["cve"],
                "package_name": v["package_name"],
                "severity": v["severity"],
                "days_overdue": abs(v["days_to_due"]),
                "due_date": v["due_date"],
                "risk_acceptance": v.get("risk_acceptance", {"status": "none", "expired": False})
            })

        due_soon_vulns = [v for v in current_snapshot["agent_vulnerabilities"] if v["sla_status"] == "due_soon"]
        due_soon_vulns.sort(key=lambda x: x["days_to_due"])
        top_due_soon = []
        for v in due_soon_vulns[:10]:
            top_due_soon.append({
                "agent_id": v["agent_id"],
                "agent_name": v["agent_name"],
                "cve": v["cve"],
                "package_name": v["package_name"],
                "severity": v["severity"],
                "days_to_due": v["days_to_due"],
                "due_date": v["due_date"],
                "risk_acceptance": v.get("risk_acceptance", {"status": "none", "expired": False})
            })

        persistent_vulns = [v for v in current_snapshot["agent_vulnerabilities"] if v["persistent"]]
        persistent_vulns.sort(key=lambda x: -x["age_days"])
        top_persistent = []
        for v in persistent_vulns[:10]:
            top_persistent.append({
                "agent_id": v["agent_id"],
                "agent_name": v["agent_name"],
                "cve": v["cve"],
                "package_name": v["package_name"],
                "severity": v["severity"],
                "age_days": v["age_days"]
            })

        recurring_vulns = [v for v in current_snapshot["agent_vulnerabilities"] if v["recurring"]]
        recurring_vulns.sort(key=lambda x: -x["snapshot_occurrences"])
        top_recurring = []
        for v in recurring_vulns[:10]:
            top_recurring.append({
                "agent_id": v["agent_id"],
                "agent_name": v["agent_name"],
                "cve": v["cve"],
                "package_name": v["package_name"],
                "severity": v["severity"],
                "snapshot_occurrences": v["snapshot_occurrences"]
            })

        top_backlog_assets = sorted(by_asset_list, key=lambda x: -x["total"])[:10]
        top_backlog_owners = sorted(by_owner_list, key=lambda x: -x["total"])[:10]

        # --- GERAR ALERTAS DE SLA (Fase 3D) ---
        sla_alerts = []
        assets_without_owner = []
        for aid, aname in unique_agents_seen.items():
            actx = get_asset_context(assets_data, aid, aname)
            t_owner = actx.get("technical_owner", "unknown")
            if t_owner == "unknown" or not t_owner:
                assets_without_owner.append(aname)
        if assets_without_owner:
            sla_alerts.append({
                "level": "warning",
                "title": "Ativo vulnerável sem owner técnico",
                "message": f"Os seguintes ativos possuem vulnerabilidades ativas mas não têm dono técnico classificado: {', '.join(assets_without_owner[:3])}."
            })

        critical_assets_overdue = []
        for aid, aname in unique_agents_seen.items():
            actx = get_asset_context(assets_data, aid, aname)
            crit = actx.get("criticality", "unknown")
            if crit in ["critical", "high"]:
                has_actionable_overdue = by_asset_actionable_overdue[aid] > 0
                if has_actionable_overdue:
                    critical_assets_overdue.append(aname)
        if critical_assets_overdue:
            sla_alerts.append({
                "level": "critical",
                "title": "Ativo crítico com SLA vencido",
                "message": f"Os seguintes ativos críticos/altos possuem vulnerabilidades acionáveis com SLA de tratativa estourado: {', '.join(critical_assets_overdue[:3])}."
            })

        owners_critical_backlog = []
        for own, stats in by_owner_map.items():
            if own == "unknown":
                continue
            if by_owner_actionable_overdue[own] >= 3:
                owners_critical_backlog.append(own)
        if owners_critical_backlog:
            sla_alerts.append({
                "level": "warning",
                "title": "Owner com backlog crítico elevado",
                "message": f"Os seguintes donos técnicos acumulam alto backlog de vulnerabilidades acionáveis vencidas (>= 3): {', '.join(owners_critical_backlog[:3])}."
            })

        # Alerta específico Fase 3E: SLA vencido + acceptance expired
        expired_accepted_overdue = []
        for v in current_snapshot["agent_vulnerabilities"]:
            ra = v.get("risk_acceptance", {})
            if v["sla_status"] == "overdue" and ra.get("status") == "accepted" and ra.get("expired"):
                expired_accepted_overdue.append(f"{v['agent_name']} ({v['cve']})")
        if expired_accepted_overdue:
            sla_alerts.append({
                "level": "critical",
                "title": "Pendência crítica de revisão: Exceção de SLA vencida",
                "message": f"Os seguintes itens possuem SLA vencido e a exceção de risco (aceite) expirou: {', '.join(expired_accepted_overdue[:3])}."
            })

        # Adicionar alertas de SLA aos alertas gerais
        alerts.extend(sla_alerts)

        # --- CÁLCULOS FASE 3E (Risk Acceptance & Exceções) ---
        accepted_risks_count = 0
        false_positive_risks_count = 0
        expired_acceptances_count = 0
        planned_remediations_count = 0
        compensating_controls_count = 0
        actionable_priorities_count = 0
        accepted_expired_count = 0
        
        waiting_change_window_count = 0
        out_of_scope_count = 0
        duplicate_count = 0
        under_review_count = 0
        
        by_status_map = defaultdict(int)
        by_owner_map_ra = defaultdict(int)
        by_approver_map_ra = defaultdict(int)
        expiring_soon_items = []
        expired_items = []
        matched_items_sample = []
        acceptance_alerts = list(validation_alerts)
        
        for v in current_snapshot["agent_vulnerabilities"]:
            ra = v.get("risk_acceptance", {})
            status = ra.get("status", "none")
            exp = ra.get("expired", False)
            
            if status == "none":
                continue
                
            rule_id = ra.get("rule_id")
            owner = ra.get("owner", "unknown") or "unknown"
            approver = ra.get("approved_by", "unknown") or "unknown"
            
            by_status_map[status] += 1
            by_owner_map_ra[owner] += 1
            by_approver_map_ra[approver] += 1
            
            matched_items_sample.append({
                "cve": v["cve"],
                "agent_id": v["agent_id"],
                "agent_name": v["agent_name"],
                "package_name": v["package_name"],
                "severity": v["severity"],
                "status": status,
                "rule_id": rule_id,
                "approved_by": approver,
                "valid_until": ra.get("valid_until"),
                "days_to_expiration": ra.get("days_to_expiration"),
                "reason": ra.get("reason"),
                "business_justification": ra.get("business_justification"),
                "compensating_controls": ra.get("compensating_controls"),
                "ticket": ra.get("ticket"),
                "owner": owner
            })
            
            if status == "accepted" and not exp:
                accepted_risks_count += 1
            elif status == "false_positive" and not exp:
                false_positive_risks_count += 1
            elif status == "planned_remediation" and not exp:
                planned_remediations_count += 1
            elif status == "compensating_control" and not exp:
                compensating_controls_count += 1
            elif status == "waiting_change_window" and not exp:
                waiting_change_window_count += 1
            elif status == "out_of_scope" and not exp:
                out_of_scope_count += 1
            elif status == "duplicate" and not exp:
                duplicate_count += 1
            elif status == "under_review" and not exp:
                under_review_count += 1
                
            if status == "accepted" and exp:
                accepted_expired_count += 1
                
            if exp or status == "expired":
                expired_acceptances_count += 1
                expired_items.append({
                    "cve": v["cve"],
                    "agent_id": v["agent_id"],
                    "agent_name": v["agent_name"],
                    "rule_id": rule_id,
                    "valid_until": ra.get("valid_until"),
                    "days_overdue": abs(ra.get("days_to_expiration", 0)) if ra.get("days_to_expiration") is not None else 0
                })
                # Alerta de expiração vencida
                acceptance_alerts.append({
                    "level": "warning",
                    "title": "Exceção Vencida",
                    "message": f"A exceção '{rule_id}' para {v['cve']} no ativo {v['agent_id']} ({v['agent_name']}) venceu em {ra.get('valid_until')}."
                })
                if v["is_kev"] or str(v["severity"]).lower() == "critical":
                    acceptance_alerts.append({
                        "level": "critical",
                        "title": "Exceção Crítica Vencida",
                        "message": f"A vulnerabilidade crítica/KEV {v['cve']} está com exceção '{rule_id}' VENCIDA no ativo {v['agent_id']} ({v['agent_name']})."
                    })
            else:
                days_left = ra.get("days_to_expiration")
                if days_left is not None and 0 <= days_left <= 30:
                    expiring_soon_items.append({
                        "cve": v["cve"],
                        "agent_id": v["agent_id"],
                        "agent_name": v["agent_name"],
                        "rule_id": rule_id,
                        "valid_until": ra.get("valid_until"),
                        "days_to_expiration": days_left
                    })
                    
                # Alerta se KEV/Critical aceito sob regra válida
                if (v["is_kev"] or str(v["severity"]).lower() == "critical") and status == "accepted":
                    acceptance_alerts.append({
                        "level": "warning",
                        "title": "Aviso: Risco Crítico Aceito",
                        "message": f"A vulnerabilidade crítica/KEV {v['cve']} foi aceita (regra '{rule_id}') no ativo {v['agent_id']} ({v['agent_name']})."
                    })
                    
        # Calcular total de vulnerabilidades acionáveis (não accepted/FP/out_of_scope/duplicate válidos)
        for v in current_snapshot["agent_vulnerabilities"]:
            ra = v.get("risk_acceptance", {})
            status = ra.get("status", "none")
            exp = ra.get("expired", False)
            is_valid_except = (status in ["accepted", "false_positive", "out_of_scope", "duplicate"]) and not exp
            if not is_valid_except:
                actionable_priorities_count += 1

        # Converte maps para lists
        by_status_list = [{"status": k, "count": v} for k, v in by_status_map.items()]
        by_owner_list_ra = [{"owner": k, "count": v} for k, v in by_owner_map_ra.items()]
        by_approver_list_ra = [{"approved_by": k, "count": v} for k, v in by_approver_map_ra.items()]

        # Incorporar alertas
        alerts.extend(acceptance_alerts)

        # Gerar o risk_acceptance_summary
        actual_acceptance_source = "none"
        for p in [RISK_ACCEPTANCE_PATH_PREF, RISK_ACCEPTANCE_PATH_FALLBACK]:
            if p.exists() and p.is_file():
                actual_acceptance_source = str(p)
                break
                
        risk_acceptance_summary = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "ok" if actual_acceptance_source != "none" else "degraded",
            "source": actual_acceptance_source,
            "summary": {
                "rules_total": len(risk_acceptance_data.get("rules", [])),
                "rules_enabled": len(valid_rules),
                "rules_invalid": len(invalid_rules),
                "matched_vulnerabilities": len(matched_items_sample),
                "accepted": accepted_risks_count,
                "false_positive": false_positive_risks_count,
                "planned_remediation": planned_remediations_count,
                "compensating_control": compensating_controls_count,
                "waiting_change_window": waiting_change_window_count,
                "out_of_scope": out_of_scope_count,
                "duplicate": duplicate_count,
                "under_review": under_review_count,
                "expired": expired_acceptances_count,
                "actionable_after_acceptance": actionable_priorities_count
            },
            "by_status": by_status_list,
            "by_owner": by_owner_list_ra,
            "by_approver": by_approver_list_ra,
            "expiring_soon": expiring_soon_items,
            "expired_acceptances": expired_items,
            "invalid_rules": invalid_rules,
            "matched_items_sample": matched_items_sample[:30],
            "acceptance_alerts": acceptance_alerts
        }

        # Gerar o sla_summary
        sla_summary = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": sla_policy_status,
            "source": actual_sla_source,
            "summary": {
                "total_open": total_open,
                "overdue": overdue_count,
                "due_soon": due_soon_count,
                "within_sla": within_sla_count,
                "unknown": unknown_sla_count,
                "average_age_days": round(avg_age, 2),
                "median_age_days": med_age,
                "max_age_days": max_age,
                "persistent_vulnerabilities": persistent_count,
                "recurring_vulnerabilities": recurring_count,
                "oldest_first_seen": oldest_first_seen
            },
            "by_severity": by_severity,
            "by_owner": by_owner_list,
            "by_asset": by_asset_list,
            "top_overdue": top_overdue,
            "top_due_soon": top_due_soon,
            "top_persistent_cves": top_persistent,
            "top_recurring_cves": top_recurring,
            "top_backlog_assets": top_backlog_assets,
            "top_backlog_owners": top_backlog_owners,
            "sla_alerts": sla_alerts,
            # Enriquecimentos da Fase 3E
            "risk_acceptance": {
                "accepted": accepted_risks_count,
                "false_positive": false_positive_risks_count,
                "expired": expired_acceptances_count,
                "actionable": actionable_priorities_count
            },
            "risk_acceptance_counts": {
                "accepted_within_validity": accepted_risks_count,
                "accepted_expired": accepted_expired_count,
                "false_positive": false_positive_risks_count,
                "planned_remediation": planned_remediations_count,
                "waiting_change_window": waiting_change_window_count,
                "out_of_scope": out_of_scope_count,
                "duplicate": duplicate_count,
                "under_review": under_review_count
            }
        }
        
        # Gerar tendência executiva (Fase 3F)
        trend_enrichment = generate_trend_summary(web_dir, web_group)

        # Gerar o risk_summary enriquecido
        risk_summary = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "ok",
            "source": str(risk_summary_path),
            "summary": {
                "total_vulnerabilities": total_vulns,
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "kev_count": kev_count,
                "epss_high_count": epss_high_count,
                "affected_agents": len(affected_agents_set),
                "packages_affected": len(vuln_groups),
                "report_age_minutes": 0,
                # Campos Fase 3B
                "critical_assets_affected": crit_counts["critical"],
                "high_assets_affected": crit_counts["high"],
                "internet_exposed_assets_affected": expo_counts["internet"],
                "dmz_assets_affected": expo_counts["dmz"],
                "unclassified_assets_affected": unclassified_count,
                "asset_context_enabled": True,
                # Novos campos Fase 3C
                "exposure_context_enabled": True,
                "internet_facing_assets_affected": internet_facing_affected,
                "dmz_assets_affected": dmz_affected,
                "unknown_exposure_assets_affected": unknown_exposure_affected,
                "critical_exposed_services": critical_exposed_svcs_affected,
                "external_assets_without_agent": external_without_agent,
                # Novos campos Fase 3D
                "sla_enabled": True,
                "sla_overdue": overdue_count,
                "sla_due_soon": due_soon_count,
                "sla_within": within_sla_count,
                "sla_unknown": unknown_sla_count,
                "average_age_days": round(avg_age, 2),
                "max_age_days": max_age,
                "persistent_vulnerabilities": persistent_count,
                "recurring_vulnerabilities": recurring_count,
                # Novos campos Fase 3E
                "risk_acceptance_enabled": True,
                "accepted_risks": accepted_risks_count,
                "false_positive_risks": false_positive_risks_count,
                "expired_acceptances": expired_acceptances_count,
                "planned_remediations": planned_remediations_count,
                "compensating_controls": compensating_controls_count,
                "actionable_priorities": actionable_priorities_count
            },
            "top_priorities": top_priorities,
            "top_actionable_priorities": top_actionable_priorities,
            "top_priorities_excluding_accepted": top_priorities_excluding_accepted,
            "accepted_items": accepted_items,
            "false_positive_items": false_positive_items,
            "expired_acceptances": expired_acceptances_list,
            "alerts": alerts
        }
        
        if trend_enrichment:
            risk_summary.update(trend_enrichment)
        else:
            risk_summary.update({
                "trend_enabled": True,
                "trend_status": "limited_history",
                "risk_direction": "unknown",
                "executive_health": "unknown",
                "snapshots_analyzed": 1,
                "delta_total_vulnerabilities": 0,
                "delta_critical": 0,
                "delta_high": 0,
                "delta_kev": 0,
                "delta_sla_overdue": 0,
                "delta_actionable_priorities": 0
            })

        # Gerar plano de tratativa operacional (Fase 3G)
        treatment_enrichment = generate_treatment_plan(web_dir, web_group)
        if treatment_enrichment:
            risk_summary.update(treatment_enrichment)
        else:
            risk_summary.update({
                "treatment_plan_enabled": True,
                "treatment_now": 0,
                "treatment_next_7_days": 0,
                "treatment_next_15_days": 0,
                "treatment_next_30_days": 0,
                "treatment_monitor": 0,
                "treatment_owners": 0,
                "quick_wins_count": 0,
                "change_window_candidates_count": 0
            })
        
        # Escrever arquivos atomicamente
        _atomic_write(json.dumps(risk_summary, indent=2, ensure_ascii=False), risk_summary_path, web_group)
        _atomic_write(json.dumps(risk_delta, indent=2, ensure_ascii=False), risk_delta_path, web_group)
        _atomic_write(json.dumps(asset_context_summary, indent=2, ensure_ascii=False), asset_context_summary_path, web_group)
        _atomic_write(json.dumps(exposure_context_summary, indent=2, ensure_ascii=False), exposure_context_summary_path, web_group)
        _atomic_write(json.dumps(sla_summary, indent=2, ensure_ascii=False), sla_summary_path, web_group)
        risk_acceptance_summary_path = web_path / "data" / "risk_acceptance_summary.json"
        _atomic_write(json.dumps(risk_acceptance_summary, indent=2, ensure_ascii=False), risk_acceptance_summary_path, web_group)
        
        # Reter snapshots
        all_snapshots = sorted(snapshots_dir.glob("snapshot_*.json"), key=lambda x: x.stat().st_mtime)
        if len(all_snapshots) > 30:
            to_remove = all_snapshots[:-30]
            for f in to_remove:
                try:
                    f.unlink()
                    logger.info(f"Retenção de snapshots: removido arquivo antigo {f.name}")
                except Exception as e:
                    logger.warning(f"Falha ao remover snapshot antigo {f.name}: {e}")
                    
    except Exception as e:
        logger.error(f"[ERRO] Falha ao gerar inteligência de risco (Fase 3D): {e}", exc_info=True)

def generate_trend_summary(web_dir: str, web_group: Optional[str] = None) -> Optional[dict]:
    """
    Fase 3F: Lê os snapshots históricos sob /var/www/wazuh-soar/data/snapshots/,
    calcula as evoluções temporárias e gera o trend_summary.json.
    Retorna dicionário de enriquecimento para o risk_summary.json.
    """
    try:
        web_path = Path(web_dir)
        snapshots_dir = web_path / "data" / "snapshots"
        trend_summary_path = web_path / "data" / "trend_summary.json"
        
        if not snapshots_dir.exists():
            degraded_summary = {
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "status": "degraded",
                "message": "Snapshots directory does not exist",
                "summary": {
                    "snapshots_analyzed": 0,
                    "trend_status": "unknown",
                    "risk_direction": "unknown",
                    "executive_health": "unknown"
                }
            }
            _atomic_write(json.dumps(degraded_summary, indent=2, ensure_ascii=False), trend_summary_path, web_group)
            return None

        # Lista de snapshots ordenados cronologicamente pelo nome do arquivo
        snapshot_files = sorted(snapshots_dir.glob("snapshot_*.json"), key=lambda x: x.name)
        
        if not snapshot_files:
            degraded_summary = {
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "status": "degraded",
                "message": "No snapshots found in directory",
                "summary": {
                    "snapshots_analyzed": 0,
                    "trend_status": "unknown",
                    "risk_direction": "unknown",
                    "executive_health": "unknown"
                }
            }
            _atomic_write(json.dumps(degraded_summary, indent=2, ensure_ascii=False), trend_summary_path, web_group)
            return None

        snapshots_analyzed = len(snapshot_files)
        
        # Classificação de status de tendência
        if snapshots_analyzed == 1:
            trend_status = "limited_history"
        elif snapshots_analyzed == 2:
            trend_status = "comparison"
        elif snapshots_analyzed >= 7:
            trend_status = "weekly_trend"
        else:
            trend_status = "trend"
            
        series = []
        for sf in snapshot_files:
            try:
                with open(sf, "r", encoding="utf-8") as f:
                    snap = json.load(f)
            except Exception as e:
                logger.warning(f"Falha ao processar snapshot {sf.name} para tendência: {e}")
                continue
                
            timestamp = snap.get("timestamp", sf.stat().st_mtime)
            vulns = snap.get("agent_vulnerabilities", [])
            
            # Agregadores por snapshot
            total_v = len(vulns)
            crit = 0
            high = 0
            med = 0
            low = 0
            kev = 0
            epss_high = 0
            
            sla_overdue = 0
            sla_due_soon = 0
            sla_within = 0
            sla_unknown = 0
            
            persistent = 0
            recurring = 0
            
            accepted = 0
            false_positive = 0
            expired_acc = 0
            actionable = 0
            
            agents_set = set()
            pkgs_set = set()
            
            for v in vulns:
                severity = str(v.get("severity", "unknown")).lower()
                if severity == "critical":
                    crit += 1
                elif severity == "high":
                    high += 1
                elif severity == "medium":
                    med += 1
                elif severity == "low":
                    low += 1
                    
                if v.get("is_kev"):
                    kev += 1
                if (v.get("epss_score") or 0.0) >= 0.20:
                    epss_high += 1
                    
                sla_stat = v.get("sla_status", "unknown")
                if sla_stat == "overdue":
                    sla_overdue += 1
                elif sla_stat == "due_soon":
                    sla_due_soon += 1
                elif sla_stat == "within_sla":
                    sla_within += 1
                else:
                    sla_unknown += 1
                    
                if v.get("persistent"):
                    persistent += 1
                if v.get("recurring"):
                    recurring += 1
                    
                ra = v.get("risk_acceptance", {})
                ra_status = ra.get("status", "none")
                ra_expired = ra.get("expired", False)
                
                if ra_status == "accepted" and not ra_expired:
                    accepted += 1
                elif ra_status == "false_positive" and not ra_expired:
                    false_positive += 1
                    
                if ra_expired:
                    expired_acc += 1
                    
                is_excluded = ra_status in ["accepted", "false_positive", "out_of_scope", "duplicate"]
                if (not is_excluded) or ra_expired:
                    actionable += 1
                    
                if v.get("agent_id"):
                    agents_set.add(v["agent_id"])
                if v.get("package_name"):
                    pkgs_set.add(v["package_name"])
                    
            series.append({
                "timestamp": timestamp,
                "total_vulnerabilities": total_v,
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low,
                "kev_count": kev,
                "epss_high_count": epss_high,
                "affected_agents": len(agents_set),
                "packages_affected": len(pkgs_set),
                "sla_overdue": sla_overdue,
                "sla_due_soon": sla_due_soon,
                "sla_within": sla_within,
                "sla_unknown": sla_unknown,
                "persistent_vulnerabilities": persistent,
                "recurring_vulnerabilities": recurring,
                "accepted_risks": accepted,
                "false_positive_risks": false_positive,
                "expired_acceptances": expired_acc,
                "actionable_priorities": actionable,
                "_vulns": vulns
            })
            
        if not series:
            return None
            
        last_snap = series[-1]
        
        # Calcular tempo de período
        try:
            first_time_str = series[0]["timestamp"].replace("Z", "+00:00")
            last_time_str = last_snap["timestamp"].replace("Z", "+00:00")
            first_time = datetime.fromisoformat(first_time_str)
            last_time = datetime.fromisoformat(last_time_str)
            period_days = (last_time - first_time).days
        except Exception:
            period_days = 0
            
        if len(series) >= 2:
            prev_snap = series[-2]
            delta = {
                "total_vulnerabilities": last_snap["total_vulnerabilities"] - prev_snap["total_vulnerabilities"],
                "critical": last_snap["critical"] - prev_snap["critical"],
                "high": last_snap["high"] - prev_snap["high"],
                "medium": last_snap["medium"] - prev_snap["medium"],
                "low": last_snap["low"] - prev_snap["low"],
                "kev_count": last_snap["kev_count"] - prev_snap["kev_count"],
                "sla_overdue": last_snap["sla_overdue"] - prev_snap["sla_overdue"],
                "sla_due_soon": last_snap["sla_due_soon"] - prev_snap["sla_due_soon"],
                "actionable_priorities": last_snap["actionable_priorities"] - prev_snap["actionable_priorities"]
            }
            
            # risk_direction
            if delta["critical"] > 0 or delta["kev_count"] > 0 or delta["sla_overdue"] > 0 or delta["actionable_priorities"] > 0:
                risk_direction = "worsening"
            elif delta["total_vulnerabilities"] < 0 and delta["critical"] <= 0:
                risk_direction = "improving"
            else:
                risk_direction = "stable"
                
            # executive_health
            expired_delta = last_snap["expired_acceptances"] - prev_snap["expired_acceptances"]
            if delta["critical"] > 0 or delta["kev_count"] > 0 or delta["sla_overdue"] > 0 or expired_delta > 0:
                executive_health = "critical"
            elif delta["critical"] <= 0 and delta["kev_count"] <= 0 and last_snap["sla_overdue"] == 0 and delta["actionable_priorities"] <= 0:
                executive_health = "healthy"
            else:
                executive_health = "attention"
        else:
            prev_snap = last_snap
            delta = {
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "kev_count": 0,
                "sla_overdue": 0,
                "sla_due_soon": 0,
                "actionable_priorities": 0
            }
            risk_direction = "unknown"
            executive_health = "attention" if snapshots_analyzed > 0 else "unknown"

        # Top persistent CVEs
        last_vulns = last_snap.get("_vulns", [])
        persistent_items = [v for v in last_vulns if v.get("persistent")]
        persistent_items.sort(key=lambda x: -x.get("age_days", 0))
        top_persistent = []
        for v in persistent_items[:10]:
            top_persistent.append({
                "cve": v["cve"],
                "agent_id": v["agent_id"],
                "agent_name": v["agent_name"],
                "severity": v["severity"],
                "age_days": v.get("age_days", 0),
                "sla_status": v.get("sla_status", "unknown")
            })
            
        # Evolução por Ativo
        asset_info = {}
        for v in prev_snap.get("_vulns", []):
            aid = v["agent_id"]
            if aid not in asset_info:
                asset_info[aid] = {
                    "agent_id": aid,
                    "agent_name": v["agent_name"],
                    "prev_total": 0,
                    "prev_critical": 0,
                    "curr_total": 0,
                    "curr_critical": 0,
                    "technical_owner": v.get("technical_owner", "unknown"),
                    "criticality": v.get("criticality", "unknown"),
                    "exposure_level": v.get("exposure_level", "unknown")
                }
            asset_info[aid]["prev_total"] += 1
            if str(v.get("severity", "")).lower() == "critical":
                asset_info[aid]["prev_critical"] += 1
                
        for v in last_vulns:
            aid = v["agent_id"]
            if aid not in asset_info:
                asset_info[aid] = {
                    "agent_id": aid,
                    "agent_name": v["agent_name"],
                    "prev_total": 0,
                    "prev_critical": 0,
                    "curr_total": 0,
                    "curr_critical": 0,
                    "technical_owner": v.get("technical_owner", "unknown"),
                    "criticality": v.get("criticality", "unknown"),
                    "exposure_level": v.get("exposure_level", "unknown")
                }
            asset_info[aid]["curr_total"] += 1
            if str(v.get("severity", "")).lower() == "critical":
                asset_info[aid]["curr_critical"] += 1
            asset_info[aid]["technical_owner"] = v.get("technical_owner", asset_info[aid]["technical_owner"])
            asset_info[aid]["criticality"] = v.get("criticality", asset_info[aid]["criticality"])
            asset_info[aid]["exposure_level"] = v.get("exposure_level", asset_info[aid]["exposure_level"])
            
        asset_trend_list = []
        for aid, info in asset_info.items():
            dt = info["curr_total"] - info["prev_total"]
            dc = info["curr_critical"] - info["prev_critical"]
            
            if dc > 0 or dt > 0:
                dir_val = "worsening"
            elif dt < 0:
                dir_val = "improving"
            else:
                dir_val = "stable"
                
            asset_trend_list.append({
                "agent_id": aid,
                "agent_name": info["agent_name"],
                "current_total": info["curr_total"],
                "previous_total": info["prev_total"],
                "delta_total": dt,
                "current_critical": info["curr_critical"],
                "previous_critical": info["prev_critical"],
                "delta_critical": dc,
                "risk_direction": dir_val,
                "technical_owner": info["technical_owner"] or "unknown",
                "criticality": info["criticality"] or "unknown",
                "exposure_level": info["exposure_level"] or "unknown"
            })
            
        top_worsening_assets = [a for a in asset_trend_list if a["risk_direction"] == "worsening"]
        top_worsening_assets.sort(key=lambda x: (-x["delta_critical"], -x["delta_total"]))
        
        top_improving_assets = [a for a in asset_trend_list if a["risk_direction"] == "improving"]
        top_improving_assets.sort(key=lambda x: (x["delta_total"], x["delta_critical"]))
        
        # Evolução por Owner
        owner_info = {}
        for v in prev_snap.get("_vulns", []):
            owner = v.get("technical_owner", "unknown") or "unknown"
            if owner not in owner_info:
                owner_info[owner] = {"prev_total": 0, "prev_overdue": 0, "curr_total": 0, "curr_overdue": 0}
            owner_info[owner]["prev_total"] += 1
            if v.get("sla_status") == "overdue":
                owner_info[owner]["prev_overdue"] += 1
                
        for v in last_vulns:
            owner = v.get("technical_owner", "unknown") or "unknown"
            if owner not in owner_info:
                owner_info[owner] = {"prev_total": 0, "prev_overdue": 0, "curr_total": 0, "curr_overdue": 0}
            owner_info[owner]["curr_total"] += 1
            if v.get("sla_status") == "overdue":
                owner_info[owner]["curr_overdue"] += 1
                
        owner_trend_list = []
        for owner, info in owner_info.items():
            dt = info["curr_total"] - info["prev_total"]
            do = info["curr_overdue"] - info["prev_overdue"]
            if do > 0 or dt > 0:
                dir_val = "worsening"
            elif dt < 0:
                dir_val = "improving"
            else:
                dir_val = "stable"
                
            owner_trend_list.append({
                "technical_owner": owner,
                "current_total": info["curr_total"],
                "previous_total": info["prev_total"],
                "delta_total": dt,
                "current_overdue": info["curr_overdue"],
                "previous_overdue": info["prev_overdue"],
                "delta_overdue": do,
                "risk_direction": dir_val
            })
            
        # Séries temporais (Timeline)
        severity_trend = []
        sla_trend = []
        acceptance_trend = []
        clean_trend_series = []
        
        for s in series:
            ts = s["timestamp"]
            clean_trend_series.append({
                "timestamp": ts,
                "total_vulnerabilities": s["total_vulnerabilities"],
                "critical": s["critical"],
                "high": s["high"],
                "actionable_priorities": s["actionable_priorities"]
            })
            severity_trend.append({
                "timestamp": ts,
                "critical": s["critical"],
                "high": s["high"],
                "medium": s["medium"],
                "low": s["low"]
            })
            sla_trend.append({
                "timestamp": ts,
                "overdue": s["sla_overdue"],
                "due_soon": s["sla_due_soon"],
                "within_sla": s["sla_within"],
                "unknown": s["sla_unknown"]
            })
            acceptance_trend.append({
                "timestamp": ts,
                "accepted_risks": s["accepted_risks"],
                "false_positive_risks": s["false_positive_risks"],
                "expired_acceptances": s["expired_acceptances"],
                "actionable_priorities": s["actionable_priorities"]
            })
            
        # Alertas Executivos
        executive_alerts = []
        if len(series) >= 2:
            if last_snap["sla_overdue"] > prev_snap["sla_overdue"]:
                executive_alerts.append({
                    "level": "critical",
                    "title": "SLA Overdue Crescendo",
                    "message": f"O volume de vulnerabilidades vencidas aumentou de {prev_snap['sla_overdue']} para {last_snap['sla_overdue']}."
                })
            if last_snap["sla_due_soon"] > prev_snap["sla_due_soon"]:
                executive_alerts.append({
                    "level": "warning",
                    "title": "SLA Due Soon Crescendo",
                    "message": f"Vulnerabilidades próximas do vencimento de SLA cresceram de {prev_snap['sla_due_soon']} para {last_snap['sla_due_soon']}."
                })
            if last_snap["persistent_vulnerabilities"] > prev_snap["persistent_vulnerabilities"]:
                executive_alerts.append({
                    "level": "warning",
                    "title": "Vulnerabilidades Persistentes Crescendo",
                    "message": f"Vulnerabilidades abertas há mais de 30 dias cresceram de {prev_snap['persistent_vulnerabilities']} para {last_snap['persistent_vulnerabilities']}."
                })
            if last_snap["expired_acceptances"] > prev_snap["expired_acceptances"]:
                executive_alerts.append({
                    "level": "critical",
                    "title": "Exceções Vencidas Aumentando",
                    "message": f"O número de exceções ou aceites de risco vencidos aumentou de {prev_snap['expired_acceptances']} para {last_snap['expired_acceptances']}."
                })
            if last_snap["accepted_risks"] > prev_snap["accepted_risks"] * 1.2 and last_snap["accepted_risks"] > 5:
                executive_alerts.append({
                    "level": "warning",
                    "title": "Riscos Aceitos Crescendo Rapidamente",
                    "message": f"Houve um aumento expressivo no volume de aceites de risco ({prev_snap['accepted_risks']} -> {last_snap['accepted_risks']})."
                })
            if last_snap["actionable_priorities"] > prev_snap["actionable_priorities"]:
                executive_alerts.append({
                    "level": "warning",
                    "title": "Prioridades Acionáveis Crescendo",
                    "message": f"O backlog real acionável aumentou de {prev_snap['actionable_priorities']} para {last_snap['actionable_priorities']}."
                })
            if last_snap["critical"] > prev_snap["critical"]:
                executive_alerts.append({
                    "level": "critical",
                    "title": "Vulnerabilidades Críticas Aumentando",
                    "message": f"Vulnerabilidades críticas subiram de {prev_snap['critical']} para {last_snap['critical']}."
                })
        else:
            executive_alerts.append({
                "level": "info",
                "title": "Histórico de Tendência Limitado",
                "message": "Histórico insuficiente para calcular tendências executivas."
            })
            
        trend_summary = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "ok",
            "source": str(snapshots_dir),
            "summary": {
                "snapshots_analyzed": snapshots_analyzed,
                "first_snapshot": series[0]["timestamp"],
                "last_snapshot": last_snap["timestamp"],
                "period_days": period_days,
                "trend_status": trend_status,
                "risk_direction": risk_direction,
                "executive_health": executive_health
            },
            "current": {
                "total_vulnerabilities": last_snap["total_vulnerabilities"],
                "critical": last_snap["critical"],
                "high": last_snap["high"],
                "medium": last_snap["medium"],
                "low": last_snap["low"],
                "kev_count": last_snap["kev_count"],
                "epss_high_count": last_snap["epss_high_count"],
                "sla_overdue": last_snap["sla_overdue"],
                "sla_due_soon": last_snap["sla_due_soon"],
                "accepted_risks": last_snap["accepted_risks"],
                "false_positive_risks": last_snap["false_positive_risks"],
                "actionable_priorities": last_snap["actionable_priorities"]
            },
            "delta": delta,
            "trend_series": clean_trend_series,
            "severity_trend": severity_trend,
            "sla_trend": sla_trend,
            "acceptance_trend": acceptance_trend,
            "asset_trend": asset_trend_list,
            "owner_trend": owner_trend_list,
            "top_worsening_assets": top_worsening_assets[:10],
            "top_improving_assets": top_improving_assets[:10],
            "top_persistent_cves": top_persistent,
            "executive_alerts": executive_alerts
        }
        
        _atomic_write(json.dumps(trend_summary, indent=2, ensure_ascii=False), trend_summary_path, web_group)
        
        return {
            "trend_enabled": True,
            "trend_status": trend_status,
            "risk_direction": risk_direction,
            "executive_health": executive_health,
            "snapshots_analyzed": snapshots_analyzed,
            "delta_total_vulnerabilities": delta["total_vulnerabilities"],
            "delta_critical": delta["critical"],
            "delta_high": delta["high"],
            "delta_kev": delta["kev_count"],
            "delta_sla_overdue": delta["sla_overdue"],
            "delta_actionable_priorities": delta["actionable_priorities"]
        }
    except Exception as e:
        logger.error(f"[ERRO] Falha ao gerar tendência executiva: {e}", exc_info=True)
        return None

def write_degraded_treatment_plan(web_dir: str, web_group: Optional[str], message: str) -> None:
    try:
        summary_path = Path(web_dir) / "data" / "treatment_plan_summary.json"
        plan_detailed_path = Path(web_dir) / "data" / "treatment_plan.json"
        degraded = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "degraded",
            "message": message,
            "summary": {
                "total_actionable_items": 0,
                "now": 0,
                "next_7_days": 0,
                "next_15_days": 0,
                "next_30_days": 0,
                "monitor": 0,
                "accepted_or_exception": 0,
                "false_positive": 0,
                "owners": 0,
                "quick_wins": 0,
                "change_window_candidates": 0
            },
            "by_owner": [],
            "by_bucket": [],
            "by_effort": [],
            "quick_wins": [],
            "change_window_candidates": [],
            "top_treatment_items": [],
            "owner_workload": [],
            "treatment_alerts": [
                {
                    "level": "warning",
                    "title": "Plano de Tratativa Indisponível",
                    "message": f"O plano operacional de tratativa está degradado: {message}."
                }
            ]
        }
        _atomic_write(json.dumps(degraded, indent=2, ensure_ascii=False), summary_path, web_group)
        _atomic_write(json.dumps({"timestamp": degraded["timestamp"], "status": "degraded", "items": []}, indent=2, ensure_ascii=False), plan_detailed_path, web_group)
    except Exception as e:
        logger.error(f"[ERRO] Falha ao gravar plano de tratativa degradado: {e}", exc_info=True)

def generate_treatment_plan(web_dir: str, web_group: Optional[str] = None) -> Optional[dict]:
    """
    Fase 3G: Lê snapshots e summaries para compilar o plano de tratativa operacional,
    carga de trabalho por owner e detecção de quick wins / planejamentos de mudanças complexas.
    Retorna dicionário de enriquecimento para o risk_summary.json.
    """
    try:
        web_path = Path(web_dir)
        snapshots_dir = web_path / "data" / "snapshots"
        latest_snap_path = snapshots_dir / "latest_snapshot.json"
        trend_summary_path = web_path / "data" / "trend_summary.json"
        
        summary_path = web_path / "data" / "treatment_plan_summary.json"
        plan_detailed_path = web_path / "data" / "treatment_plan.json"
        
        # Configuração de política padrão segura (default embutido)
        policy = {
            "metadata": {
                "version": "1.0",
                "description": "Política de priorização de plano de tratativa operacional",
                "updated_by": "security-team",
                "updated_at": "2026-06-16T00:00:00Z"
            },
            "defaults": {
                "planning_windows_days": [7, 15, 30],
                "quick_win_max_assets": 2,
                "quick_win_max_packages": 2,
                "high_effort_threshold_assets": 5,
                "owner_unknown_label": "unknown",
                "max_plan_items": 200,
                "max_top_items_per_section": 20
            },
            "priority_weights": {
                "critical": 40,
                "high": 25,
                "medium": 10,
                "low": 2,
                "kev": 30,
                "epss_high": 15,
                "sla_overdue": 35,
                "sla_due_soon": 20,
                "internet_facing": 25,
                "dmz": 15,
                "critical_asset": 25,
                "high_asset": 15,
                "trend_worsening": 20,
                "recurring": 10,
                "persistent": 10,
                "accepted_valid": -30,
                "false_positive_valid": -100,
                "expired_acceptance": 30
            },
            "effort_rules": {
                "single_asset_single_package": "low",
                "few_assets_same_package": "medium",
                "many_assets_or_core_component": "high",
                "kernel_or_os_update": "high",
                "windows_cumulative_update": "high"
            },
            "treatment_buckets": {
                "now": {
                  "label": "Tratar agora",
                  "min_score": 80
                },
                "next_7_days": {
                  "label": "Próximos 7 dias",
                  "min_score": 65
                },
                "next_15_days": {
                  "label": "Próximos 15 dias",
                  "min_score": 50
                },
                "next_30_days": {
                  "label": "Próximos 30 dias",
                  "min_score": 30
                },
                "monitor": {
                  "label": "Monitorar",
                  "min_score": 0
                }
            }
        }
        
        # Suporte ao arquivo real
        policy_opt = Path("/opt/hmg-soar/config/treatment_policy.json")
        policy_loc = Path("./config/treatment_policy.json")
        policy_file = policy_opt if policy_opt.exists() else policy_loc
        if policy_file.exists():
            try:
                with open(policy_file, "r", encoding="utf-8") as pf:
                    user_policy = json.load(pf)
                    for key in ["metadata", "defaults", "priority_weights", "effort_rules", "treatment_buckets"]:
                        if key in user_policy:
                            policy[key].update(user_policy[key])
            except Exception as pe:
                logger.warning(f"Falha ao carregar arquivo de política de tratativa: {pe}")
                
        # Ler tendência de ativos
        asset_trends = {}
        if trend_summary_path.exists():
            try:
                with open(trend_summary_path, "r", encoding="utf-8") as tf:
                    trend_data = json.load(tf)
                    for item in trend_data.get("asset_trend", []):
                        aid = item.get("agent_id")
                        if aid:
                            asset_trends[aid] = item.get("risk_direction", "stable")
            except Exception as te:
                logger.warning(f"Falha ao ler trend_summary para plano de tratativa: {te}")
                
        if not latest_snap_path.exists():
            write_degraded_treatment_plan(web_dir, web_group, "Snapshot mais recente nao disponível")
            return None
            
        with open(latest_snap_path, "r", encoding="utf-8") as sf:
            snapshot = json.load(sf)
            
        vulns = snapshot.get("agent_vulnerabilities", [])
        if not vulns:
            write_degraded_treatment_plan(web_dir, web_group, "Nenhuma vulnerabilidade ativa no snapshot")
            return None
            
        # Mapeamento do número de agentes por CVE
        cve_agent_map = defaultdict(set)
        for v in vulns:
            cve = v.get("cve")
            aid = v.get("agent_id")
            if cve and aid:
                cve_agent_map[cve].add(aid)
                
        weights = policy.get("priority_weights", {})
        defaults = policy.get("defaults", {})
        
        treated_items = []
        bucket_counts = defaultdict(int)
        effort_counts = defaultdict(int)
        owner_counts = defaultdict(int)
        
        owner_details = {}
        sensitive_packages = {
            "openssl", "curl", "sudo", "openssh", "openssh-server", "kernel", "linux-image", 
            "glibc", "libc", "apache", "nginx", "php", "python", "java", "log4j", "docker", 
            "containerd", "kubernetes"
        }
        
        for v in vulns:
            cve = v.get("cve", "unknown_cve")
            aid = v.get("agent_id", "unknown_agent")
            aname = v.get("agent_name", "unknown_agent_name")
            pkg = v.get("package_name", "unknown_package")
            severity = v.get("severity", "unknown")
            severity_lower = str(severity).lower()
            
            is_kev_val = bool(v.get("is_kev", False))
            epss_score_val = v.get("epss_score") or v.get("epss") or 0.0
            
            owner = v.get("technical_owner") or defaults.get("owner_unknown_label", "unknown")
            b_owner = v.get("business_owner") or defaults.get("owner_unknown_label", "unknown")
            
            criticality = v.get("criticality") or "unknown"
            exposure_level = v.get("exposure_level") or "unknown"
            
            sla_status = v.get("sla_status", "unknown")
            days_to_due = v.get("days_to_due", 0)
            
            ra = v.get("risk_acceptance", {})
            ra_status = ra.get("status", "none")
            ra_expired = ra.get("expired", False)
            
            trend_dir = asset_trends.get(aid, "stable")
            
            # 1. Technical Score
            tech_base = 0.0
            if is_kev_val:
                tech_base += 40
            if severity_lower == "critical":
                tech_base += 25
            elif severity_lower == "high":
                tech_base += 15
            if epss_score_val >= 0.50:
                tech_base += 30
            elif epss_score_val >= 0.20:
                tech_base += 20
                
            assets_count = len(cve_agent_map.get(cve, []))
            tech_base += min(assets_count * 3, 15)
            
            if str(pkg).lower() in sensitive_packages:
                tech_base += 10
                
            asset_crit_val = 0
            if criticality.lower() == "critical":
                asset_crit_val = 25
            elif criticality.lower() == "high":
                asset_crit_val = 15
            elif criticality.lower() == "medium":
                asset_crit_val = 5
                
            asset_expo_val = 0
            if exposure_level.lower() == "internet" or exposure_level.lower() == "internet_facing":
                asset_expo_val = 25
            elif exposure_level.lower() == "dmz":
                asset_expo_val = 15
            elif exposure_level.lower() == "internal":
                asset_expo_val = 5
                
            sla_op_val = 0
            if sla_status == "overdue":
                sla_op_val += 15
            elif sla_status == "due_soon":
                sla_op_val += 10
            if bool(v.get("persistent", False)):
                sla_op_val += 10
            if bool(v.get("recurring", False)):
                sla_op_val += 10
                
            ra_modifier = 0
            if ra_status == "accepted" and not ra_expired:
                ra_modifier = -30
            elif ra_status == "compensating_control" and not ra_expired:
                ra_modifier = -15
            elif ra_expired:
                ra_modifier = 10
                
            technical_score = max(0, min(100, int(tech_base + asset_crit_val + asset_expo_val + sla_op_val + ra_modifier)))
            
            # 2. Treatment Score
            severity_w = 0
            if severity_lower == "critical":
                severity_w = weights.get("critical", 40)
            elif severity_lower == "high":
                severity_w = weights.get("high", 25)
            elif severity_lower == "medium":
                severity_w = weights.get("medium", 10)
            elif severity_lower == "low":
                severity_w = weights.get("low", 2)
                
            kev_w = weights.get("kev", 30) if is_kev_val else 0
            epss_w = weights.get("epss_high", 15) if epss_score_val >= 0.20 else 0
            
            sla_w = 0
            if sla_status == "overdue":
                sla_w = weights.get("sla_overdue", 35)
            elif sla_status == "due_soon":
                sla_w = weights.get("sla_due_soon", 20)
                
            expo_w = 0
            if exposure_level.lower() == "internet" or exposure_level.lower() == "internet_facing":
                expo_w = weights.get("internet_facing", 25)
            elif exposure_level.lower() == "dmz":
                expo_w = weights.get("dmz", 15)
                
            asset_w = 0
            if criticality.lower() == "critical":
                asset_w = weights.get("critical_asset", 25)
            elif criticality.lower() == "high":
                asset_w = weights.get("high_asset", 15)
                
            trend_w = weights.get("trend_worsening", 20) if trend_dir.lower() == "worsening" else 0
            rec_w = weights.get("recurring", 10) if bool(v.get("recurring", False)) else 0
            per_w = weights.get("persistent", 10) if bool(v.get("persistent", False)) else 0
            
            ra_w = 0
            if ra_status == "accepted" and not ra_expired:
                ra_w = weights.get("accepted_valid", -30)
            elif ra_status == "false_positive" and not ra_expired:
                ra_w = weights.get("false_positive_valid", -100)
            elif ra_expired:
                ra_w = weights.get("expired_acceptance", 30)
                
            treatment_score = max(0, min(100, int(
                severity_w + kev_w + epss_w + sla_w + expo_w + asset_w + trend_w + rec_w + per_w + ra_w
            )))
            
            # Determine Esforço e Esforço sugerido
            pkg_lower = str(pkg).lower()
            is_os_or_kernel = any(x in pkg_lower for x in ["linux-image", "linux-headers", "kernel", "linux-modules", "microsoft", "windows-update", "kb"])
            is_core_comp = pkg_lower in sensitive_packages
            
            if is_os_or_kernel or is_core_comp:
                effort = "high"
                action_type = "planejar janela de mudança controlada" if is_os_or_kernel else "planejar atualização de componente crítico"
            elif assets_count >= defaults.get("high_effort_threshold_assets", 5):
                effort = "high"
                action_type = "planejar atualização em lote de ativos"
            elif assets_count >= 2:
                effort = "medium"
                action_type = "planejar atualização controlada"
            else:
                effort = "low"
                action_type = "atualizar pacote via gerenciador de pacotes"
                
            # Determine Bucket & suggested window
            if ra_status == "false_positive" and not ra_expired:
                bucket = "false_positive"
                suggested_win = "none"
            elif ra_status == "accepted" and not ra_expired:
                bucket = "accepted_or_exception"
                suggested_win = "none"
            else:
                is_critical_override = (severity_lower == "critical")
                if is_critical_override and sla_status == "overdue":
                    bucket = "now"
                elif is_critical_override and is_kev_val:
                    bucket = "now"
                elif is_critical_override and (exposure_level.lower() == "internet" or exposure_level.lower() == "internet_facing"):
                    bucket = "now"
                elif is_critical_override and sla_status == "due_soon":
                    bucket = "next_7_days"
                elif severity_lower == "high" and trend_dir.lower() == "worsening":
                    bucket = "next_15_days"
                elif treatment_score >= 80:
                    bucket = "now"
                elif treatment_score >= 65:
                    bucket = "next_7_days"
                elif treatment_score >= 50:
                    bucket = "next_15_days"
                elif treatment_score >= 30:
                    bucket = "next_30_days"
                else:
                    bucket = "monitor"
                    
                if bucket == "now":
                    suggested_win = "immediate"
                elif bucket == "next_7_days":
                    suggested_win = "next_7_days"
                elif bucket == "next_15_days":
                    suggested_win = "next_15_days"
                elif bucket == "next_30_days":
                    suggested_win = "next_30_days"
                else:
                    suggested_win = "routine_maintenance"
                    
            if ra_expired:
                action_type = "revisar regra de risk acceptance expirada"
                
            # Dynamic reason
            reasons = []
            if severity_lower == "critical":
                reasons.append("Crítica")
            elif severity_lower == "high":
                reasons.append("Alta")
            if is_kev_val:
                reasons.append("KEV ativo")
            if epss_score_val >= 0.20:
                reasons.append("EPSS alto")
            if sla_status == "overdue":
                reasons.append("SLA vencido")
            elif sla_status == "due_soon":
                reasons.append("próxima do vencimento")
            if bool(v.get("recurring", False)):
                reasons.append("recorrente")
            if bool(v.get("persistent", False)):
                reasons.append("persistente")
            if criticality.lower() in ["critical", "high"]:
                reasons.append("ativo crítico")
            if exposure_level.lower() in ["internet", "internet_facing"]:
                reasons.append("exposto à internet")
            if ra_expired:
                reasons.append("exceção expirada")
                
            reason_str = ", ".join(reasons) if reasons else "Priorização geral de tratamento"
            reason_str = reason_str[0].upper() + reason_str[1:]
            
            item_data = {
                "cve": cve,
                "agent_id": aid,
                "agent_name": aname,
                "package_name": pkg,
                "severity": severity,
                "technical_owner": owner,
                "business_owner": b_owner,
                "asset_criticality": criticality,
                "exposure_level": exposure_level,
                "sla_status": sla_status,
                "days_to_due": days_to_due,
                "risk_acceptance_status": ra_status,
                "trend_direction": trend_dir,
                "technical_score": technical_score,
                "treatment_score": treatment_score,
                "treatment_bucket": bucket,
                "effort": effort,
                "suggested_action_type": action_type,
                "suggested_window": suggested_win,
                "reason": reason_str
            }
            
            treated_items.append(item_data)
            
            # Counts aggregates
            is_actionable = bucket not in ["accepted_or_exception", "false_positive"]
            if is_actionable:
                bucket_counts[bucket] += 1
                effort_counts[effort] += 1
                owner_counts[owner] += 1
                
                # Update workload per owner
                if owner not in owner_details:
                    owner_details[owner] = {
                        "technical_owner": owner,
                        "total_actionable": 0,
                        "now": 0,
                        "next_7_days": 0,
                        "next_15_days": 0,
                        "next_30_days": 0,
                        "monitor": 0,
                        "overdue": 0,
                        "due_soon": 0,
                        "critical": 0,
                        "high": 0,
                        "estimated_effort": {"low": 0, "medium": 0, "high": 0},
                        "_assets_counts": defaultdict(int),
                        "_cves_counts": defaultdict(int),
                        "top_assets": [],
                        "top_cves": []
                    }
                    
                ow = owner_details[owner]
                ow["total_actionable"] += 1
                ow[bucket] += 1
                if sla_status == "overdue":
                    ow["overdue"] += 1
                elif sla_status == "due_soon":
                    ow["due_soon"] += 1
                if severity_lower == "critical":
                    ow["critical"] += 1
                elif severity_lower == "high":
                    ow["high"] += 1
                    
                ow["estimated_effort"][effort] += 1
                ow["_assets_counts"][(aid, aname)] += 1
                ow["_cves_counts"][cve] += 1
                
        # Finalize workload lists
        owner_workload = []
        for owner, ow in owner_details.items():
            assets_sorted = sorted(ow["_assets_counts"].items(), key=lambda x: -x[1])
            ow["top_assets"] = [
                {"agent_id": a_id, "agent_name": a_name, "total_vulnerabilities": count}
                for (a_id, a_name), count in assets_sorted[:5]
            ]
            cves_sorted = sorted(ow["_cves_counts"].items(), key=lambda x: -x[1])
            ow["top_cves"] = [{"cve": cve_id, "count": count} for cve_id, count in cves_sorted[:5]]
            
            del ow["_assets_counts"]
            del ow["_cves_counts"]
            
            owner_workload.append(ow)
            
        # Sort treated items by treatment score descending
        treated_items.sort(key=lambda x: -x["treatment_score"])
        
        # Select quick wins
        quick_wins_candidates = [
            i for i in treated_items
            if i["effort"] == "low" and i["treatment_bucket"] in ["now", "next_7_days"]
            and len(cve_agent_map.get(i["cve"], [])) <= defaults.get("quick_win_max_assets", 2)
        ]
        
        quick_wins = []
        for qw in quick_wins_candidates[:defaults.get("max_top_items_per_section", 20)]:
            quick_wins.append({
                "title": f"Atualizar {qw['package_name']} no ativo {qw['agent_name']}",
                "reason": f"{qw['reason'] or 'Prioritário'}, baixo esforço e apenas {len(cve_agent_map.get(qw['cve'], []))} ativo(s) afetado(s).",
                "affected_assets": len(cve_agent_map.get(qw['cve'], [])),
                "affected_packages": 1,
                "treatment_score": qw["treatment_score"],
                "owner": qw["technical_owner"],
                "suggested_window": qw["suggested_window"]
            })
            
        # Select change window candidates
        change_candidates_raw = [
            i for i in treated_items
            if i["effort"] == "high" or i["asset_criticality"].lower() == "critical"
            or len(cve_agent_map.get(i["cve"], [])) >= defaults.get("high_effort_threshold_assets", 5)
        ]
        
        change_window_candidates = []
        change_seen = set()
        for cc in change_candidates_raw:
            cve_cc = cc["cve"]
            owner_cc = cc["technical_owner"]
            key = (cve_cc, owner_cc)
            if key not in change_seen:
                change_seen.add(key)
                affected_assets_cc = len(cve_agent_map.get(cve_cc, []))
                change_window_candidates.append({
                    "title": f"Planejar atualização do pacote {cc['package_name']} ({cve_cc})",
                    "reason": f"Componente complexo ou sistema operacional em {affected_assets_cc} ativos, exigindo janela controlada.",
                    "owner": owner_cc,
                    "affected_assets": affected_assets_cc,
                    "effort": cc["effort"],
                    "suggested_window": "planned_change"
                })
                if len(change_window_candidates) >= defaults.get("max_top_items_per_section", 20):
                    break
                    
        total_actionable = sum(bucket_counts.values())
        
        # Build alerts
        treatment_alerts = []
        if bucket_counts["now"] > 50:
            treatment_alerts.append({
                "level": "critical",
                "title": "Carga Imediata Elevada",
                "message": f"Há {bucket_counts['now']} itens no balde 'Tratar Agora' exigindo atenção imediata."
            })
        overdue_total = sum(1 for v in vulns if v.get("sla_status") == "overdue")
        if overdue_total > 0:
            treatment_alerts.append({
                "level": "critical",
                "title": "Itens com SLA Vencido no Backlog",
                "message": f"Existem {overdue_total} vulnerabilidades ativas fora do prazo de SLA de remediação."
            })
        expired_acc_total = sum(1 for v in vulns if v.get("risk_acceptance", {}).get("expired", False))
        if expired_acc_total > 0:
            treatment_alerts.append({
                "level": "warning",
                "title": "Regras de Exceção Expiradas",
                "message": f"Existem {expired_acc_total} aceites de risco expirados aguardando reavaliação ou tratamento."
            })
        if len(change_window_candidates) > 10:
            treatment_alerts.append({
                "level": "warning",
                "title": "Janelas de Mudança Acumuladas",
                "message": f"Há {len(change_window_candidates)} atualizações de alta complexidade listadas para planejamento."
            })
            
        if not treatment_alerts:
            treatment_alerts.append({
                "level": "info",
                "title": "Plano Operacional Estável",
                "message": "Nenhum desvio crítico detectado na priorização do plano operacional."
            })
            
        by_owner = [{"owner": k, "count": v} for k, v in owner_counts.items()]
        by_bucket = [{"bucket": k, "count": v} for k, v in bucket_counts.items()]
        by_effort = [{"effort": k, "count": v} for k, v in effort_counts.items()]
        
        treatment_summary = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "ok",
            "source": "risk_summary + sla_summary + trend_summary + risk_acceptance_summary",
            "summary": {
                "total_actionable_items": total_actionable,
                "now": bucket_counts["now"],
                "next_7_days": bucket_counts["next_7_days"],
                "next_15_days": bucket_counts["next_15_days"],
                "next_30_days": bucket_counts["next_30_days"],
                "monitor": bucket_counts["monitor"],
                "accepted_or_exception": sum(1 for v in vulns if v.get("risk_acceptance", {}).get("status", "none") == "accepted" and not v.get("risk_acceptance", {}).get("expired", False)),
                "false_positive": sum(1 for v in vulns if v.get("risk_acceptance", {}).get("status", "none") == "false_positive" and not v.get("risk_acceptance", {}).get("expired", False)),
                "owners": len(owner_counts),
                "quick_wins": len(quick_wins),
                "change_window_candidates": len(change_window_candidates)
            },
            "by_owner": by_owner,
            "by_bucket": by_bucket,
            "by_effort": by_effort,
            "quick_wins": quick_wins,
            "change_window_candidates": change_window_candidates,
            "top_treatment_items": treated_items[:defaults.get("max_plan_items", 200)],
            "owner_workload": owner_workload,
            "treatment_alerts": treatment_alerts
        }
        
        _atomic_write(json.dumps(treatment_summary, indent=2, ensure_ascii=False), summary_path, web_group)
        
        plan_detailed = {
            "timestamp": treatment_summary["timestamp"],
            "status": "ok",
            "items": treated_items[:defaults.get("max_plan_items", 200)]
        }
        _atomic_write(json.dumps(plan_detailed, indent=2, ensure_ascii=False), plan_detailed_path, web_group)
        
        return {
            "treatment_plan_enabled": True,
            "treatment_now": bucket_counts["now"],
            "treatment_next_7_days": bucket_counts["next_7_days"],
            "treatment_next_15_days": bucket_counts["next_15_days"],
            "treatment_next_30_days": bucket_counts["next_30_days"],
            "treatment_monitor": bucket_counts["monitor"],
            "treatment_owners": len(owner_counts),
            "quick_wins_count": len(quick_wins),
            "change_window_candidates_count": len(change_window_candidates)
        }
        
    except Exception as e:
        logger.error(f"[ERRO] Falha ao gerar plano de tratativa operacional: {e}", exc_info=True)
        return None

def prompt_yes_no(question: str, default_no: bool = True) -> bool:
    suffix = "[s/N]" if default_no else "[S/n]"
    while True:
        answer = input(f"{question} {suffix}: ").strip().lower()
        if not answer:
            return not default_no
        if answer in {"s", "sim", "y", "yes"}:
            return True
        if answer in {"n", "nao", "não", "no"}:
            return False
        print("Digite 's' para sim ou 'n' para não.")


def require_passwords(ctx: AppContext) -> None:
    if not ctx.indexer_pass:
        ctx.indexer_pass = getpass.getpass("Senha do OpenSearch/Indexer: ")
    if not ctx.wazuh_pass:
        ctx.wazuh_pass = getpass.getpass("Senha da API do Wazuh: ")


def normalize_agent_list(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    agents: List[str] = []
    for item in raw.replace(";", ",").split(","):
        value = item.strip()
        if value:
            agents.append(value.zfill(3) if value.isdigit() else value)
    return list(dict.fromkeys(agents))


def choose_agents_interactively() -> List[str]:
    print("\nAgentes conhecidos no HMG:")
    for agent_id, name in KNOWN_AGENTS.items():
        print(f"  {agent_id} - {name}")

    print("\nDigite um ID, vários separados por vírgula, ou 'all' para consultar todos.")
    selection = input("Agente(s): ").strip().lower()

    if selection in {"all", "todos", "*"}:
        return list(KNOWN_AGENTS.keys())

    agents = normalize_agent_list(selection)
    if not agents:
        print("Nenhum agente informado. Saindo sem executar.")
        sys.exit(1)
    return agents


def _parse_kev_json(data: dict) -> Dict[str, dict]:
    """Extrai e normaliza o mapa CVE→metadados a partir do payload JSON do CISA KEV."""
    kev_map: Dict[str, dict] = {}
    for vuln in data.get("vulnerabilities", []):
        cve = str(vuln.get("cveID", "")).upper().strip()
        if cve:
            kev_map[cve] = {
                "ransomware": str(vuln.get("knownRansomwareCampaignUse", "")).upper() == "KNOWN",
                "vendor": vuln.get("vendorProject", "N/A"),
                "product": vuln.get("product", "N/A"),
                "date_added": vuln.get("dateAdded", "N/A"),
            }
    return kev_map


def get_cisa_kev(ctx: AppContext) -> Dict[str, dict]:
    """Baixa e retorna o catálogo CISA KEV com resiliência em múltiplos níveis.

    Ordem de tentativa (Phase 3I.1):
      1. Cache local válido (dentro do TTL configurado).
      2. Fonte primária: CISA.gov JSON.
      3. Fonte fallback: espelho raw do GitHub.
      4. Cache expirado (stale) — última linha de defesa.
      5. Dict vazio com aviso crítico — nunca levanta exceção para o chamador.
    """
    cache_key = "cisa_kev"

    # ── Nível 1: cache quente ──────────────────────────────────────────────────
    if ctx.use_cache:
        cached = _read_cache(cache_key)
        if cached is not None:
            logger.info(
                f"[KEV][CACHE HIT] Catálogo CISA KEV carregado do cache local "
                f"({len(cached)} CVEs, fonte: disco, TTL: {CACHE_TTL_HOURS}h)."
            )
            return cached

    t0 = time.time()
    kev_map: Dict[str, dict] = {}
    source_used: str = "none"

    # ── Nível 2: fonte primária — CISA.gov ────────────────────────────────────
    try:
        logger.info("[KEV][PRIMARY] Tentando fonte primária: CISA.gov...")
        response = ctx.session.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        kev_map = _parse_kev_json(response.json())
        source_used = "cisa_gov"
        logger.info(
            f"[KEV][PRIMARY OK] CISA.gov: {len(kev_map)} CVEs carregados "
            f"(elapsed: {time.time()-t0:.2f}s)."
        )
    except Exception as primary_err:
        logger.warning(
            f"[KEV][PRIMARY FAIL] Fonte primária CISA.gov indisponível: {primary_err}. "
            "Tentando fallback GitHub..."
        )

        # ── Nível 3: fallback — GitHub mirror ─────────────────────────────────
        try:
            t1 = time.time()
            fb_response = ctx.session.get(CISA_KEV_FALLBACK_URL, timeout=REQUEST_TIMEOUT)
            fb_response.raise_for_status()
            kev_map = _parse_kev_json(fb_response.json())
            source_used = "github_mirror"
            logger.warning(
                f"[KEV][FALLBACK OK] Espelho GitHub usado: {len(kev_map)} CVEs "
                f"(elapsed: {time.time()-t1:.2f}s). "
                "Considere investigar a disponibilidade do CISA.gov."
            )
        except Exception as fallback_err:
            logger.error(
                f"[KEV][FALLBACK FAIL] Espelho GitHub também indisponível: {fallback_err}. "
                "Tentando cache expirado (stale)..."
            )

            # ── Nível 4: stale cache — última linha de defesa ──────────────────
            stale = _read_stale_cache(cache_key)
            if stale is not None:
                source_used = "stale_cache"
                kev_map = stale
                # Não atualiza o cache (mantém o stale para próxima tentativa)
            else:
                # ── Nível 5: degradação total — retorna dict vazio ──────────────
                source_used = "empty_degraded"
                kev_map = {}
                logger.critical(
                    "[KEV][DEGRADED] Nenhuma fonte KEV disponível (primária, fallback, stale). "
                    "Análise prosseguirá SEM dados KEV. "
                    "Verifique conectividade ou defina HMG_CACHE_DIR com cache pré-populado."
                )

    elapsed = time.time() - t0
    ctx.record_timing("cisa_kev_download", elapsed)

    # Persiste no cache apenas se a fonte foi online (não stale ou degradada)
    if ctx.use_cache and source_used in ("cisa_gov", "github_mirror") and kev_map:
        _write_cache(cache_key, kev_map)
        logger.info(f"[KEV][CACHE WRITE] Catálogo KEV salvo no cache (fonte: {source_used}).")

    return kev_map


def _parse_epss_stream(fileobj: Any, epss_threshold: float) -> Dict[str, float]:
    """Lê e filtra scores EPSS a partir de um file-like object (CSV descomprimido).

    Espera o formato padrão EPSS: primeira linha = metadado, segunda = cabeçalho,
    demais = cve,epss,percentile.
    """
    epss_high: Dict[str, float] = {}
    fileobj.readline()  # ignora metadado do modelo (ex: "#model_version:...,score_date:...")
    reader = csv.reader(fileobj)
    next(reader, None)   # pula cabeçalho: cve,epss,percentile
    for row in reader:
        if len(row) < 2:
            continue
        cve = str(row[0]).upper().strip()
        try:
            score = float(row[1])
        except ValueError:
            continue
        if score >= epss_threshold:
            epss_high[cve] = score
    return epss_high


def _fetch_epss_from_api_first(ctx: AppContext, epss_threshold: float) -> Dict[str, float]:
    """Busca scores EPSS via API FIRST (fallback paginado).

    Percorre todas as páginas e retorna apenas os CVEs com score >= threshold.
    """
    logger.warning(
        "[EPSS][API FIRST] Usando FIRST API como fallback paginado. "
        "Isso pode ser mais lento que o CSV diário."
    )
    epss_high: Dict[str, float] = {}
    offset = 0
    page_size = 1000
    total_fetched = 0

    while True:
        try:
            resp = ctx.session.get(
                EPSS_API_URL,
                params={"epss-gt": epss_threshold, "limit": page_size, "offset": offset},
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            payload = resp.json()
        except Exception as api_err:
            logger.error(f"[EPSS][API FIRST FAIL] Página offset={offset}: {api_err}")
            break

        data_items = payload.get("data", [])
        if not data_items:
            break

        for item in data_items:
            cve = str(item.get("cve", "")).upper().strip()
            try:
                score = float(item.get("epss", 0.0))
            except (ValueError, TypeError):
                continue
            if cve and score >= epss_threshold:
                epss_high[cve] = score

        total_fetched += len(data_items)
        total_available = int(payload.get("total", 0))
        offset += page_size
        if offset >= total_available or len(data_items) < page_size:
            break

    logger.info(
        f"[EPSS][API FIRST OK] {len(epss_high)} CVEs acima do threshold "
        f"{epss_threshold*100:.0f}% carregados via FIRST API "
        f"({total_fetched} registros paginados)."
    )
    return epss_high


def get_epss_data(ctx: AppContext) -> Dict[str, float]:
    """Baixa e retorna scores EPSS com resiliência em múltiplos níveis.

    Estratégia (Phase 3I.1):
      1. Cache JSON filtrado válido (resultado processado do último download bem-sucedido).
      2. CSV diário em disco (arquivo .csv.gz cacheado localmente com TTL de 24h).
      3. Download ao vivo do CSV streaming de epss.cyentia.com.
      4. FIRST API paginada (fallback REST, mais lento).
      5. Cache JSON expirado (stale) — dados antigos mas funcionais.
      6. Dict vazio com aviso crítico — degradação total sem exceção.
    """
    cache_key = f"epss_thresh_{ctx.epss_threshold}"

    # ── Nível 1: cache JSON filtrado quente ───────────────────────────────────
    if ctx.use_cache:
        cached = _read_cache(cache_key)
        if cached is not None:
            logger.info(
                f"[EPSS][CACHE HIT] EPSS filtrado carregado do cache local "
                f"({len(cached)} CVEs, threshold: {ctx.epss_threshold*100:.0f}%, "
                f"TTL: {CACHE_TTL_HOURS}h)."
            )
            return cached

    t0 = time.time()
    epss_high_risk: Dict[str, float] = {}
    source_used: str = "none"

    # ── Nível 2: CSV diário em disco ──────────────────────────────────────────
    csv_cache_path = _epss_csv_cache_path()
    if ctx.use_cache and _epss_csv_cache_is_valid():
        try:
            logger.info(
                f"[EPSS][CSV CACHE] Lendo CSV diário do EPSS do disco: {csv_cache_path} "
                f"(TTL: {EPSS_CSV_CACHE_TTL_HOURS}h)."
            )
            with gzip.open(csv_cache_path, "rt", encoding="utf-8") as f:
                epss_high_risk = _parse_epss_stream(f, ctx.epss_threshold)
            source_used = "csv_disk_cache"
            logger.info(
                f"[EPSS][CSV CACHE OK] {len(epss_high_risk)} CVEs filtrados do CSV em disco "
                f"(elapsed: {time.time()-t0:.2f}s)."
            )
        except Exception as csv_err:
            logger.warning(f"[EPSS][CSV CACHE FAIL] Falha ao ler CSV em disco: {csv_err}.")

    # ── Nível 3: download ao vivo do CSV streaming ───────────────────────────
    if not epss_high_risk:
        try:
            logger.info("[EPSS][LIVE CSV] Baixando CSV streaming do EPSS (epss.cyentia.com)...")
            t1 = time.time()
            with ctx.session.get(EPSS_URL, stream=True, timeout=REQUEST_TIMEOUT) as response:
                response.raise_for_status()
                # Salvar o raw gz em disco para reuso futuro (nível 2)
                if ctx.use_cache:
                    try:
                        raw_bytes = response.content  # leitura completa para dupla utilização
                        csv_cache_path.write_bytes(raw_bytes)
                        logger.info(f"[EPSS][CSV SAVED] CSV diário salvo em: {csv_cache_path}")
                        import io as _io
                        with gzip.GzipFile(fileobj=_io.BytesIO(raw_bytes)) as gzf:
                            with _io.TextIOWrapper(gzf, encoding="utf-8") as tf:
                                epss_high_risk = _parse_epss_stream(tf, ctx.epss_threshold)
                    except Exception as save_err:
                        logger.warning(f"[EPSS][CSV SAVE FAIL] Falha ao salvar CSV em disco: {save_err}. Parsing do stream original.")
                        # Fallback: re-baixar (ou parse do stream já consumido)
                        with gzip.GzipFile(fileobj=response.raw) as gzf:
                            with io.TextIOWrapper(gzf, encoding="utf-8") as tf:
                                epss_high_risk = _parse_epss_stream(tf, ctx.epss_threshold)
                else:
                    with gzip.GzipFile(fileobj=response.raw) as gzf:
                        with io.TextIOWrapper(gzf, encoding="utf-8") as tf:
                            epss_high_risk = _parse_epss_stream(tf, ctx.epss_threshold)
            source_used = "live_csv_stream"
            logger.info(
                f"[EPSS][LIVE CSV OK] {len(epss_high_risk)} CVEs filtrados do CSV ao vivo "
                f"(elapsed: {time.time()-t1:.2f}s)."
            )
        except Exception as live_err:
            logger.warning(
                f"[EPSS][LIVE CSV FAIL] Download ao vivo do CSV falhou: {live_err}. "
                "Tentando FIRST API..."
            )

            # ── Nível 4: FIRST API paginada ───────────────────────────────────
            try:
                epss_high_risk = _fetch_epss_from_api_first(ctx, ctx.epss_threshold)
                if epss_high_risk:
                    source_used = "first_api"
            except Exception as api_err:
                logger.error(f"[EPSS][FIRST API FAIL] Também falhou: {api_err}.")

    # ── Nível 5: stale cache JSON ──────────────────────────────────────────────
    if not epss_high_risk:
        stale = _read_stale_cache(cache_key)
        if stale is not None:
            source_used = "stale_cache"
            epss_high_risk = stale
        else:
            # ── Nível 6: degradação total ─────────────────────────────────────
            source_used = "empty_degraded"
            epss_high_risk = {}
            logger.critical(
                "[EPSS][DEGRADED] Nenhuma fonte EPSS disponível "
                "(CSV disco, live stream, FIRST API, stale cache). "
                "Análise prosseguirá SEM dados EPSS. "
                "Verifique conectividade ou popule o cache manualmente."
            )

    elapsed = time.time() - t0
    ctx.record_timing("epss_download", elapsed)
    logger.info(
        f"[EPSS][SUMMARY] Fonte usada: '{source_used}' | "
        f"{len(epss_high_risk)} CVEs >= {ctx.epss_threshold*100:.0f}% | "
        f"Tempo total: {elapsed:.2f}s."
    )

    # Persiste cache JSON filtrado apenas se veio de fonte online
    if ctx.use_cache and source_used in ("live_csv_stream", "first_api", "csv_disk_cache") and epss_high_risk:
        _write_cache(cache_key, epss_high_risk)
        logger.info(f"[EPSS][CACHE WRITE] Cache JSON filtrado salvo (fonte: {source_used}).")

    return epss_high_risk


def wazuh_api_base_url() -> str:
    return f"{SCHEME}://{WAZUH_MANAGER_IP}:{WAZUH_API_PORT}"


def get_wazuh_token(ctx: AppContext) -> str:
    # Verificar se o token ainda é válido (não expirou)
    if ctx.wazuh_token and ctx.wazuh_token_obtained_at:
        elapsed = time.time() - ctx.wazuh_token_obtained_at
        if elapsed < WAZUH_TOKEN_TTL_SECONDS:
            return ctx.wazuh_token
        logger.info("Token Wazuh expirado. Renovando...")
        ctx.wazuh_token = None

    try:
        response = ctx.session.get(
            f"{wazuh_api_base_url()}/security/user/authenticate",
            auth=(WAZUH_USER, ctx.wazuh_pass),
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(f"Erro de conexão com a API do Wazuh: {e}") from e
    except requests.exceptions.Timeout as e:
        raise RuntimeError(f"Timeout na autenticação com a API do Wazuh: {e}") from e

    if response.status_code == 401:
        raise RuntimeError("Credenciais inválidas para a API do Wazuh (HTTP 401).")
    if response.status_code != 200:
        raise RuntimeError(f"Erro de autenticação na API do Wazuh: HTTP {response.status_code} - {response.text}")

    ctx.wazuh_token = response.json()["data"]["token"]
    ctx.wazuh_token_obtained_at = time.time()
    return ctx.wazuh_token




def query_indexer_vulnerabilities(ctx: AppContext, agent_ids: List[str]) -> List[dict]:
    """Consulta vulnerabilidades no OpenSearch usando Scroll API para paginação completa."""
    t0 = time.time()
    url = f"{SCHEME}://{INDEXER_IP}:{INDEXER_PORT}/{VULN_INDEX_PATTERN}/_search?scroll={SCROLL_TIMEOUT}"
    query = {
        "size": SCROLL_PAGE_SIZE,
        "query": {
            "terms": {
                "agent.id": agent_ids,
            }
        },
    }

    try:
        response = ctx.session.post(
            url,
            json=query,
            auth=(INDEXER_USER, ctx.indexer_pass),
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(f"Erro de conexão com o Indexer/OpenSearch: {e}") from e
    except requests.exceptions.Timeout as e:
        raise RuntimeError(f"Timeout na consulta ao Indexer (limite: {REQUEST_TIMEOUT}s): {e}") from e

    if response.status_code == 401:
        raise RuntimeError("Credenciais inválidas para o Indexer/OpenSearch (HTTP 401).")
    if response.status_code != 200:
        raise RuntimeError(f"Erro na consulta ao Indexer: HTTP {response.status_code} - {response.text}")

    result = response.json()
    scroll_id = result.get("_scroll_id")
    hits = result.get("hits", {}).get("hits", [])
    all_hits = list(hits)

    # Paginação via Scroll API — buscar todas as páginas
    scroll_url = f"{SCHEME}://{INDEXER_IP}:{INDEXER_PORT}/_search/scroll"
    while len(hits) == SCROLL_PAGE_SIZE:
        try:
            scroll_response = ctx.session.post(
                scroll_url,
                json={"scroll": SCROLL_TIMEOUT, "scroll_id": scroll_id},
                auth=(INDEXER_USER, ctx.indexer_pass),
                timeout=REQUEST_TIMEOUT,
            )
            if scroll_response.status_code != 200:
                logger.warning(f"Erro durante scroll: HTTP {scroll_response.status_code}. Usando resultados parciais.")
                break
            scroll_result = scroll_response.json()
            scroll_id = scroll_result.get("_scroll_id")
            hits = scroll_result.get("hits", {}).get("hits", [])
            all_hits.extend(hits)
        except (requests.exceptions.RequestException, KeyError) as e:
            logger.warning(f"Erro durante paginação scroll: {e}. Usando resultados parciais ({len(all_hits)} registros).")
            break

    # Limpar o scroll context no servidor
    if scroll_id:
        try:
            ctx.session.delete(
                scroll_url,
                json={"scroll_id": scroll_id},
                auth=(INDEXER_USER, ctx.indexer_pass),
                timeout=10,
            )
        except requests.exceptions.RequestException:
            pass  # Não-crítico: o scroll expira automaticamente

    elapsed = time.time() - t0
    ctx.record_timing("indexer_query", elapsed)

    if len(all_hits) >= 50000:
        logger.warning(f"{YELLOW}[AVISO] Consulta retornou {len(all_hits)} registros. Considere filtrar por agentes específicos.{RESET}")

    return all_hits


def extract_record(hit: dict, cisa_kev: Dict[str, dict], epss_data: Dict[str, float]) -> Optional[VulnRecord]:
    source = hit.get("_source", {})
    agent = source.get("agent", {}) or {}
    vuln = source.get("vulnerability", {}) or {}
    pkg = source.get("package", {}) or {}

    cve_raw = vuln.get("id")
    if not cve_raw:
        return None

    cve = str(cve_raw).upper().strip()
    agent_id = str(agent.get("id", "N/A")).zfill(3) if str(agent.get("id", "")).isdigit() else str(agent.get("id", "N/A"))
    agent_name = str(agent.get("name") or KNOWN_AGENTS.get(agent_id, "N/A"))

    package_name = str(pkg.get("name") or vuln.get("category") or "Sistema Operacional").strip()
    version = str(pkg.get("version") or "N/A").strip()
    severity = str(vuln.get("severity") or "N/A").strip()

    cvss_score = None
    cvss3 = vuln.get("cvss3")
    if isinstance(cvss3, dict):
        cvss_score = cvss3.get("base_score") or cvss3.get("score")
    if cvss_score is None:
        cvss2 = vuln.get("cvss2")
        if isinstance(cvss2, dict):
            cvss_score = cvss2.get("base_score") or cvss2.get("score")
    if cvss_score is None:
        cvss_score = vuln.get("cvss", {}).get("score") if isinstance(vuln.get("cvss"), dict) else vuln.get("cvss")

    if cvss_score is None:
        sev_lower = severity.lower()
        if "critical" in sev_lower:
            cvss_score = 9.5
        elif "high" in sev_lower:
            cvss_score = 8.0
        elif "medium" in sev_lower:
            cvss_score = 5.5
        elif "low" in sev_lower:
            cvss_score = 2.5

    try:
        if cvss_score is not None:
            cvss_score = float(cvss_score)
    except (ValueError, TypeError):
        cvss_score = None

    is_kev = cve in cisa_kev
    is_ransomware = cisa_kev.get(cve, {}).get("ransomware", False) if is_kev else False

    return VulnRecord(
        agent_id=agent_id,
        agent_name=agent_name,
        cve=cve,
        package_name=package_name,
        version=version,
        severity=severity,
        cvss_score=cvss_score,
        is_kev=is_kev,
        is_ransomware=is_ransomware,
        epss_score=epss_data.get(cve), # Retorna None se estiver ausente/abaixo do threshold
    )


def classify_priority(record: VulnRecord, cvss_thresh: float, epss_thresh: float) -> str:
    if record.is_kev:
        return "Priority 1+"

    cvss = record.cvss_score or 0.0
    epss = record.epss_score or 0.0

    if cvss >= cvss_thresh and epss >= epss_thresh:
        return "Priority 1"
    elif cvss >= cvss_thresh and epss < epss_thresh:
        return "Priority 2"
    elif cvss < cvss_thresh and epss >= epss_thresh:
        return "Priority 3"
    else:
        return "Priority 4"


def analyze_vulnerabilities(
    ctx: AppContext,
    hits: Iterable[dict],
    cisa_kev: Dict[str, dict],
    epss_data: Dict[str, float],
) -> List[VulnRecord]:
    records: List[VulnRecord] = []
    seen_cves: Dict[Tuple[str, str], Set[str]] = {}  # (agent_id, package) -> set of CVEs já vistos
    duplicates_skipped = 0

    for hit in hits:
        record = extract_record(hit, cisa_kev, epss_data)
        if not record:
            continue

        # Deduplicação: mesmo CVE + agente + pacote = duplicado
        dedup_key = (record.agent_id, record.package_name)
        if dedup_key not in seen_cves:
            seen_cves[dedup_key] = set()
        if record.cve in seen_cves[dedup_key]:
            duplicates_skipped += 1
            continue
        seen_cves[dedup_key].add(record.cve)

        record.priority = classify_priority(record, ctx.cvss_threshold, ctx.epss_threshold)
        records.append(record)

    if duplicates_skipped > 0:
        logger.info(f"[DEDUP] {duplicates_skipped} registros duplicados removidos da análise.")

    return records



def format_priority_color(priority: str) -> str:
    if priority == "Priority 1+":
        return f"{RED}{BOLD}Priority 1+{RESET}"
    elif priority == "Priority 1":
        return f"{RED}Priority 1{RESET}"
    elif priority == "Priority 2":
        return f"{YELLOW}Priority 2{RESET}"
    elif priority == "Priority 3":
        return f"{YELLOW}Priority 3{RESET}"
    elif priority == "Priority 4":
        return f"{GREEN}Priority 4{RESET}"
    return priority


def print_findings(records: List[VulnRecord]) -> None:
    p1_plus = [r for r in records if r.priority == "Priority 1+"]
    p1 = [r for r in records if r.priority == "Priority 1"]
    p2 = [r for r in records if r.priority == "Priority 2"]
    p3 = [r for r in records if r.priority == "Priority 3"]
    p4 = [r for r in records if r.priority == "Priority 4"]

    print("\n" + "=" * 90)
    print("RESULTADO DO MOTOR DE INTELIGÊNCIA SOAR (HMG)")
    print("=" * 90)
    print(f"Priority 1+ (KEV Ativo)            : {len(p1_plus)}")
    print(f"Priority 1  (CVSS & EPSS Altos)     : {len(p1)}")
    print(f"Priority 2  (Apenas CVSS Alto)      : {len(p2)}")
    print(f"Priority 3  (Apenas EPSS Alto)      : {len(p3)}")
    print(f"Priority 4  (Baixo Risco imediato)  : {len(p4)}")
    print("=" * 90)

    top_threats = sorted(p1_plus + p1, key=lambda x: (x.priority != "Priority 1+", -(x.epss_score or 0.0)))
    if top_threats:
        print(f"\n{RED}{BOLD}[AMEAÇAS CRÍTICAS DETECTADAS - P1+ E P1]{RESET}")
        for r in top_threats[:60]:
            p_color = format_priority_color(r.priority)
            r_str = f" {RED}[RANSOMWARE]{RESET}" if r.is_ransomware else ""
            cvss_str = f"{r.cvss_score:.1f}" if r.cvss_score is not None else "N/A"
            epss_str = f"{r.epss_score*100:.1f}%" if r.epss_score is not None else "0.0%"
            print(f"  {p_color} | {r.agent_id} | {r.agent_name} | {r.cve} | CVSS {cvss_str} | EPSS {epss_str} | {r.package_name} {r.version}{r_str}")
        if len(top_threats) > 60:
            print(f"  ... {len(top_threats)-60} ameaças adicionais omitidas da tela.")

    p2_p3 = p2 + p3
    if p2_p3:
        print(f"\n{YELLOW}[VULNERABILIDADES DE RISCO MÉDIO/MODERADO - P2 E P3]{RESET}")
        for r in p2_p3[:30]:
            p_color = format_priority_color(r.priority)
            cvss_str = f"{r.cvss_score:.1f}" if r.cvss_score is not None else "N/A"
            epss_str = f"{r.epss_score*100:.1f}%" if r.epss_score is not None else "0.0%"
            print(f"  {p_color} | {r.agent_id} | {r.agent_name} | {r.cve} | CVSS {cvss_str} | EPSS {epss_str} | {r.package_name} {r.version}")
        if len(p2_p3) > 30:
            print(f"  ... {len(p2_p3)-30} registros adicionais omitidos da tela.")





def export_csv(records: List[VulnRecord], output_path: str) -> None:
    try:
        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                "Agent ID", "Agent Name", "CVE ID", "Priority",
                "CVSS Score", "Severity", "EPSS Score",
                "Package Name", "Version", "CISA KEV", "Ransomware Use"
            ])
            for r in records:
                writer.writerow([
                    r.agent_id, r.agent_name, r.cve, r.priority,
                    r.cvss_score if r.cvss_score is not None else "",
                    r.severity, r.epss_score if r.epss_score is not None else "",
                    r.package_name, r.version,
                    "TRUE" if r.is_kev else "FALSE",
                    "TRUE" if r.is_ransomware else "FALSE"
                ])
        print(f"[+] Relatório exportado com sucesso em CSV: {output_path}")
    except Exception as e:
        logger.error(f"Erro ao exportar CSV: {e}")


def export_pdf(
    ctx: AppContext,
    records: List[VulnRecord],
    output_path: str,
    agent_ids: List[str]
) -> None:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT
        from reportlab.pdfgen import canvas
    except ImportError:
        logger.warning("Biblioteca 'reportlab' não encontrada. Pulando geração do relatório PDF.")
        return

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            num_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self.draw_page_decorations(num_pages)
                super().showPage()
            super().save()

        def draw_page_decorations(self, page_count):
            self.saveState()
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#4a5568"))
            
            if self._pageNumber > 1:
                self.drawString(36, 765, "HMG Wazuh SOAR Brain - Relatório de Inteligência e Priorização")
                self.setStrokeColor(colors.HexColor("#cbd5e0"))
                self.setLineWidth(0.5)
                self.line(36, 757, 576, 757)
                
            page_text = f"Página {self._pageNumber} de {page_count}"
            self.drawRightString(576, 25, page_text)
            self.drawString(36, 25, f"HMG Wazuh Brain | Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            self.setStrokeColor(colors.HexColor("#cbd5e0"))
            self.setLineWidth(0.5)
            self.line(36, 35, 576, 35)
            
            self.restoreState()

    try:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=54,
            bottomMargin=54
        )

        styles = getSampleStyleSheet()
        normal_style = styles['Normal']

        title_style = ParagraphStyle(
            'DocTitle', parent=styles['Title'], fontName='Helvetica-Bold', fontSize=18,
            leading=22, textColor=colors.HexColor('#1a365d'), alignment=TA_LEFT, spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            'DocSubtitle', parent=normal_style, fontName='Helvetica', fontSize=10,
            leading=13, textColor=colors.HexColor('#4a5568'), spaceAfter=15
        )
        h1_style = ParagraphStyle(
            'Heading1_Custom', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=12,
            leading=16, textColor=colors.HexColor('#2b6cb0'), spaceBefore=12, spaceAfter=6, keepWithNext=True
        )
        body_style = ParagraphStyle(
            'Body_Custom', parent=normal_style, fontName='Helvetica', fontSize=9,
            leading=12, textColor=colors.HexColor('#2d3748'), spaceAfter=8
        )
        cell_style = ParagraphStyle(
            'CellText', parent=normal_style, fontName='Helvetica', fontSize=7.5, leading=9, textColor=colors.HexColor('#2d3748')
        )
        cell_header_style = ParagraphStyle(
            'CellHeader', parent=normal_style, fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=colors.white
        )

        p1_plus_style = ParagraphStyle('P1PlusStyle', parent=cell_style, fontName='Helvetica-Bold', textColor=colors.HexColor('#e53e3e'))
        p1_style = ParagraphStyle('P1Style', parent=cell_style, fontName='Helvetica-Bold', textColor=colors.HexColor('#dd6b20'))
        p2_style = ParagraphStyle('P2Style', parent=cell_style, textColor=colors.HexColor('#b7791f'))
        p3_style = ParagraphStyle('P3Style', parent=cell_style, textColor=colors.HexColor('#3182ce'))
        p4_style = ParagraphStyle('P4Style', parent=cell_style, textColor=colors.HexColor('#38a169'))

        story = []

        story.append(Paragraph("HMG Wazuh SOAR Brain - Relatório de Priorização", title_style))
        story.append(Paragraph("Análise integrada de vulnerabilidades usando CISA KEV e EPSS (CVSS Threshold)", subtitle_style))

        meta_data = [
            [
                Paragraph("<b>Data de Geração:</b>", cell_style), Paragraph(datetime.now().strftime('%d/%m/%Y %H:%M:%S'), cell_style),
                Paragraph("<b>Agentes Analisados:</b>", cell_style), Paragraph(", ".join(agent_ids), cell_style)
            ],
            [
                Paragraph("<b>Limiar CVSS:</b>", cell_style), Paragraph(f"&gt;= {ctx.cvss_threshold:.1f}", cell_style),
                Paragraph("<b>Limiar EPSS:</b>", cell_style), Paragraph(f"&gt;= {ctx.epss_threshold*100:.0f}%", cell_style)
            ]
        ]
        t_meta = Table(meta_data, colWidths=[110, 160, 110, 160])
        t_meta.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f7fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t_meta)
        story.append(Spacer(1, 15))

        p1_plus = [r for r in records if r.priority == "Priority 1+"]
        p1 = [r for r in records if r.priority == "Priority 1"]
        p2 = [r for r in records if r.priority == "Priority 2"]
        p3 = [r for r in records if r.priority == "Priority 3"]
        p4 = [r for r in records if r.priority == "Priority 4"]

        story.append(Paragraph("1. Resumo Executivo da Distribuição de Risco", h1_style))
        story.append(Paragraph(
            "O motor de inteligência SOAR do HMG avalia vulnerabilidades ativas em nosso parque tecnológico com base em ameaças conhecidas (CISA KEV) "
            "e probabilidade preditiva de exploração em larga escala (EPSS), estabelecendo cinco níveis de prioridade:",
            body_style
        ))

        summary_data = [
            [Paragraph("<b>Prioridade</b>", cell_header_style), Paragraph("<b>Critério / Descrição</b>", cell_header_style), Paragraph("<b>Qtd.</b>", cell_header_style)],
            [Paragraph("<b>Priority 1+</b>", p1_plus_style), Paragraph("Explorada ativamente na natureza (Consta no CISA KEV)", cell_style), Paragraph(str(len(p1_plus)), cell_style)],
            [Paragraph("<b>Priority 1</b>", p1_style), Paragraph(f"Ameaça crítica fora do KEV com CVSS &gt;= {ctx.cvss_threshold:.1f} e EPSS &gt;= {ctx.epss_threshold*100:.0f}%", cell_style), Paragraph(str(len(p1)), cell_style)],
            [Paragraph("<b>Priority 2</b>", p2_style), Paragraph(f"Ameaça de severidade alta com CVSS &gt;= {ctx.cvss_threshold:.1f} e baixo EPSS (&lt; {ctx.epss_threshold*100:.0f}%)", cell_style), Paragraph(str(len(p2)), cell_style)],
            [Paragraph("<b>Priority 3</b>", p3_style), Paragraph(f"Ameaça de severidade baixa/média com CVSS &lt; {ctx.cvss_threshold:.1f} e alto EPSS (&gt;= {ctx.epss_threshold*100:.0f}%)", cell_style), Paragraph(str(len(p3)), cell_style)],
            [Paragraph("<b>Priority 4</b>", p4_style), Paragraph("Baixo risco imediato de exploração (Abaixo de ambos os limiares)", cell_style), Paragraph(str(len(p4)), cell_style)]
        ]
        t_summary = Table(summary_data, colWidths=[100, 360, 80])
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a365d')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e0')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t_summary)
        story.append(Spacer(1, 15))

        story.append(Paragraph("2. Ameaças de Risco Crítico (Priority 1+ e Priority 1)", h1_style))
        story.append(Paragraph(
            "Vulnerabilidades classificadas como Priority 1+ e Priority 1 possuem altíssimo potencial de exploração em nossos servidores. "
            "Recomenda-se a aplicação emergencial de patches corretivos.",
            body_style
        ))

        top_threats = sorted(p1_plus + p1, key=lambda x: (x.priority != "Priority 1+", -(x.epss_score or 0.0)))
        if top_threats:
            threats_headers = [
                Paragraph("<b>Prioridade</b>", cell_header_style), Paragraph("<b>Agente</b>", cell_header_style),
                Paragraph("<b>CVE</b>", cell_header_style), Paragraph("<b>Pacote</b>", cell_header_style),
                Paragraph("<b>CVSS</b>", cell_header_style), Paragraph("<b>EPSS</b>", cell_header_style),
                Paragraph("<b>Ransomware</b>", cell_header_style)
            ]
            threats_rows = [threats_headers]
            for r in top_threats:
                p_style = p1_plus_style if r.priority == "Priority 1+" else p1_style
                ransom_text = '<font color="#e53e3e"><b>SIM (Ransomware)</b></font>' if r.is_ransomware else "Não"
                
                threats_rows.append([
                    Paragraph(r.priority, p_style),
                    Paragraph(f"{r.agent_id}<br/>{r.agent_name}", cell_style),
                    Paragraph(r.cve, cell_style),
                    Paragraph(f"{r.package_name}<br/>{r.version}", cell_style),
                    Paragraph(f"{r.cvss_score:.1f}" if r.cvss_score is not None else "N/A", cell_style),
                    Paragraph(f"{r.epss_score*100:.2f}%" if r.epss_score is not None else "0.00%", cell_style),
                    Paragraph(ransom_text, cell_style)
                ])

            t_threats = Table(threats_rows, colWidths=[65, 85, 75, 140, 45, 50, 80])
            t_threats.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d3748')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e0')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
                ('REPEATROWS', (0, 0), (0, 0)),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(t_threats)
        else:
            story.append(Paragraph("<i>Nenhuma vulnerabilidade crítica (Priority 1+ ou Priority 1) detectada para os agentes informados.</i>", body_style))

        story.append(Spacer(1, 15))

        story.append(Paragraph("3. Principais Riscos Moderados (Priority 2 e Priority 3)", h1_style))
        story.append(Paragraph(
            f"Vulnerabilidades classificadas como Priority 2 (CVSS alto, mas com baixo EPSS) e "
            f"Priority 3 (CVSS baixo, mas com alto EPSS). Mostrando as top 30 ordenadas por criticidade.",
            body_style
        ))

        p2_p3 = sorted(p2 + p3, key=lambda x: (x.priority != "Priority 2", -(x.cvss_score or 0.0)))
        if p2_p3:
            mod_headers = [
                Paragraph("<b>Prioridade</b>", cell_header_style), Paragraph("<b>Agente</b>", cell_header_style),
                Paragraph("<b>CVE</b>", cell_header_style), Paragraph("<b>Pacote</b>", cell_header_style),
                Paragraph("<b>CVSS</b>", cell_header_style), Paragraph("<b>EPSS</b>", cell_header_style)
            ]
            mod_rows = [mod_headers]
            for r in p2_p3[:30]:
                p_style = p2_style if r.priority == "Priority 2" else p3_style
                mod_rows.append([
                    Paragraph(r.priority, p_style),
                    Paragraph(f"{r.agent_id}<br/>{r.agent_name}", cell_style),
                    Paragraph(r.cve, cell_style),
                    Paragraph(f"{r.package_name}<br/>{r.version}", cell_style),
                    Paragraph(f"{r.cvss_score:.1f}" if r.cvss_score is not None else "N/A", cell_style),
                    Paragraph(f"{r.epss_score*100:.2f}%" if r.epss_score is not None else "0.00%", cell_style)
                ])

            t_mod = Table(mod_rows, colWidths=[70, 90, 80, 190, 50, 60])
            t_mod.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e0')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
                ('REPEATROWS', (0, 0), (0, 0)),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(t_mod)
            if len(p2_p3) > 30:
                story.append(Spacer(1, 5))
                story.append(Paragraph(f"<i>* Adicionalmente, {len(p2_p3)-30} vulnerabilidades de risco moderado foram omitidas do PDF. Consulte os outros relatórios.</i>", cell_style))
        else:
            story.append(Paragraph("<i>Nenhuma vulnerabilidade moderada (Priority 2 ou Priority 3) detectada.</i>", body_style))

        doc.build(story, canvasmaker=NumberedCanvas)
        print(f"[+] Relatório exportado com sucesso em PDF: {output_path}")
    except Exception as e:
        logger.error(f"Erro ao exportar PDF: {e}")


def render_html(ctx: AppContext, records: List[VulnRecord], agent_ids: List[str], mode: str) -> str:
    """Monta o HTML completo como string e retorna. Não grava em disco."""
    metadata = _build_report_metadata(ctx, records, agent_ids, mode)
    assets_data = load_assets_context()
    exposure_data = load_exposure_context()
    sla_policy = load_sla_policy()
    
    # Tentar inferir diretório de snapshots
    snapshots_dirs = [
        Path("/var/www/wazuh-soar/data/snapshots"),
        Path("./var/www/wazuh-soar/data/snapshots"),
        Path("data/snapshots")
    ]
    snapshots_dir = None
    for d in snapshots_dirs:
        if d.exists() and d.is_dir():
            snapshots_dir = d
            break
    if not snapshots_dir:
        snapshots_dir = Path("/var/www/wazuh-soar/data/snapshots")
        
    current_timestamp = metadata["generated_at"]
    
    # Mapear first_seen e occurrences por chave única
    first_seen_map = {}
    occurrences_map = {}
    first_seen_estimated_map = {}
    
    for r in records:
        if not r.cve:
            continue
        v_key = generate_vulnerability_key(r.cve, r.agent_id, r.package_name, r.severity)
        first_seen_map[v_key] = current_timestamp
        occurrences_map[v_key] = 1
        first_seen_estimated_map[v_key] = True
        
    if snapshots_dir.exists():
        snapshot_files = sorted(snapshots_dir.glob("snapshot_*.json"))
        vuln_timestamps = defaultdict(list)
        for f in snapshot_files:
            if not re.match(r"^snapshot_\d{8}_\d{6}\.json$", f.name):
                continue
            try:
                with open(f, "r", encoding="utf-8") as file:
                    data = json.load(file)
                ts = data.get("timestamp")
                if not ts:
                    continue
                for v in data.get("agent_vulnerabilities", []):
                    v_key = generate_vulnerability_key(v.get("cve"), v.get("agent_id"), v.get("package_name"), v.get("severity"))
                    vuln_timestamps[v_key].append(ts)
            except Exception:
                pass
                
        for r in records:
            if not r.cve:
                continue
            v_key = generate_vulnerability_key(r.cve, r.agent_id, r.package_name, r.severity)
            ts_list = vuln_timestamps.get(v_key, [])
            if ts_list:
                ts_list.sort()
                first_seen_map[v_key] = ts_list[0]
                first_seen_estimated_map[v_key] = (ts_list[0] == current_timestamp)
                unique_ts = set(ts_list)
                unique_ts.add(current_timestamp)
                occurrences_map[v_key] = len(unique_ts)
                
    near_due_threshold = sla_policy.get("near_due_threshold_days", 5)
    persistent_threshold = sla_policy.get("persistent_threshold_days", 30)
    recurring_threshold = sla_policy.get("recurring_threshold_count", 3)
    business_days = bool(sla_policy.get("business_days_only", False))

    vuln_list = []
    for r in records:
        context = get_asset_context(assets_data, r.agent_id, r.agent_name)
        expo_context = get_exposure_context(exposure_data, r.agent_id, r.agent_name)
        open_svcs = expo_context.get("open_services", [])
        top_svcs = [f"{s.get('service')}/{s.get('exposure')}" for s in open_svcs if s.get('service') and s.get('exposure')]
        
        v_key = generate_vulnerability_key(r.cve, r.agent_id, r.package_name, r.severity)
        f_seen = first_seen_map.get(v_key, current_timestamp)
        occ_count = occurrences_map.get(v_key, 1)
        est_flag = first_seen_estimated_map.get(v_key, True)
        
        age_days = calculate_days_difference(f_seen, current_timestamp, business_days)
        if age_days < 0:
            age_days = 0
            
        sla_days = calculate_sla_days(r.severity, r.is_kev, context, expo_context, sla_policy)
        due_date = add_days(f_seen, sla_days, business_days)
        days_to_due = calculate_days_difference(current_timestamp, due_date, business_days)
        
        if days_to_due < 0:
            sla_status = "overdue"
        elif 0 <= days_to_due <= near_due_threshold:
            sla_status = "due_soon"
        else:
            sla_status = "within_sla"
            
        persistent = (age_days >= persistent_threshold)
        recurring = (occ_count >= recurring_threshold)
        
        vuln_list.append({
            "agent_id": r.agent_id,
            "agent_name": r.agent_name,
            "cve": r.cve,
            "priority": r.priority,
            "cvss": r.cvss_score,
            "severity": r.severity,
            "epss": r.epss_score,
            "package": r.package_name,
            "version": r.version,
            "is_kev": r.is_kev,
            "is_ransomware": r.is_ransomware,
            "criticality": context.get("criticality", "unknown"),
            "environment": context.get("environment", "unknown"),
            "exposure": context.get("exposure", "unknown"),
            "asset_type": context.get("asset_type", "unknown"),
            "tags": context.get("tags", []),
            "hostname": context.get("asset_name", r.agent_name),
            "exposure_level": expo_context.get("exposure_level", "unknown"),
            "network_zone": expo_context.get("network_zone", "unknown"),
            "internet_facing": bool(expo_context.get("internet_facing", False)),
            "dmz": bool(expo_context.get("dmz", False)),
            "has_public_ip": bool(expo_context.get("has_public_ip", False)),
            "has_public_dns": bool(expo_context.get("has_public_dns", False)),
            "source": expo_context.get("source", "manual"),
            "confidence": expo_context.get("confidence", "low"),
            "top_services": top_svcs,
            # Novos campos Fase 3D
            "sla_status": sla_status,
            "due_date": due_date,
            "days_to_due": days_to_due,
            "age_days": age_days,
            "technical_owner": context.get("technical_owner", "unknown"),
            "business_owner": context.get("business_owner", "unknown"),
            "persistent": persistent,
            "recurring": recurring,
            "first_seen": f_seen,
            "snapshot_occurrences": occ_count
        })

    vuln_data_js = json.dumps(vuln_list, indent=2)

    html_content = HTML_TEMPLATE.replace("{{VULN_DATA}}", vuln_data_js)
    html_content = html_content.replace("{{GEN_TIME}}", metadata["generated_at"])
    html_content = html_content.replace("{{CVSS_THRESH}}", str(ctx.cvss_threshold))
    html_content = html_content.replace("{{EPSS_THRESH}}", str(ctx.epss_threshold))
    html_content = html_content.replace("{{{AGENTS_ANALYZED}}}", ", ".join(agent_ids))
    html_content = html_content.replace("{{{EXEC_MODE}}}", mode)
    html_content = html_content.replace("{{SCRIPT_VERSION}}", SCRIPT_VERSION)
    html_content = html_content.replace("{{TOTAL_UNIQUE_CVES}}", str(metadata["total_unique_cves"]))
    html_content = html_content.replace("{{TOTAL_AGENTS}}", str(metadata["total_agents"]))

    # Fase 3H.1 - hardening final de placeholders visíveis
    agents_label = ", ".join(agent_ids)
    for placeholder in ("{{{EXEC_MODE}}}", "{{EXEC_MODE}}", "{EXEC_MODE}"):
        html_content = html_content.replace(placeholder, str(mode))
    for placeholder in ("{{{AGENTS_ANALYZED}}}", "{{AGENTS_ANALYZED}}", "{AGENTS_ANALYZED}"):
        html_content = html_content.replace(placeholder, agents_label)

    return html_content


def export_html(ctx: AppContext, records: List[VulnRecord], output_path: str, agent_ids: List[str] = None, mode: str = "audit") -> None:
    """Gera HTML e grava em disco. Mantém compatibilidade com --html."""
    try:
        if agent_ids is None:
            agent_ids = list(set(r.agent_id for r in records))

        html_content = render_html(ctx, records, agent_ids, mode)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"[+] Relatório exportado com sucesso em HTML: {output_path}")
    except Exception as e:
        logger.error(f"Erro ao exportar HTML: {e}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HMG Wazuh KEV/EPSS checker com Priorização de 5 Níveis baseada no contexto regulatório."
    )
    parser.add_argument("--agent", help="ID do agente alvo. Ex: --agent 003 ou --agent 003,004")
    parser.add_argument("--all-agents", action="store_true", help="Consulta todos os agentes conhecidos.")
    parser.add_argument("--mode", choices=["audit"], default="audit", help="Modo analítico e passivo (padrão: audit).")
    parser.add_argument("--epss-threshold", type=float, default=DEFAULT_EPSS_THRESHOLD, help="Threshold EPSS (Default: 0.20).")
    parser.add_argument("--cvss-threshold", type=float, default=DEFAULT_CVSS_THRESHOLD, help="Threshold CVSS Base Score (Default: 6.0).")
    parser.add_argument("--output", "-o", help="Caminho do arquivo CSV para exportação.")
    parser.add_argument("--pdf", "-p", help="Caminho do arquivo PDF para exportação.")
    parser.add_argument("--html", "-w", help="Caminho do arquivo HTML interativo.")
    parser.add_argument("--no-cache", action="store_true", help="Desabilita cache local de CISA KEV e EPSS.")
    parser.add_argument("--clear-cache", action="store_true", help="Limpa o cache antes de executar.")

    # Novos argumentos para publicação web
    parser.add_argument(
        "--web-output-dir",
        help="Diretório para publicação web estática (ex: /var/www/wazuh-soar). "
             "Gera index.html + data/latest.json + cópia histórica em reports/."
    )
    parser.add_argument(
        "--web-group",
        default=DEFAULT_WEB_GROUP,
        help=f"Grupo do web server para permissões (default: {DEFAULT_WEB_GROUP}). "
             "Valores comuns: www-data, nginx, apache."
    )
    parser.add_argument(
        "--json-output",
        help="Caminho para exportar JSON com dados e metadados do relatório (ex: data/latest.json)."
    )

    args = parser.parse_args()

    # Validação de thresholds
    if not (0.0 <= args.epss_threshold <= 1.0):
        parser.error(f"--epss-threshold deve estar entre 0.0 e 1.0 (recebido: {args.epss_threshold})")
    if not (0.0 <= args.cvss_threshold <= 10.0):
        parser.error(f"--cvss-threshold deve estar entre 0.0 e 10.0 (recebido: {args.cvss_threshold})")

    # Validar que o grupo existe (se --web-output-dir foi passado)
    if args.web_output_dir and args.web_group:
        if _grp is not None:
            try:
                _grp.getgrnam(args.web_group)
            except KeyError:
                logger.warning(
                    f"[AVISO] Grupo '{args.web_group}' não encontrado no sistema. "
                    f"A publicação continuará sem ajuste de grupo. "
                    f"Grupos comuns: www-data, nginx, apache."
                )
                args.web_group = None
        else:
            logger.warning("[AVISO] Módulo 'grp' indisponível. Validação de grupo ignorada (ambiente Windows).")
            args.web_group = None

    # Recomendação de segurança para publicação web agendada
    if args.web_output_dir and args.mode != "audit":
        logger.warning(
            f"{YELLOW}[RECOMENDAÇÃO] Para publicação web agendada (cron/systemd timer), "
            f"use --mode audit para garantir conformidade e execução estritamente analítica.{RESET}"
        )

    return args


def print_execution_summary(ctx: AppContext, records: List[VulnRecord], total_start: float) -> None:
    """Imprime resumo de execução com métricas de tempo e estatísticas."""
    total_elapsed = time.time() - total_start

    print("\n" + "=" * 90)
    print("RESUMO DA EXECUÇÃO")
    print("=" * 90)
    print(f"  Tempo total de execução     : {total_elapsed:.1f}s")

    for label, elapsed in ctx.timings.items():
        label_fmt = label.replace("_", " ").title()
        print(f"  {label_fmt:<28}: {elapsed:.1f}s")

    unique_agents = set(r.agent_id for r in records)
    unique_cves = set(r.cve for r in records)
    print(f"  Agentes analisados          : {len(unique_agents)}")
    print(f"  CVEs únicos encontrados     : {len(unique_cves)}")
    print(f"  Total de registros          : {len(records)}")
    print("=" * 90)


def main() -> int:
    total_start = time.time()
    args = parse_args()

    # Gerenciar cache
    if args.clear_cache and CACHE_DIR.exists():
        shutil.rmtree(CACHE_DIR, ignore_errors=True)
        print("[*] Cache local limpo.")

    if args.all_agents:
        agent_ids = list(KNOWN_AGENTS.keys())
    else:
        agent_ids = normalize_agent_list(args.agent)
        if not agent_ids:
            agent_ids = choose_agents_interactively()

    print("\n" + "=" * 90)
    print("HMG WAZUH SOAR BRAIN - MOTOR DE PRIORIZAÇÃO")
    print("=" * 90)
    print(f"Início                 : {now()}")
    print(f"Agentes consultados    : {', '.join(agent_ids)}")
    print(f"Modo                   : {args.mode}")
    print(f"Thresholds configurados: CVSS >= {args.cvss_threshold} | EPSS >= {args.epss_threshold*100:.0f}%")
    print(f"Cache local            : {'desabilitado' if args.no_cache else 'habilitado'} (TTL: {CACHE_TTL_HOURS}h)")

    # Inicializa o contexto da aplicação para evitar escopo global mutável
    ctx = AppContext(
        cvss_threshold=args.cvss_threshold,
        epss_threshold=args.epss_threshold,
        use_cache=not args.no_cache,
    )

    require_passwords(ctx)

    print("\n[*] Baixando inteligência CISA KEV (com Ransomware mapping)...")
    cisa_kev_data = get_cisa_kev(ctx)
    print(f"[+] KEV carregado: {len(cisa_kev_data)} CVEs.")

    print("[*] Baixando modelo preditivo EPSS via streaming...")
    epss_dict = get_epss_data(ctx)
    print(f"[+] EPSS filtrado carregado: {len(epss_dict)} CVEs ativos.")

    print("[*] Consultando OpenSearch/Wazuh Indexer (com paginação scroll)...")
    hits = query_indexer_vulnerabilities(ctx, agent_ids)
    print(f"[+] Consulta concluída. Registros brutos processados: {len(hits)}")

    records = analyze_vulnerabilities(ctx, hits, cisa_kev_data, epss_dict)

    print_findings(records)

    csv_path = args.output or "relatorio_wazuh.csv"
    pdf_path = args.pdf or "relatorio_wazuh.pdf"
    html_path = args.html or "relatorio_wazuh.html"

    print("\n[*] Gerando relatórios de auditoria...")
    export_csv(records, csv_path)
    export_pdf(ctx, records, pdf_path, agent_ids)
    export_html(ctx, records, html_path, agent_ids, args.mode)
    print("[+] Todos os relatórios foram gerados e salvos!")

    # Exportação JSON independente (--json-output)
    if args.json_output:
        export_json(ctx, records, agent_ids, args.mode, args.json_output, args.web_group)

    # Publicação web estática (--web-output-dir)
    if args.web_output_dir:
        print(f"\n[*] Publicando relatório web em: {args.web_output_dir}")
        html_for_web = render_html(ctx, records, agent_ids, args.mode)

        # Gerar JSON para publicação web
        metadata = _build_report_metadata(ctx, records, agent_ids, args.mode)
        vuln_list = []
        for r in records:
            vuln_list.append({
                "agent_id": r.agent_id,
                "agent_name": r.agent_name,
                "cve": r.cve,
                "priority": r.priority,
                "cvss": r.cvss_score,
                "severity": r.severity,
                "epss": r.epss_score,
                "package": r.package_name,
                "version": r.version,
                "is_kev": r.is_kev,
                "is_ransomware": r.is_ransomware,
            })
        json_payload = json.dumps({"metadata": metadata, "vulnerabilities": vuln_list}, indent=2, ensure_ascii=False)

        # Gerar inteligência de risco (Fase 3A)
        generate_risk_intelligence(ctx, records, agent_ids, args.web_output_dir, args.web_group)

        success = publish_to_web(html_for_web, json_payload, args.web_output_dir, args.web_group)
        if not success:
            logger.error("[ERRO] Publicação web falhou. Relatórios locais foram gerados normalmente.")

    print_execution_summary(ctx, records, total_start)

    print("\nFim da execução.")
    return 0


# ==========================================
# TEMPLATE HTML INTERATIVO (DESIGN PREMIUM)
# ==========================================
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Painel Interativo de Vulnerabilidades - HMG Wazuh SOAR</title>
  <style>
    :root {
      /* EyeMole Palette (Logo Core) */
      --eyemole-bg-deep: #030711;
      --eyemole-bg-panel: #0b1220;
      --eyemole-surface: #101827;
      --eyemole-surface-soft: #131d2e;

      --eyemole-cyan: #78f7ff;
      --eyemole-cyan-strong: #2de2f2;
      --eyemole-aqua: #9afcff;

      --eyemole-magenta: #f59df4;
      --eyemole-pink: #ff6fd8;
      --eyemole-violet: #9b7cff;
      --eyemole-blue: #3b82f6;

      --eyemole-border: rgba(120, 247, 255, 0.16);
      --eyemole-border-pink: rgba(245, 157, 244, 0.14);
      --eyemole-glow-cyan: rgba(120, 247, 255, 0.12);
      --eyemole-glow-pink: rgba(245, 157, 244, 0.10);

      /* Tons harmonizados de alerta da marca */
      --eyemole-alert: #ffb86b;
      --eyemole-critical: #ff6f91;

      /* Theme Mapping */
      --bg-color: var(--eyemole-bg-deep);
      --card-bg: var(--eyemole-bg-panel);
      --border-color: var(--eyemole-border);
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --primary: var(--eyemole-cyan-strong);

      /* Semantic Severity Colors */
      --p1plus: #ef4444;
      --p1: #f97316;
      --p2: #eab308;
      --p3: #22d3ee;
      --p4: #10b981;

      /* Design tokens — spacing */
      --space-xs: 0.25rem;
      --space-sm: 0.5rem;
      --space-md: 1rem;
      --space-lg: 1.5rem;
      --space-xl: 2rem;
      --space-2xl: 3rem;

      /* Design tokens — border-radius */
      --radius-sm: 6px;
      --radius-md: 10px;
      --radius-lg: 14px;
      --radius-xl: 20px;

      /* Design tokens — shadows & glows */
      --shadow-sm: 0 2px 4px rgba(0, 0, 0, 0.2);
      --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.3);
      --shadow-lg: 0 8px 24px rgba(0, 0, 0, 0.4);
      --shadow-glow-blue: 0 0 16px rgba(120, 247, 255, 0.08);
      --shadow-glow-purple: 0 0 16px rgba(155, 124, 255, 0.08);
      --shadow-glow-red: 0 0 16px rgba(239, 68, 68, 0.08);

      /* Design tokens — transitions */
      --transition-fast: 0.15s ease;
      --transition-normal: 0.25s ease;
      --transition-slow: 0.4s cubic-bezier(0.4, 0, 0.2, 1);

      /* Design tokens — surfaces mapping */
      --surface-1: var(--eyemole-bg-panel);
      --surface-2: var(--eyemole-surface);
      --surface-3: var(--eyemole-surface-soft);
      --border-subtle: rgba(120, 247, 255, 0.06);
      --border-medium: var(--eyemole-border);
      --border-strong: rgba(120, 247, 255, 0.28);
    }
    
    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    html { scroll-behavior: smooth; }

    body {
      background-color: var(--bg-color);
      background-image:
        radial-gradient(circle at 50% -10%, var(--eyemole-glow-cyan), transparent 35%),
        radial-gradient(circle at 80% 8%, var(--eyemole-glow-pink), transparent 30%);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.5;
      padding: 2rem;
      min-height: 100vh;
    }

    /* Global scrollbar — premium thin dark */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(120, 247, 255, 0.1); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(120, 247, 255, 0.25); }
    * { scrollbar-width: thin; scrollbar-color: rgba(120, 247, 255, 0.1) transparent; }

    .container { max-width: 1440px; margin: 0 auto; }
    header {
      margin-bottom: var(--space-xl);
      display: flex;
      flex-direction: column;
      align-items: center;
      padding-bottom: var(--space-lg);
      position: relative;
      gap: var(--space-md);
    }
    header::after {
      content: '';
      position: absolute;
      bottom: 0;
      left: 0;
      right: 0;
      height: 2px;
      background: linear-gradient(90deg, transparent, var(--eyemole-cyan) 30%, var(--eyemole-violet) 50%, var(--eyemole-magenta) 70%, transparent);
    }
    @keyframes headerGradient { 0% { background-position: 0% 50%; } 100% { background-position: 200% 50%; } }
    h1 { font-size: 1.85rem; font-weight: 800; letter-spacing: -0.03em; background: linear-gradient(135deg, var(--eyemole-cyan), var(--eyemole-violet), var(--eyemole-magenta)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; margin-bottom: 0.25rem; }
    .subtitle { color: var(--text-muted); font-size: 0.85rem; letter-spacing: 0.01em; }
    .meta-badges { display: flex; gap: 0.55rem; flex-wrap: wrap; align-items: center; justify-content: center; }
    .meta-badge {
      background: rgba(16, 24, 39, 0.6);
      border: 1px solid rgba(120, 247, 255, 0.12);
      padding: 0.35rem 0.85rem;
      border-radius: 50px;
      font-size: 0.75rem;
      color: var(--text-muted);
      transition: all var(--transition-fast);
      backdrop-filter: blur(4px);
    }
    .meta-badge:hover {
      border-color: var(--eyemole-cyan);
      background: rgba(16, 24, 39, 0.85);
      color: var(--text-main);
      box-shadow: 0 0 10px rgba(120, 247, 255, 0.1);
      transform: translateY(-1px);
    }
    .meta-badge strong { color: var(--eyemole-cyan); }

    .grid-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: var(--space-md); margin-bottom: var(--space-xl); }
    .metric-card {
      background: var(--eyemole-surface);
      border: 1px solid rgba(120, 247, 255, 0.08);
      border-left: none !important;
      border-radius: var(--radius-md);
      padding: 1.1rem 1.2rem;
      cursor: pointer;
      transition: all var(--transition-normal);
      position: relative;
      overflow: hidden;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }
    .metric-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 4px;
      height: 100%;
      background: var(--eyemole-cyan);
    }
    .metric-card:hover {
      border-color: rgba(120, 247, 255, 0.24);
      transform: translateY(-2px);
      box-shadow: 0 8px 16px -2px rgba(0, 0, 0, 0.3), 0 0 12px rgba(120, 247, 255, 0.06);
    }
    .metric-card.active { border-color: var(--eyemole-cyan); }

    /* Estilização individual dos cards e números (Identidade EyeMole) */
    .metric-card:has(#overview-total-vulns)::before {
      background: linear-gradient(180deg, var(--eyemole-cyan), var(--eyemole-aqua));
    }
    #overview-total-vulns { color: var(--eyemole-cyan) !important; }

    .metric-card:has(#overview-risk-critical)::before {
      background: linear-gradient(180deg, var(--eyemole-critical), var(--eyemole-pink));
    }
    #overview-risk-critical { color: var(--eyemole-pink) !important; }

    .metric-card:has(#overview-risk-high)::before {
      background: linear-gradient(180deg, var(--eyemole-alert), var(--eyemole-magenta));
    }
    #overview-risk-high { color: var(--eyemole-magenta) !important; }

    .metric-card:has(#overview-risk-kev)::before {
      background: linear-gradient(180deg, var(--eyemole-cyan), var(--eyemole-violet));
    }
    #overview-risk-kev { color: var(--eyemole-cyan) !important; }

    .metric-card:has(#overview-risk-epss)::before {
      background: linear-gradient(180deg, var(--eyemole-violet), var(--eyemole-pink));
    }
    #overview-risk-epss { color: var(--eyemole-violet) !important; }

    .metric-card:has(#overview-risk-agents)::before {
      background: linear-gradient(180deg, var(--eyemole-blue), var(--eyemole-cyan));
    }
    #overview-risk-agents { color: var(--eyemole-blue) !important; }

    .metric-card:has(#overview-sla-status)::before {
      background: linear-gradient(180deg, var(--eyemole-critical), var(--eyemole-cyan));
    }
    #overview-sla-status { color: var(--eyemole-pink) !important; }

    .metric-card:has(#overview-actionable-priorities)::before {
      background: linear-gradient(180deg, var(--eyemole-cyan), var(--eyemole-aqua));
    }
    #overview-actionable-priorities { color: var(--eyemole-aqua) !important; }

    .metric-card:has(#overview-trend-health)::before {
      background: linear-gradient(180deg, var(--eyemole-violet), var(--eyemole-magenta));
    }
    #overview-trend-health { color: var(--eyemole-magenta) !important; }

    .metric-card:has(#overview-treatment-now)::before {
      background: linear-gradient(180deg, var(--eyemole-critical), var(--eyemole-pink));
    }
    #overview-treatment-now { color: var(--eyemole-pink) !important; }

    .metric-card:has(#overview-status-api)::before {
      background: linear-gradient(180deg, var(--eyemole-cyan), var(--eyemole-blue));
    }
    #overview-status-api { color: var(--eyemole-cyan) !important; }

    .metric-card:has(#overview-generation-age)::before {
      background: linear-gradient(180deg, var(--eyemole-cyan), var(--eyemole-surface-soft));
    }
    #overview-generation-age { color: var(--eyemole-cyan) !important; }
    .metric-title { font-size: 0.75rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .metric-value { font-size: 1.75rem; font-weight: 700; letter-spacing: -0.02em; margin-top: 0.3rem; line-height: 1; font-variant-numeric: tabular-nums; transition: opacity var(--transition-fast); }

    /* Skeleton loading shimmer */
    @keyframes shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
    .skeleton { background: linear-gradient(90deg, rgba(148,163,184,0.05) 25%, rgba(148,163,184,0.12) 50%, rgba(148,163,184,0.05) 75%); background-size: 200% 100%; animation: shimmer 1.8s ease-in-out infinite; border-radius: var(--radius-sm); }
    .skeleton-text { height: 1em; width: 60%; display: inline-block; }
    .skeleton-value { height: 2rem; width: 40%; display: inline-block; margin-top: 0.25rem; }

    .toolbar { background: var(--surface-2); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: var(--space-md) var(--space-lg); margin-bottom: var(--space-lg); display: flex; flex-wrap: wrap; gap: var(--space-md); align-items: center; justify-content: space-between; }
    .search-wrapper { position: relative; flex: 1; min-width: 300px; }
    .search-input {
      width: 100%;
      background: rgba(3, 7, 17, 0.6);
      border: 1px solid rgba(120, 247, 255, 0.16);
      border-radius: 8px;
      padding: 0.6rem 1rem 0.6rem 2.5rem;
      color: var(--text-main);
      font-family: inherit;
      font-size: 0.9rem;
      transition: all var(--transition-fast);
    }
    .search-input:focus {
      border-color: var(--eyemole-cyan);
      outline: none;
      box-shadow: 0 0 10px rgba(120, 247, 255, 0.15);
      background: rgba(3, 7, 17, 0.8);
    }
    .search-icon { position: absolute; left: 0.8rem; top: 50%; transform: translateY(-50%); color: var(--text-muted); pointer-events: none; }
    .checkbox-filters { display: flex; gap: 1.25rem; align-items: center; }
    .checkbox-label { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; font-size: 0.85rem; color: var(--text-muted); }
    .btn-group { display: flex; gap: 0.5rem; }
    .btn {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(120, 247, 255, 0.15);
      color: var(--text-muted);
      padding: 0.6rem 1.1rem;
      border-radius: 8px;
      cursor: pointer;
      font-family: inherit;
      font-size: 0.85rem;
      font-weight: 600;
      transition: all var(--transition-fast);
    }
    .btn:hover {
      background: rgba(120, 247, 255, 0.08);
      color: var(--text-main);
      border-color: rgba(120, 247, 255, 0.3);
    }
    .btn-primary {
      background: linear-gradient(135deg, var(--eyemole-cyan-strong), var(--eyemole-violet));
      border: none;
      color: #030711;
      font-weight: 700;
      box-shadow: 0 2px 8px rgba(45, 226, 242, 0.2);
    }
    .btn-primary:hover {
      background: linear-gradient(135deg, var(--eyemole-cyan), var(--eyemole-violet));
      color: #030711;
      box-shadow: 0 4px 14px rgba(45, 226, 242, 0.35);
      transform: translateY(-1px);
    }

    .table-container {
      background: var(--eyemole-bg-panel);
      border: 1px solid rgba(120, 247, 255, 0.1);
      border-radius: var(--radius-lg);
      overflow-x: auto;
      margin-bottom: var(--space-lg);
    }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.83rem; }
    th, td { padding: 0.85rem 1.1rem; border-bottom: 1px solid rgba(120, 247, 255, 0.06); }
    th {
      background: rgba(11, 18, 32, 0.95);
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      font-size: 0.7rem;
      letter-spacing: 0.04em;
      cursor: pointer;
      position: sticky;
      top: 0;
      z-index: 2;
      transition: color var(--transition-fast);
    }
    th:hover { color: var(--eyemole-cyan); }
    th[data-sort-active] { color: var(--eyemole-cyan); }
    tr { transition: background var(--transition-fast); }
    tbody tr:nth-child(even) { background: rgba(120, 247, 255, 0.01); }
    tbody tr:hover { background: rgba(120, 247, 255, 0.04); }
    td { color: var(--text-main); }

    .badge { display: inline-flex; align-items: center; font-size: 0.75rem; font-weight: 600; padding: 0.25rem 0.5rem; border-radius: 6px; text-transform: uppercase; }
    .badge-p1plus { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-p1 { background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }
    .badge-p2 { background: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }
    .badge-p3 { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
    .badge-p4 { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-ransomware { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); font-weight: 700; }
    .badge-kev { background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4); }

    .score { font-weight: 600; }
    .score-high { color: #f87171; }
    .score-medium { color: #fb923c; }
    .score-low { color: #facc15; }
    .score-none { color: var(--text-muted); }

    .pagination-bar { display: flex; justify-content: space-between; align-items: center; margin-top: 1rem; font-size: 0.85rem; color: var(--text-muted); }
    .page-controls { display: flex; gap: 0.25rem; }
    .page-btn { background: var(--card-bg); border: 1px solid var(--border-color); color: var(--text-main); width: 32px; height: 32px; border-radius: 6px; display: flex; align-items: center; justify-content: center; cursor: pointer; }
    .page-btn.active { background: var(--primary); border-color: transparent; font-weight: 600; }
    .page-btn.disabled { opacity: 0.3; cursor: not-allowed; }
    .page-size-selector { background: var(--card-bg); border: 1px solid var(--border-color); color: var(--text-main); padding: 0.3rem 0.5rem; border-radius: 6px; }
    .empty-state { padding: 4rem 2rem; text-align: center; color: var(--text-muted); font-size: 0.9rem; }
    .empty-state svg { opacity: 0.3; margin-bottom: var(--space-md); }

    /* Typography & spacing rhythm */
    .section-title { font-size: 1.15rem; font-weight: 700; color: var(--text-main); margin-top: var(--space-2xl); margin-bottom: var(--space-lg); padding-bottom: var(--space-sm); border-bottom: 1px solid var(--border-subtle); letter-spacing: -0.01em; }
    .section-subtitle { font-size: 0.9rem; font-weight: 600; color: var(--text-muted); margin-bottom: var(--space-md); }
    .section-gap { margin-bottom: var(--space-xl); }
    .section-gap-sm { margin-bottom: var(--space-lg); }

    /* Botão Executar Análise */
    .btn-run {
      background: linear-gradient(135deg, var(--eyemole-cyan-strong), var(--eyemole-violet));
      border: none;
      color: #030711;
      padding: 0.7rem 1.5rem;
      border-radius: 8px;
      cursor: pointer;
      font-family: inherit;
      font-size: 0.9rem;
      font-weight: 700;
      transition: all 0.25s ease;
      box-shadow: 0 2px 8px rgba(45, 226, 242, 0.2);
    }
    .btn-run:hover:not(:disabled) {
      transform: translateY(-1px);
      box-shadow: 0 4px 14px rgba(45, 226, 242, 0.35);
      background: linear-gradient(135deg, var(--eyemole-cyan), var(--eyemole-violet));
    }
    .btn-run:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
    .btn-run.running { background: linear-gradient(135deg, #d97706, #dc2626); animation: pulse-btn 1.5s infinite; }
    @keyframes pulse-btn { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
    .run-status { font-size: 0.85rem; color: var(--text-muted); font-weight: 500; }
    .run-status.success { color: #10b981; }
    .run-status.error { color: #ef4444; }
    .run-status.running { color: #f59e0b; }

    /* Pie charts — layout premium (EyeMole) */
    .pie-chart-layout {
      display: grid;
      grid-template-columns: minmax(150px, 205px) 1fr;
      align-items: center;
      gap: 1.25rem;
      width: 100%;
      height: 100%;
      padding: 0.2rem 0.4rem;
    }
    .pie-svg { width: 100%; max-width: 205px; height: 100%; max-height: 165px; display: block; }
    .pie-slice { transition: opacity 0.3s ease; }
    .pie-chart-layout:hover .pie-slice { opacity: 0.92; }
    .pie-chart-layout .pie-slice:hover { opacity: 1; }
    .pie-legend { display: grid; gap: 0.5rem; align-content: center; min-width: 120px; }
    .pie-legend-row {
      display: grid; grid-template-columns: 10px 1fr auto; gap: 0.55rem;
      align-items: center; font-size: 0.78rem; line-height: 1.2;
    }
    .pie-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
    .pie-label {
      color: var(--text-muted); font-weight: 500;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .pie-value { font-weight: 700; color: var(--text-main); font-variant-numeric: tabular-nums; white-space: nowrap; }
    .pie-pct { font-weight: 400; color: var(--text-muted); font-size: 0.72rem; }
    @media (max-width: 540px) {
      .pie-chart-layout { grid-template-columns: 1fr; gap: 0.6rem; justify-items: center; }
      .pie-svg { max-width: 160px; }
      .pie-legend { width: 100%; max-width: 240px; }
    }

    /* SVG Chart polish */
    @keyframes chartFadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
    svg text { font-family: inherit; }
    .chart-container { animation: chartFadeIn 0.5s ease-out; }
    .chart-container svg { max-width: 100%; height: auto; }
    .chart-tooltip { background: var(--surface-3); border: 1px solid var(--border-medium); border-radius: var(--radius-sm); padding: 0.4rem 0.6rem; font-size: 0.75rem; color: var(--text-main); box-shadow: var(--shadow-md); pointer-events: none; }

    /* Loading & error states */
    .loading-overlay { display: flex; align-items: center; justify-content: center; min-height: 120px; color: var(--text-muted); font-size: 0.85rem; gap: var(--space-sm); }
    .loading-spinner { width: 18px; height: 18px; border: 2px solid var(--border-medium); border-top-color: var(--primary); border-radius: 50%; animation: spin 0.8s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .widget-error { background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.15); border-radius: var(--radius-md); padding: var(--space-lg); text-align: center; color: #f87171; font-size: 0.85rem; }
    .widget-error::before { content: '⚠'; display: block; font-size: 1.5rem; margin-bottom: var(--space-sm); opacity: 0.6; }
    .widget-empty { background: var(--surface-1); border: 1px dashed var(--border-medium); border-radius: var(--radius-md); padding: var(--space-2xl) var(--space-xl); text-align: center; color: var(--text-muted); font-size: 0.85rem; }
    .widget-empty::before { content: '📋'; display: block; font-size: 2rem; margin-bottom: var(--space-sm); opacity: 0.4; }
    .fade-in { animation: chartFadeIn 0.3s ease-out; }
    .fade-out { opacity: 0; transition: opacity var(--transition-fast); }

    /* Links & accessibility */
    .cve-link { color: var(--eyemole-cyan); text-decoration: none; font-weight: 600; transition: color var(--transition-fast); }
    .cve-link:hover { color: var(--eyemole-cyan-strong); text-decoration: underline; }
    .cve-link:focus-visible { outline: 2px solid var(--eyemole-cyan); outline-offset: 2px; border-radius: 2px; }
    :focus-visible { outline: 2px solid var(--eyemole-cyan); outline-offset: 2px; }
    ::selection { background: rgba(34, 211, 238, 0.25); color: var(--text-main); }    /* Inteligência de Risco (Fase 3A) */
    .grid-risk-seven { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem; }
    .risk-card {
      background: var(--eyemole-surface);
      border: 1px solid rgba(120, 247, 255, 0.08);
      border-radius: 10px;
      padding: 1rem;
      position: relative;
      overflow: hidden;
      transition: all var(--transition-normal);
    }
    .risk-card:hover {
      border-color: rgba(120, 247, 255, 0.24);
      transform: translateY(-2px);
      box-shadow: 0 8px 16px -2px rgba(0, 0, 0, 0.3), 0 0 12px rgba(120, 247, 255, 0.06);
    }
    .risk-card::before { content: ''; position: absolute; top: 0; left: 0; width: 3px; height: 100%; }
    .risk-card.total::before { background: var(--text-muted); }
    .risk-card.critico::before { background: var(--eyemole-critical); }
    .risk-card.alto::before { background: var(--eyemole-alert); }
    .risk-card.kev::before { background: #f59e0b; }
    .risk-card.epss::before { background: #a78bfa; }
    .risk-card.agentes::before { background: #3b82f6; }
    .risk-card.idade::before { background: #10b981; }
    
    .alert-container { display: flex; flex-direction: column; gap: 0.5rem; margin-bottom: 1.5rem; }
    .alert-item { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1rem; border-radius: 8px; font-size: 0.85rem; border-left: 4px solid transparent; }
    .alert-critical { background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.15); border-left-color: #ef4444; color: #f87171; }
    .alert-warning { background: rgba(234, 179, 8, 0.06); border: 1px solid rgba(234, 179, 8, 0.12); border-left-color: #eab308; color: #facc15; }
    .alert-info { background: rgba(59, 130, 246, 0.06); border: 1px solid rgba(59, 130, 246, 0.12); border-left-color: #3b82f6; color: #60a5fa; }
    
    .delta-badge-new { background: rgba(239, 68, 68, 0.1); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.2); }
    .delta-badge-resolved { background: rgba(16, 185, 129, 0.1); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.2); }
    .badge-overdue { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-due-soon { background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }
    .badge-within-sla { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-persistent { background: rgba(167, 139, 250, 0.15); color: #c084fc; border: 1px solid rgba(167, 139, 250, 0.3); }
    .badge-recurring { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
    .sla-card-overdue::before { background: var(--p1plus) !important; }
    .sla-card-due-soon::before { background: var(--p1) !important; }
    .sla-card-within-sla::before { background: var(--p4) !important; }
    .sla-card-persistent::before { background: #a78bfa !important; }
    .sla-card-recurring::before { background: #3b82f6 !important; }

    .tab-nav {
      position: sticky;
      top: 0;
      z-index: 50;
      display: flex;
      flex-wrap: wrap;
      gap: 0;
      align-items: stretch;
      overflow-x: auto;
      scrollbar-width: none;
      padding: 0;
      margin: var(--space-lg) 0;
      background: rgba(11, 18, 32, 0.85);
      backdrop-filter: blur(8px);
      border: 1px solid rgba(120, 247, 255, 0.12);
      border-radius: var(--radius-md);
    }
    .tab-nav::-webkit-scrollbar {
      display: none;
    }
    .table-container {
      scrollbar-width: thin;
      scrollbar-color: rgba(120, 247, 255, 0.1) transparent;
    }
    .table-container::-webkit-scrollbar {
      height: 6px;
      width: 6px;
    }
    .table-container::-webkit-scrollbar-track {
      background: transparent;
    }
    .table-container::-webkit-scrollbar-thumb {
      background: rgba(120, 247, 255, 0.12);
      border-radius: 3px;
    }
    .table-container::-webkit-scrollbar-thumb:hover {
      background: rgba(120, 247, 255, 0.28);
    }

    .tab-btn {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      border: none;
      background: transparent;
      color: var(--text-muted);
      padding: 0.8rem 1.15rem;
      border-radius: 0;
      font-weight: 600;
      font-size: 0.8rem;
      cursor: pointer;
      white-space: nowrap;
      transition: all var(--transition-fast);
      position: relative;
      letter-spacing: 0.01em;
    }
    .tab-btn .tab-ico {
      width: 15px;
      height: 15px;
      opacity: 0.6;
      flex-shrink: 0;
      transition: opacity var(--transition-fast), stroke var(--transition-fast);
    }

    .tab-btn:hover {
      background: rgba(120, 247, 255, 0.04);
      color: var(--text-main);
    }
    .tab-btn:hover .tab-ico { opacity: 0.9; stroke: var(--eyemole-cyan); }

    .tab-btn:focus-visible {
      outline: 2px solid var(--eyemole-cyan);
      outline-offset: 2px;
    }

    .tab-btn.active {
      background: rgba(120, 247, 255, 0.06);
      color: var(--eyemole-cyan);
      font-weight: 700;
    }
    .tab-btn.active::after {
      content: '';
      position: absolute;
      bottom: 0;
      left: 0;
      right: 0;
      height: 2px;
      background: linear-gradient(90deg, var(--eyemole-cyan), var(--eyemole-violet), var(--eyemole-magenta));
    }
    .tab-btn.active .tab-ico { opacity: 1; stroke: var(--eyemole-cyan); }

    .tab-panel {
      display: none !important;
    }

    .tab-panel.active {
      display: block !important;
      animation: tabFadeIn 0.22s ease-out;
    }

    @keyframes tabFadeIn {
      from {
        opacity: 0;
        transform: translateY(8px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    /* Branding */
    .brand-area { display: flex; align-items: center; justify-content: center; min-width: 0; }
    .brand-logo {
      display: block;
      width: auto;
      height: 200px;
      max-height: 200px;
      object-fit: contain;
      filter:
        drop-shadow(0 0 10px rgba(120, 247, 255, 0.22))
        drop-shadow(0 0 18px rgba(245, 157, 244, 0.14));
      transition: filter var(--transition-normal);
    }
    .brand-logo:hover {
      filter:
        drop-shadow(0 0 14px rgba(120, 247, 255, 0.32))
        drop-shadow(0 0 24px rgba(245, 157, 244, 0.22));
    }
    @media (max-width: 768px) {
      .brand-logo {
        height: auto;
        max-height: 120px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    </head>

  
    <header>
      <div class="brand-area">
        <img src="assets/eyemole.png" alt="Eyemole" class="brand-logo">
      </div>
      <div class="meta-badges">
        <div class="meta-badge">Gerado em: <strong id="generation-time"></strong></div>
        <div class="meta-badge">Modo: <strong>{{{EXEC_MODE}}}</strong></div>
        <div class="meta-badge">Agentes: <strong>{{{AGENTS_ANALYZED}}}</strong> (<strong>{{TOTAL_AGENTS}}</strong> ativos)</div>
        <div class="meta-badge">CVEs únicos: <strong>{{TOTAL_UNIQUE_CVES}}</strong></div>
        <div class="meta-badge">Limiares: <strong>CVSS &gt;= <span id="cvss-limit"></span> | EPSS &gt;= <span id="epss-limit"></span>%</strong></div>
      </div>
    </header>
    
    <!-- Aba Navigation sticky (Fase 3H) -->
    <nav class="tab-nav">
      <button class="tab-btn active" data-tab="overview" onclick="activateTab('overview')"><svg class="tab-ico" xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg><span>Visão Geral</span></button>
      <button class="tab-btn" data-tab="risk" onclick="activateTab('risk')"><svg class="tab-ico" xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><line x1="12" y1="3" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="21"/><line x1="3" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="21" y2="12"/><circle cx="12" cy="12" r="2.5"/></svg><span>Risco & Prioridades</span></button>
      <button class="tab-btn" data-tab="assets" onclick="activateTab('assets')"><svg class="tab-ico" xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><span>Ativos & Exposição</span></button>
      <button class="tab-btn" data-tab="sla" onclick="activateTab('sla')"><svg class="tab-ico" xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 16 14"/></svg><span>SLA & Backlog</span></button>
      <button class="tab-btn" data-tab="governance" onclick="activateTab('governance')"><svg class="tab-ico" xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg><span>Governança & Exceções</span></button>
      <button class="tab-btn" data-tab="trends" onclick="activateTab('trends')"><svg class="tab-ico" xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg><span>Tendências</span></button>
      <button class="tab-btn" data-tab="treatment" onclick="activateTab('treatment')"><svg class="tab-ico" xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2"/></svg><span>Plano de Tratativa</span></button>
      <button class="tab-btn" data-tab="status" onclick="activateTab('status')"><svg class="tab-ico" xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="15" y2="17"/></svg><span>Status & Auditoria</span></button>
    </nav>

    <main>
      <!-- Aba 1: Visão Geral -->
      <section id="tab-overview" class="tab-panel active">
        <!-- Cards Principais Executivos -->
        <div class="grid-metrics" style="grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-bottom: 2rem; gap: 1rem;">
          
          <!-- Total de Vulnerabilidades -->
          <div class="metric-card all" style="border-left: 4px solid var(--text-muted);">
            <div class="metric-title">Total de Vulnerabilidades</div>
            <div class="metric-value" id="overview-total-vulns">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Ativas no último snapshot</div>
          </div>
          
          <!-- Críticas -->
          <div class="metric-card p1plus" style="border-left: 4px solid var(--p1plus);">
            <div class="metric-title">Severidade Crítica</div>
            <div class="metric-value" id="overview-risk-critical" style="color: #f87171;">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Risco muito alto</div>
          </div>
          
          <!-- Altas -->
          <div class="metric-card p1" style="border-left: 4px solid var(--p1);">
            <div class="metric-title">Severidade Alta</div>
            <div class="metric-value" id="overview-risk-high" style="color: #fb923c;">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Risco alto</div>
          </div>
          
          <!-- KEV -->
          <div class="metric-card p2" style="border-left: 4px solid #f59e0b;">
            <div class="metric-title">Catálogo CISA KEV</div>
            <div class="metric-value" id="overview-risk-kev" style="color: #facc15;">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Vulnerabilidades exploradas</div>
          </div>
          
          <!-- EPSS >= 20% -->
          <div class="metric-card p3" style="border-left: 4px solid #a78bfa;">
            <div class="metric-title">EPSS &gt;= 20%</div>
            <div class="metric-value" id="overview-risk-epss" style="color: #c084fc;">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Alta probabilidade de exploração</div>
          </div>
          
          <!-- Agentes Afetados -->
          <div class="metric-card p4" style="border-left: 4px solid #3b82f6;">
            <div class="metric-title">Agentes Afetados</div>
            <div class="metric-value" id="overview-risk-agents" style="color: #60a5fa;">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Hosts com vulnerabilidades</div>
          </div>
          
          <!-- SLA Próximo (Due soon) -->
          <div class="metric-card p1" style="border-left: 4px solid #fb923c;">
            <div class="metric-title">SLA Próximo / Vencido</div>
            <div class="metric-value" id="overview-sla-status" style="font-size: 1.4rem;">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;" id="overview-sla-details">Overdue: - | Due soon: -</div>
          </div>
          
          <!-- Prioridades Acionáveis -->
          <div class="metric-card p2" style="border-left: 4px solid #eab308;">
            <div class="metric-title">Prioridades Acionáveis</div>
            <div class="metric-value" id="overview-actionable-priorities">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Excluindo exceções/FP</div>
          </div>
          
          <!-- Status Tendência -->
          <div class="metric-card all" style="border-left: 4px solid #8b5cf6;">
            <div class="metric-title">Status Tendência</div>
            <div class="metric-value" id="overview-trend-health" style="font-size: 1.4rem;">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;" id="overview-trend-direction">Direção do risco: -</div>
          </div>
          
          <!-- Plano de Tratativa -->
          <div class="metric-card all" style="border-left: 4px solid #ef4444;">
            <div class="metric-title">Ações Imediatas (Now)</div>
            <div class="metric-value" id="overview-treatment-now" style="color: #f87171;">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Itens urgentes do plano</div>
          </div>

          <!-- Status Automação -->
          <div class="metric-card all" style="border-left: 4px solid #10b981;">
            <div class="metric-title">Status Automação</div>
            <div class="metric-value" id="overview-status-api" style="font-size: 1.4rem;">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;" id="overview-status-service">Serviço: -</div>
          </div>

          <!-- Geração Relatório -->
          <div class="metric-card all" style="border-left: 4px solid var(--text-muted);">
            <div class="metric-title">Idade Relatório</div>
            <div class="metric-value" id="overview-generation-age" style="font-size: 1.2rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;" id="overview-generation-time">Gerado em: -</div>
          </div>

        </div>
        
        <!-- Legacy Overview Metadata Elements (Ocultos para uso do JS) -->
        <div id="legacy-overview-meta-container" style="display: none;">
          <span id="overview-cvss-limit"></span>
          <span id="overview-epss-limit"></span>
        </div>

        <!-- Fase 3H.2 - Dashboard Executivo Visão Geral -->
        <h3 class="section-title" style="margin-top: 2rem; margin-bottom: 1rem; font-size: 1.3rem; font-weight: 800; color: var(--text-main);">Dashboard Executivo</h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; margin-bottom: 2rem;">
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Distribuição por Severidade</h4>
            <div id="overview-chart-severity" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">SLA Operacional</h4>
            <div id="overview-chart-sla" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Prioridades de Tratativa</h4>
            <div id="overview-chart-treatment" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Tendência Geral</h4>
            <div id="overview-chart-trend" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
        </div>

        <!-- Fase 3H.2 - Top 10 na Visão Geral -->
        <h3 class="section-title" style="margin-top: 2rem; margin-bottom: 1rem; font-size: 1.3rem; font-weight: 800; color: var(--text-main);">Top 10 Prioridades de Tratativa</h3>
        <div class="table-container" style="margin-bottom: 2rem; padding: 0;">
          <table class="styled-table" id="overview-top10-table" style="width: 100%; border: none;">
            <thead>
              <tr>
                <th style="width: 55px; text-align: center;">Rank</th>
                <th style="width: 100px; text-align: center;">Prioridade</th>
                <th style="width: 80px; text-align: center;">Agente</th>
                <th>CVE</th>
                <th>Pacote</th>
                <th style="width: 70px; text-align: center;">CVSS</th>
                <th style="width: 80px; text-align: center;">EPSS</th>
                <th style="width: 90px; text-align: center;">Severidade</th>
                <th>Tags / Motivo de Priorização</th>
              </tr>
            </thead>
            <tbody id="overview-top10-tbody">
              <tr>
                <td colspan="9" style="text-align: center; color: var(--text-muted); padding: 2rem;">Dados indisponíveis ou carregando...</td>
              </tr>
            </tbody>
          </table>
          <div style="text-align: right; padding: 1rem; background: rgba(0,0,0,0.08); border-top: 1px solid var(--border-color);">
            <button onclick="activateTab('risk')" class="action-btn" style="padding: 0.5rem 1rem; background: linear-gradient(135deg, #3b82f6, #8b5cf6); border: none; border-radius: 8px; color: #ffffff; font-weight: bold; cursor: pointer; font-size: 0.8rem; box-shadow: 0 4px 10px rgba(59,130,246,0.2);">Ver lista completa em Risco & Prioridades</button>
          </div>
        </div>
      </section>

      <!-- Aba 2: Risco & Prioridades -->
      <section id="tab-risk" class="tab-panel">
        <div class="grid-metrics">
      <div class="metric-card all active" onclick="filterByPriority('ALL')">
        <div class="metric-title">Total de Vulnerabilidades</div>
        <div class="metric-value" id="count-total">0</div>
      </div>
      <div class="metric-card p1plus" onclick="filterByPriority('Priority 1+')">
        <div class="metric-title">Priority 1+ (KEV Ativo)</div>
        <div class="metric-value" id="count-p1plus">0</div>
      </div>
      <div class="metric-card p1" onclick="filterByPriority('Priority 1')">
        <div class="metric-title">Priority 1 (Alto CVSS & EPSS)</div>
        <div class="metric-value" id="count-p1">0</div>
      </div>
      <div class="metric-card p2" onclick="filterByPriority('Priority 2')">
        <div class="metric-title">Priority 2 (CVSS Alto)</div>
        <div class="metric-value" id="count-p2">0</div>
      </div>
      <div class="metric-card p3" onclick="filterByPriority('Priority 3')">
        <div class="metric-title">Priority 3 (EPSS Alto)</div>
        <div class="metric-value" id="count-p3">0</div>
      </div>
      <div class="metric-card p4" onclick="filterByPriority('Priority 4')">
        <div class="metric-title">Priority 4 (Baixo Risco)</div>
        <div class="metric-value" id="count-p4">0</div>
      </div>
    </div>
        <div class="toolbar">
      <div class="search-wrapper">
        <span class="search-icon">🔍</span>
        <input type="text" class="search-input" id="search-box" placeholder="Buscar por CVE, agente, pacote..." oninput="onSearchChange()">
      </div>
      <div class="checkbox-filters">
        <label class="checkbox-label"><input type="checkbox" id="filter-ransomware" onchange="onRansomwareToggle()"><span>Apenas Ransomware</span></label>
      </div>
      <div class="btn-group">
        <button class="btn" onclick="resetFilters()">Limpar Filtros</button>
        <button class="btn btn-primary" onclick="exportFilteredCSV()">📥 Exportar CSV Filtrado</button>
      </div>
    </div>
        <!-- Priorização Inteligente de Risco (Fase 3A) -->
    <div style="margin-top: 2rem; margin-bottom: 2rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
        <h2 style="font-size: 1.4rem; font-weight: 800; color: var(--text-main); letter-spacing: -0.02em;">🎯 Priorização Inteligente de Risco</h2>
        <button class="btn" id="btn-refresh-risk" onclick="refreshRiskIntelligence()" style="font-weight: 600;">
          🔄 Atualizar risco
        </button>
      </div>

      <!-- Alertas Passivos -->
      <div class="alert-container" id="risk-alerts-container">
        <div class="alert-item alert-info">Carregando informações de alertas de risco...</div>
      </div>

      <!-- Cards Executivos de Risco -->
      <div class="grid-risk-seven" style="margin-bottom: 1.5rem;">
        <div class="risk-card total">
          <div class="metric-title" style="font-size: 0.75rem;">Total Vulnerabilidades</div>
          <div class="metric-value" id="risk-total" style="font-size: 1.6rem; margin-top: 0.25rem;">-</div>
        </div>
        <div class="risk-card critico">
          <div class="metric-title" style="font-size: 0.75rem;">Críticas</div>
          <div class="metric-value" id="risk-critical" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f87171;">-</div>
        </div>
        <div class="risk-card alto">
          <div class="metric-title" style="font-size: 0.75rem;">Altas</div>
          <div class="metric-value" id="risk-high" style="font-size: 1.6rem; margin-top: 0.25rem; color: #fb923c;">-</div>
        </div>
        <div class="risk-card kev">
          <div class="metric-title" style="font-size: 0.75rem;">Catálogo KEV</div>
          <div class="metric-value" id="risk-kev" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f59e0b;">-</div>
        </div>
        <div class="risk-card epss">
          <div class="metric-title" style="font-size: 0.75rem;">EPSS &gt;= 20%</div>
          <div class="metric-value" id="risk-epss" style="font-size: 1.6rem; margin-top: 0.25rem; color: #a78bfa;">-</div>
        </div>
        <div class="risk-card agentes">
          <div class="metric-title" style="font-size: 0.75rem;">Agentes Afetados</div>
          <div class="metric-value" id="risk-agents" style="font-size: 1.6rem; margin-top: 0.25rem; color: #3b82f6;">-</div>
        </div>
        <div class="risk-card idade">
          <div class="metric-title" style="font-size: 0.75rem;">Idade Relatório</div>
          <div class="metric-value" id="risk-age" style="font-size: 1.2rem; margin-top: 0.5rem; color: #10b981; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">-</div>
        </div>
      </div>

      <!-- Tabela Top 10 Prioridades (Visualmente removida na aba Risco) -->
      <div class="table-container" style="display: none; margin-bottom: 2rem;">
        <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
          🔥 Top 10 Prioridades de Tratativa
        </div>
        <table>
          <thead>
            <tr>
              <th style="width: 60px;">Rank</th>
              <th>CVE</th>
              <th>Pacote</th>
              <th>Severidade</th>
              <th>KEV</th>
              <th>EPSS</th>
              <th>Agentes</th>
              <th style="width: 80px;">Score</th>
              <th>Motivo da Priorização</th>
            </tr>
          </thead>
          <tbody id="risk-priorities-tbody">
            <tr>
              <td colspan="9" style="text-align: center; color: var(--text-muted); padding: 2rem;">Carregando ranking de prioridades...</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Seção Delta de Execuções -->
      <div style="margin-bottom: 1rem;">
        <h3 style="font-size: 1.1rem; font-weight: 700; color: var(--text-muted); margin-bottom: 1rem;">🔄 Mudanças desde a última análise (Comparação com baseline anterior)</h3>
        <div class="grid-risk-seven" id="delta-cards-container" style="grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));">
          <div class="risk-card total" style="pointer-events: none;">
            <div class="metric-title" style="font-size: 0.75rem;">Novas Vulns</div>
            <div class="metric-value" id="delta-new" style="font-size: 1.6rem; margin-top: 0.25rem;">-</div>
          </div>
          <div class="risk-card total" style="pointer-events: none;">
            <div class="metric-title" style="font-size: 0.75rem;">Resolvidas</div>
            <div class="metric-value" id="delta-resolved" style="font-size: 1.6rem; margin-top: 0.25rem;">-</div>
          </div>
          <div class="risk-card total" style="pointer-events: none;">
            <div class="metric-title" style="font-size: 0.75rem;">Persistentes</div>
            <div class="metric-value" id="delta-persistent" style="font-size: 1.6rem; margin-top: 0.25rem;">-</div>
          </div>
          <div class="risk-card total" style="pointer-events: none;">
            <div class="metric-title" style="font-size: 0.75rem;">Novos KEVs</div>
            <div class="metric-value" id="delta-new-kev" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f59e0b;">-</div>
          </div>
          <div class="risk-card total" style="pointer-events: none;">
            <div class="metric-title" style="font-size: 0.75rem;">Novas Críticas</div>
            <div class="metric-value" id="delta-new-critical" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f87171;">-</div>
          </div>
          <div class="risk-card total" style="pointer-events: none;">
            <div class="metric-title" style="font-size: 0.75rem;">Agentes Piorados</div>
            <div class="metric-value" id="delta-worsened-agents" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f87171;">-</div>
          </div>
          <div class="risk-card total" style="pointer-events: none;">
            <div class="metric-title" style="font-size: 0.75rem;">Agentes Melhorados</div>
            <div class="metric-value" id="delta-improved-agents" style="font-size: 1.6rem; margin-top: 0.25rem; color: #34d399;">-</div>
          </div>
        </div>
      </div>
    </div>

        <!-- Fase 3H.2 - Dashboards Risco & Prioridades -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-top: 1rem; margin-bottom: 2rem;">
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Distribuição por Severidade</h4>
            <div id="risk-chart-severity" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Distribuição por Prioridade</h4>
            <div id="risk-chart-priority" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">KEV x EPSS Alto</h4>
            <div id="risk-chart-kev-epss" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Top Pacotes por Recorrência</h4>
            <div id="risk-chart-packages" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Top Agentes por Risco</h4>
            <div id="risk-chart-agents" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
        </div>

        <div class="table-container">
      <table id="vuln-table">
        <thead>
          <tr>
            <th onclick="sortTable('priority')">Prioridade ↕</th>
            <th onclick="sortTable('agent_id')">Agente ↕</th>
            <th onclick="sortTable('cve')">CVE ↕</th>
            <th onclick="sortTable('package')">Pacote ↕</th>
            <th>Versão</th>
            <th onclick="sortTable('cvss')">CVSS ↕</th>
            <th onclick="sortTable('epss')">EPSS ↕</th>
            <th onclick="sortTable('severity')">Severidade ↕</th>
            <th>Tag / Detalhe</th>
          </tr>
        </thead>
        <tbody id="vuln-table-body"></tbody>
      </table>
      <div id="empty-state-msg" class="empty-state" style="display: none;">Nenhum registro encontrado com os filtros atuais.</div>
    </div>

    <div class="pagination-bar">
      <div>
        Exibindo <span id="pagination-start">0</span> a <span id="pagination-end">0</span> de <span id="pagination-total">0</span> registros.
        Mostrar: 
        <select class="page-size-selector" id="page-size" onchange="onChangePageSize()">
          <option value="10">10</option>
          <option value="25" selected>25</option>
          <option value="50">50</option>
          <option value="100">100</option>
          <option value="ALL">Todos</option>
        </select>
      </div>
      <div class="page-controls" id="page-controls"></div>
    </div>
  </div>
      </section>

      <!-- Aba 3: Ativos & Exposição -->
      <section id="tab-assets" class="tab-panel">
        <!-- Contexto de Ativos e Criticidade (Fase 3B) -->
    <div style="margin-top: 2rem; margin-bottom: 2rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
        <h2 style="font-size: 1.4rem; font-weight: 800; color: var(--text-main); letter-spacing: -0.02em;">🖥️ Contexto de Ativos e Criticidade</h2>
        <button class="btn" id="btn-refresh-assets" onclick="refreshAssetContext()" style="font-weight: 600;">
          🔄 Atualizar contexto
        </button>
      </div>

      <!-- Aviso de Classificação Pendente -->
      <div class="alert-container" id="assets-alerts-container" style="display: none;">
        <div class="alert-item alert-warning">
          <strong>Aviso:</strong> Existem ativos sem criticidade definida. Classifique esses ativos para melhorar a precisão da priorização.
        </div>
      </div>

      <!-- Cards de Métricas de Ativos -->
      <div class="grid-risk-seven" style="margin-bottom: 1.5rem;">
        <div class="risk-card total">
          <div class="metric-title" style="font-size: 0.75rem;">Total de Ativos</div>
          <div class="metric-value" id="assets-total" style="font-size: 1.6rem; margin-top: 0.25rem;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #10b981;">
          <div class="metric-title" style="font-size: 0.75rem;">Classificados</div>
          <div class="metric-value" id="assets-classified" style="font-size: 1.6rem; margin-top: 0.25rem; color: #34d399;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #f97316;">
          <div class="metric-title" style="font-size: 0.75rem;">Sem Classificação</div>
          <div class="metric-value" id="assets-unclassified" style="font-size: 1.6rem; margin-top: 0.25rem; color: #fb923c;">-</div>
        </div>
        <div class="risk-card critico">
          <div class="metric-title" style="font-size: 0.75rem;">Ativos Críticos</div>
          <div class="metric-value" id="assets-critical-count" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f87171;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #ef4444;">
          <div class="metric-title" style="font-size: 0.75rem;">Ativos Expostos</div>
          <div class="metric-value" id="assets-exposed-count" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f87171;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #eab308;">
          <div class="metric-title" style="font-size: 0.75rem;">Criticidade Desconhecida</div>
          <div class="metric-value" id="assets-unknown-crit" style="font-size: 1.6rem; margin-top: 0.25rem; color: #facc15;">-</div>
        </div>
      </div>

        <!-- Fase 3H.2 - Dashboards Ativos & Exposição -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; margin-top: 1.5rem; margin-bottom: 1.5rem;">
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Ativos por Criticidade</h4>
            <div id="assets-chart-criticality" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Ativos por Exposição</h4>
            <div id="assets-chart-exposure" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Top Ativos por Risco Contextual</h4>
            <div id="assets-chart-top-risk" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Serviços Críticos Declarados</h4>
            <div id="assets-chart-services" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
        </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Top Ativos por Risco -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            🔥 Top Ativos por Risco (VMDR)
          </div>
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Nome / Hostname</th>
                <th>Criticidade</th>
                <th>Exposição</th>
                <th>Tipo</th>
                <th style="text-align: right;">Risco total</th>
              </tr>
            </thead>
            <tbody id="assets-risk-tbody">
              <tr>
                <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando top ativos por risco...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Ativos Pendentes de Classificação -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            ⚠️ Ativos Pendentes de Classificação (Sem Contexto)
          </div>
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Nome / Hostname</th>
                <th>Status</th>
                <th>Ação Recomendada</th>
              </tr>
            </thead>
            <tbody id="assets-pending-tbody">
              <tr>
                <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando ativos pendentes...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
        <!-- Contexto de Exposição e Superfície de Ataque (Fase 3C) -->
    <div style="margin-top: 2rem; margin-bottom: 2rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
        <h2 style="font-size: 1.4rem; font-weight: 800; color: var(--text-main); letter-spacing: -0.02em;">🌐 Contexto de Exposição e Superfície de Ataque</h2>
        <button class="btn" id="btn-refresh-exposure" onclick="refreshExposureContext()" style="font-weight: 600;">
          🔄 Atualizar exposição
        </button>
      </div>

      <!-- Alertas de Exposição -->
      <div class="alert-container" id="exposure-alerts-container" style="display: none;">
      </div>

      <!-- Cards de Métricas de Exposição -->
      <div class="grid-risk-seven" style="margin-bottom: 1.5rem; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));">
        <div class="risk-card total">
          <div class="metric-title" style="font-size: 0.75rem;">Com Contexto</div>
          <div class="metric-value" id="expo-with-context" style="font-size: 1.6rem; margin-top: 0.25rem; color: #34d399;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #fb923c;">
          <div class="metric-title" style="font-size: 0.75rem;">Sem Contexto</div>
          <div class="metric-value" id="expo-without-context" style="font-size: 1.6rem; margin-top: 0.25rem; color: #fb923c;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #ef4444;">
          <div class="metric-title" style="font-size: 0.75rem;">Internet-facing</div>
          <div class="metric-value" id="expo-internet-facing" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f87171;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #fb923c;">
          <div class="metric-title" style="font-size: 0.75rem;">Em DMZ</div>
          <div class="metric-value" id="expo-dmz" style="font-size: 1.6rem; margin-top: 0.25rem; color: #fb923c;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #a78bfa;">
          <div class="metric-title" style="font-size: 0.75rem;">Serviços Críticos</div>
          <div class="metric-value" id="expo-critical-services" style="font-size: 1.6rem; margin-top: 0.25rem; color: #c084fc;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #ef4444;">
          <div class="metric-title" style="font-size: 0.75rem;">Serviços Exp. Internet</div>
          <div class="metric-value" id="expo-internet-services" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f87171;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #ef4444;">
          <div class="metric-title" style="font-size: 0.75rem;">Ext. Sem Agente</div>
          <div class="metric-value" id="expo-external-no-agent" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f87171;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #ef4444;">
          <div class="metric-title" style="font-size: 0.75rem;">Alertas Inconsistência</div>
          <div class="metric-value" id="expo-alerts-count" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f87171;">-</div>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Top Ativos por Exposição -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            🌐 Top Ativos por Exposição (Pontuação)
          </div>
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Nome / Hostname</th>
                <th>Exposição</th>
                <th>Zona de Rede</th>
                <th>Internet-facing</th>
                <th style="text-align: right;">Score Exposição</th>
              </tr>
            </thead>
            <tbody id="expo-top-assets-tbody">
              <tr>
                <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando top ativos expostos...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Ativos sem Contexto de Exposição -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            ⚠️ Ativos sem Contexto de Exposição
          </div>
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Nome / Hostname</th>
                <th>Status</th>
                <th>Ação Recomendada</th>
              </tr>
            </thead>
            <tbody id="expo-missing-tbody">
              <tr>
                <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando ativos sem contexto de exposição...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Alertas de Exposição -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            ⚠️ Alertas de Superfície de Ataque
          </div>
          <table>
            <thead>
              <tr>
                <th>Gravidade</th>
                <th>Tipo Alerta</th>
                <th>Descrição da Inconsistência / Alerta</th>
              </tr>
            </thead>
            <tbody id="expo-alerts-tbody">
              <tr>
                <td colspan="3" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando alertas de exposição...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Ativos Externos sem Agente -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            🖥️ Ativos Externos Autorizados sem Agente Wazuh
          </div>
          <table>
            <thead>
              <tr>
                <th>Nome Ativo</th>
                <th>IP / Hostname</th>
                <th>Exposição</th>
                <th>Fonte / Confiança</th>
              </tr>
            </thead>
            <tbody id="expo-external-tbody">
              <tr>
                <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando ativos externos...</td>
              </tr>
            </tbody>
          </table>
        </div>
    </div>
      </section>

      <!-- Aba 4: SLA & Backlog -->
      <section id="tab-sla" class="tab-panel">
        <!-- SLA, Aging e Backlog Operacional (Fase 3D) -->
    <div style="margin-top: 2rem; margin-bottom: 2rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
        <h2 style="font-size: 1.4rem; font-weight: 800; color: var(--text-main); letter-spacing: -0.02em;">🕒 SLA, Aging e Backlog Operacional</h2>
        <button class="btn" id="btn-refresh-sla" onclick="refreshSlaSummary()" style="font-weight: 600;">
          🔄 Atualizar SLA
        </button>
      </div>

      <!-- Alertas de SLA -->
      <div class="alert-container" id="sla-alerts-container" style="display: none; margin-bottom: 1.5rem;">
        <!-- Alertas dinâmicos serão inseridos aqui -->
      </div>

      <!-- Grid de Métricas de SLA -->
      <div class="grid-risk-seven" style="grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); margin-bottom: 1.5rem; gap: 0.75rem;">
        <div class="risk-card total">
          <div class="metric-title" style="font-size: 0.75rem;">Total em Aberto</div>
          <div class="metric-value" id="sla-total-open" style="font-size: 1.6rem; margin-top: 0.25rem;">-</div>
        </div>
        <div class="risk-card critico sla-card-overdue">
          <div class="metric-title" style="font-size: 0.75rem;">Vencidas</div>
          <div class="metric-value" id="sla-overdue" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f87171;">-</div>
        </div>
        <div class="risk-card alto sla-card-due-soon">
          <div class="metric-title" style="font-size: 0.75rem;">Próximas do Vencimento</div>
          <div class="metric-value" id="sla-due-soon" style="font-size: 1.6rem; margin-top: 0.25rem; color: #fb923c;">-</div>
        </div>
        <div class="risk-card total sla-card-within-sla">
          <div class="metric-title" style="font-size: 0.75rem;">Dentro do SLA</div>
          <div class="metric-value" id="sla-within-sla" style="font-size: 1.6rem; margin-top: 0.25rem; color: #34d399;">-</div>
        </div>
        <div class="risk-card total">
          <div class="metric-title" style="font-size: 0.75rem;">Sem SLA</div>
          <div class="metric-value" id="sla-no-sla" style="font-size: 1.6rem; margin-top: 0.25rem; color: var(--text-muted);">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #10b981;">
          <div class="metric-title" style="font-size: 0.75rem;">Idade Média</div>
          <div class="metric-value" id="sla-avg-age" style="font-size: 1.6rem; margin-top: 0.25rem; color: #34d399;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #fb923c;">
          <div class="metric-title" style="font-size: 0.75rem;">Maior Aging</div>
          <div class="metric-value" id="sla-max-age" style="font-size: 1.6rem; margin-top: 0.25rem; color: #fb923c;">-</div>
        </div>
        <div class="risk-card total sla-card-persistent">
          <div class="metric-title" style="font-size: 0.75rem;">Persistentes</div>
          <div class="metric-value" id="sla-persistent" style="font-size: 1.6rem; margin-top: 0.25rem; color: #c084fc;">-</div>
        </div>
        <div class="risk-card total sla-card-recurring">
          <div class="metric-title" style="font-size: 0.75rem;">Recorrentes</div>
          <div class="metric-value" id="sla-recurring" style="font-size: 1.6rem; margin-top: 0.25rem; color: #60a5fa;">-</div>
        </div>
      </div>

        <!-- Fase 3H.2 - Dashboards SLA & Backlog -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; margin-top: 1.5rem; margin-bottom: 1.5rem;">
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">SLA: Vencidas / Próximas / Dentro</h4>
            <div id="sla-chart-compliance" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Aging por Faixa</h4>
            <div id="sla-chart-aging" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Backlog por Ativo</h4>
            <div id="sla-chart-backlog-asset" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Backlog por Owner Técnico</h4>
            <div id="sla-chart-backlog-owner" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
        </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Top Vulnerabilidades Vencidas -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            🚨 Top Vulnerabilidades Vencidas (Overdue)
          </div>
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>Ativo</th>
                <th>Pacote</th>
                <th>Severidade</th>
                <th style="text-align: right;">Atraso (Dias)</th>
                <th>Prazo Limite</th>
              </tr>
            </thead>
            <tbody id="sla-overdue-tbody">
              <tr>
                <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando vulnerabilidades vencidas...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Próximas do Vencimento -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            ⏳ Próximas do Vencimento (Due Soon)
          </div>
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>Ativo</th>
                <th>Pacote</th>
                <th>Severidade</th>
                <th style="text-align: right;">Restante (Dias)</th>
                <th>Prazo Limite</th>
              </tr>
            </thead>
            <tbody id="sla-due-soon-tbody">
              <tr>
                <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando vulnerabilidades próximas do vencimento...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Top CVEs Persistentes -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            ⚠️ Top CVEs Persistentes (Aging &gt;= 30 Dias)
          </div>
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>Ativo</th>
                <th>Pacote</th>
                <th>Severidade</th>
                <th style="text-align: right;">Aging (Dias)</th>
              </tr>
            </thead>
            <tbody id="sla-persistent-tbody">
              <tr>
                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando CVEs persistentes...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Top CVEs Recorrentes -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            🔄 Top CVEs Recorrentes (Aparições &gt;= 3 Snapshots)
          </div>
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>Ativo</th>
                <th>Pacote</th>
                <th>Severidade</th>
                <th style="text-align: right;">Snapshots</th>
              </tr>
            </thead>
            <tbody id="sla-recurring-tbody">
              <tr>
                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando CVEs recorrentes...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Backlog por Ativo -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            🖥️ Backlog de Vulnerabilidades por Ativo
          </div>
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Ativo</th>
                <th>Total</th>
                <th style="color:#f87171;">Vencidas</th>
                <th style="color:#fb923c;">Próximas</th>
                <th style="color:#34d399;">No SLA</th>
              </tr>
            </thead>
            <tbody id="sla-backlog-asset-tbody">
              <tr>
                <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando backlog por ativo...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Backlog por Owner Técnico -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            👥 Backlog de Vulnerabilidades por Owner Técnico
          </div>
          <table>
            <thead>
              <tr>
                <th>Owner Técnico</th>
                <th>Total</th>
                <th style="color:#f87171;">Vencidas</th>
                <th style="color:#fb923c;">Próximas</th>
                <th style="color:#34d399;">No SLA</th>
              </tr>
            </thead>
            <tbody id="sla-backlog-owner-tbody">
              <tr>
                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando backlog por owner...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Tabela Alertas de SLA -->
      <div class="table-container" style="margin-bottom: 1.5rem;">
        <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
          ⚠️ Alertas Operacionais de SLA & Backlog
        </div>
        <table>
          <thead>
            <tr>
              <th style="width: 120px;">Gravidade</th>
              <th>Alerta</th>
              <th>Mensagem Detalhada</th>
            </tr>
          </thead>
          <tbody id="sla-alerts-tbody">
            <tr>
              <td colspan="3" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando alertas de SLA...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
      </section>

      <!-- Aba 5: Governança & Exceções -->
      <section id="tab-governance" class="tab-panel">
        <!-- Risk Acceptance e Gestão de Exceções (Fase 3E) -->
    <div style="margin-top: 2rem; margin-bottom: 2rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
        <h2 style="font-size: 1.4rem; font-weight: 800; color: var(--text-main); letter-spacing: -0.02em;">🛡️ Risk Acceptance e Gestão de Exceções</h2>
        <button class="btn" id="btn-refresh-ra" onclick="refreshRiskAcceptance()" style="font-weight: 600;">
          🔄 Atualizar Exceções
        </button>
      </div>

      <!-- Alertas de Risk Acceptance -->
      <div class="alert-container" id="ra-alerts-container" style="display: none; margin-bottom: 1.5rem;">
        <!-- Alertas dinâmicos serão inseridos aqui -->
      </div>

      <!-- Grid de Métricas de Exceções -->
      <div class="grid-risk-seven" style="grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); margin-bottom: 1.5rem; gap: 0.75rem;">
        <div class="risk-card total">
          <div class="metric-title" style="font-size: 0.75rem;">Regras Cadastradas</div>
          <div class="metric-value" id="ra-rules-total" style="font-size: 1.6rem; margin-top: 0.25rem;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #ef4444;">
          <div class="metric-title" style="font-size: 0.75rem;">Regras Inválidas</div>
          <div class="metric-value" id="ra-rules-invalid" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f87171;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #10b981;">
          <div class="metric-title" style="font-size: 0.75rem;">Vulnerabilidades Aceitas</div>
          <div class="metric-value" id="ra-accepted-count" style="font-size: 1.6rem; margin-top: 0.25rem; color: #34d399;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #3b82f6;">
          <div class="metric-title" style="font-size: 0.75rem;">Falsos Positivos</div>
          <div class="metric-value" id="ra-fp-count" style="font-size: 1.6rem; margin-top: 0.25rem; color: #60a5fa;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #eab308;">
          <div class="metric-title" style="font-size: 0.75rem;">Correções Planejadas</div>
          <div class="metric-value" id="ra-planned-count" style="font-size: 1.6rem; margin-top: 0.25rem; color: #facc15;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #a78bfa;">
          <div class="metric-title" style="font-size: 0.75rem;">Controles Compensatórios</div>
          <div class="metric-value" id="ra-compensating-count" style="font-size: 1.6rem; margin-top: 0.25rem; color: #c084fc;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #fb923c;">
          <div class="metric-title" style="font-size: 0.75rem;">Aguardando Janela</div>
          <div class="metric-value" id="ra-waiting-count" style="font-size: 1.6rem; margin-top: 0.25rem; color: #fb923c;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #ef4444;">
          <div class="metric-title" style="font-size: 0.75rem;">Exceções Vencidas</div>
          <div class="metric-value" id="ra-expired-count" style="font-size: 1.6rem; margin-top: 0.25rem; color: #f87171;">-</div>
        </div>
        <div class="risk-card total" style="border-left: 3px solid #10b981;">
          <div class="metric-title" style="font-size: 0.75rem;">Prioridades Acionáveis</div>
          <div class="metric-value" id="ra-actionable-count" style="font-size: 1.6rem; margin-top: 0.25rem; color: #34d399;">-</div>
        </div>
      </div>

        <!-- Fase 3H.2 - Dashboards Governança & Exceções -->
        <div id="governance-no-data-msg" style="display: none; text-align: center; color: var(--text-muted); padding: 1.5rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; margin-top: 1.5rem; margin-bottom: 1.5rem;">
          Nenhuma exceção configurada no momento.
        </div>
        <div id="governance-charts-container" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; margin-top: 1.5rem; margin-bottom: 1.5rem;">
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Status das Exceções</h4>
            <div id="gov-chart-status" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Aceites de Risco</h4>
            <div id="gov-chart-acceptance" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Falsos Positivos</h4>
            <div id="gov-chart-fps" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Exceções Expiradas</h4>
            <div id="gov-chart-expired" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
        </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Exceções Vencidas -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            🚨 Exceções Vencidas (Expired)
          </div>
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>Ativo</th>
                <th>Regra ID</th>
                <th>Vencido em</th>
                <th style="text-align: right;">Atraso (Dias)</th>
              </tr>
            </thead>
            <tbody id="ra-expired-tbody">
              <tr>
                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando exceções vencidas...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Exceções Próximas do Vencimento -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            ⏳ Exceções Próximas do Vencimento (&lt;= 30 Dias)
          </div>
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>Ativo</th>
                <th>Regra ID</th>
                <th>Vence em</th>
                <th style="text-align: right;">Restante (Dias)</th>
              </tr>
            </thead>
            <tbody id="ra-expiring-soon-tbody">
              <tr>
                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando exceções próximas do vencimento...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Falsos Positivos -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            🔍 Falsos Positivos Homologados
          </div>
          <table>
            <thead>
              <tr>
                <th>CVE / Pacote</th>
                <th>Ativo</th>
                <th>Justificativa</th>
                <th>Aprovado por</th>
              </tr>
            </thead>
            <tbody id="ra-fp-tbody">
              <tr>
                <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando falsos positivos...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Riscos Aceitos -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            🛡️ Riscos Aceitos Ativos
          </div>
          <table>
            <thead>
              <tr>
                <th>CVE / Pacote</th>
                <th>Ativo</th>
                <th>Justificativa / Motivo</th>
                <th>Validade</th>
              </tr>
            </thead>
            <tbody id="ra-accepted-tbody">
              <tr>
                <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando riscos aceitos...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Correções Planejadas -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            📅 Correções Planejadas
          </div>
          <table>
            <thead>
              <tr>
                <th>CVE / Pacote</th>
                <th>Ativo</th>
                <th>Ticket</th>
                <th>Planejado Para</th>
              </tr>
            </thead>
            <tbody id="ra-planned-tbody">
              <tr>
                <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando correções planejadas...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Controles Compensatórios -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            🛡️ Controles Compensatórios Ativos
          </div>
          <table>
            <thead>
              <tr>
                <th>CVE / Pacote</th>
                <th>Ativo</th>
                <th>Controles Compensatórios Aplicados</th>
                <th>Dono / Validade</th>
              </tr>
            </thead>
            <tbody id="ra-compensating-tbody">
              <tr>
                <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando controles compensatórios...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Regras Inválidas -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            ❌ Regras Declarativas Inválidas (Erros de Validação)
          </div>
          <table>
            <thead>
              <tr>
                <th>Regra ID / Índice</th>
                <th>Status</th>
                <th>Mensagem de Erro de Validação</th>
              </tr>
            </thead>
            <tbody id="ra-invalid-rules-tbody">
              <tr>
                <td colspan="3" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando regras inválidas...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Amostra de Itens Matched -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            📋 Amostra de Itens Correspondidos (Match)
          </div>
          <table>
            <thead>
              <tr>
                <th>CVE / Pacote</th>
                <th>Ativo</th>
                <th>Regra ID</th>
                <th>Status Aplicado</th>
              </tr>
            </thead>
            <tbody id="ra-matched-sample-tbody">
              <tr>
                <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando amostra de matches...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Tabela Alertas de Exceção -->
      <div class="table-container" style="margin-bottom: 1.5rem;">
        <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
          ⚠️ Alertas de Exceções & Governança de Risco
        </div>
        <table>
          <thead>
            <tr>
              <th style="width: 120px;">Gravidade</th>
              <th>Alerta</th>
              <th>Mensagem Detalhada</th>
            </tr>
          </thead>
          <tbody id="ra-alerts-tbody">
            <tr>
              <td colspan="3" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando alertas de exceções...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
      </section>

      <!-- Aba 6: Tendências -->
      <section id="tab-trends" class="tab-panel">
        <!-- Trend Analytics e Evolução do Risco (Fase 3F) -->
    <div style="margin-top: 2rem; margin-bottom: 2rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
        <h2 style="font-size: 1.4rem; font-weight: 800; color: var(--text-main); letter-spacing: -0.02em;">📈 Trend Analytics e Evolução do Risco</h2>
        <button class="btn" id="btn-refresh-trend" onclick="refreshTrendSummary()" style="font-weight: 600;">
          🔄 Atualizar Tendências
        </button>
      </div>

      <!-- Alertas Executivos -->
      <div class="alert-container" id="trend-alerts-container" style="display: none; margin-bottom: 1.5rem;">
        <!-- Alertas dinâmicos serão inseridos aqui -->
      </div>

      <!-- Grid de Métricas de Tendências -->
      <div class="grid-metrics" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin-bottom: 1.5rem; gap: 1rem;">
        <div class="metric-card all" style="cursor: default; pointer-events: none; border-left: 4px solid #3b82f6;">
          <div class="metric-title" style="font-size: 0.8rem;">Status Executivo</div>
          <div class="metric-value" id="trend-exec-health" style="font-size: 1.8rem; margin-top: 0.5rem;">-</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;" id="trend-period-days">Período: -</div>
        </div>
        <div class="metric-card all" style="cursor: default; pointer-events: none; border-left: 4px solid #10b981;">
          <div class="metric-title" style="font-size: 0.8rem;">Direção do Risco</div>
          <div class="metric-value" id="trend-risk-direction" style="font-size: 1.8rem; margin-top: 0.5rem;">-</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;" id="trend-snapshots-analyzed">Snapshots analisados: -</div>
        </div>
        <div class="metric-card all" style="cursor: default; pointer-events: none; border-left: 4px solid #ef4444;">
          <div class="metric-title" style="font-size: 0.8rem;">Variação Total (Delta)</div>
          <div class="metric-value" id="trend-delta-total" style="font-size: 1.8rem; margin-top: 0.5rem;">-</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;" id="trend-delta-critical-high">Críticas: - | Altas: -</div>
        </div>
        <div class="metric-card all" style="cursor: default; pointer-events: none; border-left: 4px solid #eab308;">
          <div class="metric-title" style="font-size: 0.8rem;">Variação de SLA e Backlog</div>
          <div class="metric-value" id="trend-delta-sla-actionable" style="font-size: 1.8rem; margin-top: 0.5rem;">-</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;" id="trend-delta-details">SLA Vencido: - | KEV: -</div>
        </div>
      </div>

      <!-- Tabelas de Tendências -->
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Ativos em Piora -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: #ef4444; border-bottom: 1px solid var(--border-color); background: rgba(239, 68, 68, 0.05);">
            ⚠️ Top Ativos com Piora de Risco
          </div>
          <table>
            <thead>
              <tr>
                <th>Ativo</th>
                <th>Owner Técnico</th>
                <th>Críticas (Anterior -> Atual)</th>
                <th>Total (Anterior -> Atual)</th>
                <th>Direção</th>
              </tr>
            </thead>
            <tbody id="trend-worsening-tbody">
              <tr>
                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando ativos em piora...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Ativos em Melhora -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: #10b981; border-bottom: 1px solid var(--border-color); background: rgba(16, 185, 129, 0.05);">
            ✅ Top Ativos com Melhora de Risco
          </div>
          <table>
            <thead>
              <tr>
                <th>Ativo</th>
                <th>Owner Técnico</th>
                <th>Críticas (Anterior -> Atual)</th>
                <th>Total (Anterior -> Atual)</th>
                <th>Direção</th>
              </tr>
            </thead>
            <tbody id="trend-improving-tbody">
              <tr>
                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando ativos em melhora...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Tendência por Owner -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            👤 Tendência do Backlog por Owner Técnico
          </div>
          <table>
            <thead>
              <tr>
                <th>Owner Técnico</th>
                <th>Total (Anterior -> Atual)</th>
                <th>SLA Vencido (Anterior -> Atual)</th>
                <th>Direção</th>
              </tr>
            </thead>
            <tbody id="trend-owner-tbody">
              <tr>
                <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando tendência por owner...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela CVEs Persistentes -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            🛡️ Top CVEs Persistentes e SLA
          </div>
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>Ativo</th>
                <th>Severidade</th>
                <th>Dias Aberto</th>
                <th>Status SLA</th>
              </tr>
            </thead>
            <tbody id="trend-persistent-tbody">
              <tr>
                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando CVEs persistentes...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Gráficos de Tendência (Fase 3H.2) -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Gráfico 1: Evolução do Total de Vulnerabilidades -->
        <div class="table-container" style="margin-bottom: 0; padding: 1rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
          <div style="font-weight: 700; color: var(--text-main); margin-bottom: 1rem; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">
            📈 Evolução do Total de Vulnerabilidades
          </div>
          <div id="trend-chart-total" style="height: 200px; width: 100%; position: relative;">
            <div style="display: flex; height: 100%; align-items: center; justify-content: center; color: var(--text-muted);">Aguardando dados...</div>
          </div>
        </div>

        <!-- Gráfico 2: Evolução de Críticas e Altas -->
        <div class="table-container" style="margin-bottom: 0; padding: 1rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
          <div style="font-weight: 700; color: var(--text-main); margin-bottom: 1rem; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">
            📈 Evolução de Críticas e Altas
          </div>
          <div id="trend-chart-crit-high" style="height: 200px; width: 100%; position: relative;">
            <div style="display: flex; height: 100%; align-items: center; justify-content: center; color: var(--text-muted);">Aguardando dados...</div>
          </div>
        </div>

        <!-- Gráfico 3: Evolução de SLA -->
        <div class="table-container" style="margin-bottom: 0; padding: 1rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
          <div style="font-weight: 700; color: var(--text-main); margin-bottom: 1rem; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">
            📈 Evolução de Cumprimento de SLA
          </div>
          <div id="trend-chart-sla" style="height: 200px; width: 100%; position: relative;">
            <div style="display: flex; height: 100%; align-items: center; justify-content: center; color: var(--text-muted);">Aguardando dados...</div>
          </div>
        </div>

        <!-- Gráfico 4: Evolução do Backlog Acionável -->
        <div class="table-container" style="margin-bottom: 0; padding: 1rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
          <div style="font-weight: 700; color: var(--text-main); margin-bottom: 1rem; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">
            📈 Evolução do Backlog Acionável
          </div>
          <div id="trend-chart-actionable" style="height: 200px; width: 100%; position: relative;">
            <div style="display: flex; height: 100%; align-items: center; justify-content: center; color: var(--text-muted);">Aguardando dados...</div>
          </div>
        </div>
      </div>

      <!-- Tabelas de Linha do Tempo de Tendências -->
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Evolução de Severidade -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            📊 Histórico de Severidade (Últimas Execuções)
          </div>
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Críticas</th>
                <th>Altas</th>
                <th>Médias</th>
                <th>Baixas</th>
              </tr>
            </thead>
            <tbody id="trend-severity-tbody">
              <tr>
                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando histórico de severidade...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Evolução de SLA -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            ⌛ Histórico de Cumprimento de SLA
          </div>
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Overdue (Vencidas)</th>
                <th>Due Soon (No Limite)</th>
                <th>Within SLA (Em Conformidade)</th>
              </tr>
            </thead>
            <tbody id="trend-sla-tbody">
              <tr>
                <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando histórico de SLA...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Evolução de Risk Acceptance -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            🛡️ Histórico de Risk Acceptance e Backlog Acionável
          </div>
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Riscos Aceitos</th>
                <th>Falsos Positivos</th>
                <th>Exceções Vencidas</th>
                <th>Prioridades Acionáveis</th>
              </tr>
            </thead>
            <tbody id="trend-acceptance-tbody">
              <tr>
                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando histórico de aceites...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Tabela Alertas Executivos -->
      <div class="table-container" style="margin-bottom: 1.5rem;">
        <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
          🚨 Alertas Executivos e Desvios de Tendência
        </div>
        <table>
          <thead>
            <tr>
              <th style="width: 120px;">Gravidade</th>
              <th>Alerta</th>
              <th>Mensagem Detalhada de Tendência</th>
            </tr>
          </thead>
          <tbody id="trend-alerts-tbody">
            <tr>
              <td colspan="3" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando alertas executivos...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
      </section>

      <!-- Aba 7: Plano de Tratativa -->
      <section id="tab-treatment" class="tab-panel">
        <!-- Plano de Tratativa e Workload Operacional (Fase 3G) -->
    <div style="margin-top: 2rem; margin-bottom: 2rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
        <h2 style="font-size: 1.4rem; font-weight: 800; color: var(--text-main); letter-spacing: -0.02em;">📋 Plano de Tratativa e Workload Operacional</h2>
        <button class="btn" id="btn-refresh-treatment" onclick="refreshTreatmentPlan()" style="font-weight: 600;">
          🔄 Atualizar Plano
        </button>
      </div>

      <!-- Alertas de Tratativa -->
      <div class="alert-container" id="treatment-alerts-container" style="display: none; margin-bottom: 1.5rem;">
        <!-- Alertas dinâmicos serão inseridos aqui -->
      </div>

      <!-- Grid de Plano de Tratativa -->
      <div class="grid-metrics" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin-bottom: 1.5rem; gap: 1rem;">
        <div class="metric-card all" style="cursor: default; pointer-events: none; border-left: 4px solid #ef4444;">
          <div class="metric-title" style="font-size: 0.8rem;">Ações Imediatas (Now)</div>
          <div class="metric-value" id="treatment-metrics-now" style="font-size: 1.8rem; margin-top: 0.5rem;">-</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Tratar agora</div>
        </div>
        <div class="metric-card all" style="cursor: default; pointer-events: none; border-left: 4px solid #f97316;">
          <div class="metric-title" style="font-size: 0.8rem;">Próximos 7 Dias</div>
          <div class="metric-value" id="treatment-metrics-7d" style="font-size: 1.8rem; margin-top: 0.5rem;">-</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Curto prazo</div>
        </div>
        <div class="metric-card all" style="cursor: default; pointer-events: none; border-left: 4px solid #eab308;">
          <div class="metric-title" style="font-size: 0.8rem;">Próximos 15 Dias</div>
          <div class="metric-value" id="treatment-metrics-15d" style="font-size: 1.8rem; margin-top: 0.5rem;">-</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Médio prazo</div>
        </div>
        <div class="metric-card all" style="cursor: default; pointer-events: none; border-left: 4px solid #3b82f6;">
          <div class="metric-title" style="font-size: 0.8rem;">Próximos 30 Dias</div>
          <div class="metric-value" id="treatment-metrics-30d" style="font-size: 1.8rem; margin-top: 0.5rem;">-</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Longo prazo</div>
        </div>
        <div class="metric-card all" style="cursor: default; pointer-events: none; border-left: 4px solid #10b981;">
          <div class="metric-title" style="font-size: 0.8rem;">Monitorar / Exceções</div>
          <div class="metric-value" id="treatment-metrics-monitor" style="font-size: 1.8rem; margin-top: 0.5rem;">-</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;" id="treatment-metrics-exc-fp">Exceções: - | FP: -</div>
        </div>
        <div class="metric-card all" style="cursor: default; pointer-events: none; border-left: 4px solid #8b5cf6;">
          <div class="metric-title" style="font-size: 0.8rem;">Equipes (Owners)</div>
          <div class="metric-value" id="treatment-metrics-owners" style="font-size: 1.8rem; margin-top: 0.5rem;">-</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;" id="treatment-metrics-wins-change">Quick Wins: - | Janelas: -</div>
        </div>
      </div>

        <!-- Fase 3H.2 - Dashboards Plano de Tratativa -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; margin-top: 1.5rem; margin-bottom: 1.5rem;">
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Distribuição por Bucket</h4>
            <div id="treat-chart-buckets" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Workload por Owner</h4>
            <div id="treat-chart-workload" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Quick Wins</h4>
            <div id="treat-chart-quickwins" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
          <div class="metric-card" style="padding: 1.25rem; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column;">
            <h4 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 1rem; color: var(--text-main); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">Change Window Candidates</h4>
            <div id="treat-chart-changes" style="height: 160px; display: flex; align-items: center; justify-content: center; width: 100%;"></div>
          </div>
        </div>

      <!-- Tabelas de Priorização e Cargas de Trabalho -->
      <div class="table-container">
        <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
          🔥 Top Itens para Tratativa Operacional (Fase 3G)
        </div>
        <table>
          <thead>
            <tr>
              <th>CVE</th>
              <th>Ativo</th>
              <th>Pacote</th>
              <th>Dono Técnico</th>
              <th>Criticidade / Exposição</th>
              <th style="text-align: center;">Prioridade Operacional</th>
              <th>Balde / Ação Sugerida</th>
              <th>Complexidade (Esforço)</th>
              <th>Motivo da Priorização</th>
            </tr>
          </thead>
          <tbody id="treatment-top-tbody">
            <tr>
              <td colspan="9" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando plano de tratativa...</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div style="display: grid; grid-template-columns: 1fr; gap: 1rem; margin-top: 1.5rem; margin-bottom: 1.5rem;">
        <!-- Tabela Workload por Owner -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            👥 Distribuição de Carga de Trabalho (Workload) por Owner Técnico
          </div>
          <table>
            <thead>
              <tr>
                <th>Owner Técnico</th>
                <th>Total Ativo</th>
                <th>Bucket Now (Imediato)</th>
                <th>Próximos 7d / 15d / 30d</th>
                <th>SLA Overdue / Due Soon</th>
                <th>Críticas / Altas</th>
                <th>Esforço (Baixo / Médio / Alto)</th>
                <th>Top Ativos / Top CVEs Afetados</th>
              </tr>
            </thead>
            <tbody id="treatment-workload-tbody">
              <tr>
                <td colspan="8" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando workload por owner...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Quick Wins -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: #10b981; border-bottom: 1px solid var(--border-color); background: rgba(16, 185, 129, 0.05);">
            🎯 Quick Wins (Ações de Baixo Esforço e Alto Impacto)
          </div>
          <table>
            <thead>
              <tr>
                <th>Ação Recomendada</th>
                <th>Dono Técnico</th>
                <th>Ativos Afetados</th>
                <th>Janela Sugerida</th>
                <th style="text-align: center;">Score</th>
                <th>Justificativa</th>
              </tr>
            </thead>
            <tbody id="treatment-wins-tbody">
              <tr>
                <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando quick wins...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Mudança Planejada / Alta Complexidade -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: #eab308; border-bottom: 1px solid var(--border-color); background: rgba(234, 179, 8, 0.05);">
            ⚙️ Janelas de Mudança Planejada (Alta Complexidade / Impacto)
          </div>
          <table>
            <thead>
              <tr>
                <th>Plano de Mudança</th>
                <th>Dono Técnico</th>
                <th>Ativos Afetados</th>
                <th>Esforço Estimado</th>
                <th>Status Janela</th>
                <th>Detalhamento Técnico</th>
              </tr>
            </thead>
            <tbody id="treatment-change-tbody">
              <tr>
                <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando janela de mudanças...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <!-- Tabela Alertas de Tratativa -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            🚨 Alertas do Plano de Tratativa
          </div>
          <table>
            <thead>
              <tr>
                <th style="width: 120px;">Gravidade</th>
                <th>Alerta Operacional</th>
                <th>Descrição Detalhada do Alerta</th>
              </tr>
            </thead>
            <tbody id="treatment-plan-alerts-tbody">
              <tr>
                <td colspan="3" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Carregando alertas do plano...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Tabela Agrupamentos Buckets & Esforço -->
        <div class="table-container" style="margin-bottom: 0;">
          <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); background: rgba(10, 14, 23, 0.2);">
            📊 Resumo Geral do Plano de Trabalho
          </div>
          <div style="padding: 1rem; display: flex; justify-content: space-around; font-size: 0.9rem;">
            <div style="flex: 1; border-right: 1px solid var(--border-color); padding: 0 1rem;">
              <h4 style="margin-bottom: 0.5rem; color: var(--text-muted);">Baldes de Prazos</h4>
              <ul id="treatment-summary-buckets" style="list-style: none; padding-left: 0;">
                <li>-</li>
              </ul>
            </div>
            <div style="flex: 1; padding: 0 1rem;">
              <h4 style="margin-bottom: 0.5rem; color: var(--text-muted);">Complexidade (Esforço)</h4>
              <ul id="treatment-summary-effort" style="list-style: none; padding-left: 0;">
                <li>-</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
      </section>

      <!-- Aba 8: Status & Auditoria -->
      <section id="tab-status" class="tab-panel">
        <!-- Painel de Execução Manual -->
    <div class="toolbar" style="justify-content: flex-start; gap: 1.5rem; align-items: center;">
      <button class="btn btn-run" id="btn-run-analysis" onclick="runAnalysis()">
        🔄 Executar análise agora
      </button>
      <span class="run-status" id="run-status">Pronto</span>
    </div>
        <!-- Status Operacional da Automação -->
    <div style="margin-top: 2rem; margin-bottom: 2rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
        <h2 style="font-size: 1.4rem; font-weight: 800; color: var(--text-main); letter-spacing: -0.02em;">🤖 Status Operacional da Automação</h2>
        <button class="btn" id="btn-refresh-status" onclick="refreshOperationalStatus()" style="font-weight: 600;">
          🔄 Atualizar status
        </button>
      </div>
      
      <!-- Grid de Status Cards -->
      <div class="grid-metrics" style="grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); margin-bottom: 1.5rem; gap: 1rem;">
        <div class="metric-card all" style="cursor: default; pointer-events: none;">
          <div class="metric-title">API SOAR</div>
          <div class="metric-value" id="status-api" style="font-size: 1.5rem; color: var(--text-muted); margin-top: 0.5rem;">Carregando...</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem;" id="status-api-detail">-</div>
        </div>
        <div class="metric-card all" style="cursor: default; pointer-events: none;">
          <div class="metric-title">Serviço de Relatório</div>
          <div class="metric-value" id="status-report-service" style="font-size: 1.5rem; color: var(--text-muted); margin-top: 0.5rem;">Carregando...</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem;" id="status-report-detail">-</div>
        </div>
        <div class="metric-card all" style="cursor: default; pointer-events: none;">
          <div class="metric-title">Agendamento (Timer)</div>
          <div class="metric-value" id="status-timer" style="font-size: 1.5rem; color: var(--text-muted); margin-top: 0.5rem;">Carregando...</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem;" id="status-timer-detail">-</div>
        </div>
        <div class="metric-card all" style="cursor: default; pointer-events: none;">
          <div class="metric-title">Último Relatório (HTML/JSON)</div>
          <div class="metric-value" id="status-latest-report" style="font-size: 1.2rem; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 0.5rem;">Carregando...</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem;" id="status-latest-report-detail">-</div>
        </div>
      </div>

      <!-- Tabela de Auditoria -->
      <div class="table-container" style="margin-bottom: 0;">
        <div style="padding: 1rem 1.25rem; font-weight: 700; color: var(--text-muted); border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; background: rgba(10, 14, 23, 0.2);">
          <span>📋 Últimas 10 Execuções Auditadas</span>
          <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: normal;" id="audit-last-checked"></span>
        </div>
        <table id="audit-table">
          <thead>
            <tr>
              <th>Data/Hora (UTC)</th>
              <th>Operador</th>
              <th>IP Origem</th>
              <th>Ação</th>
              <th>Resultado</th>
              <th>Status / Exit</th>
              <th>Mensagem</th>
            </tr>
          </thead>
          <tbody id="audit-table-body">
            <tr>
              <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">Carregando dados de auditoria...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
      </section>
    </main>
  </div>
<script>
    const rawData = {{VULN_DATA}};
    const scanMeta = { genTime: "{{GEN_TIME}}", cvssThresh: {{CVSS_THRESH}}, epssThresh: {{EPSS_THRESH}} };

    function safeGetEl(id) {
      return document.getElementById(id);
    }

    function safeSetHtml(id, html) {
      const el = safeGetEl(id);
      if (!el) {
        console.warn(`[SOAR Dashboard] Elemento não encontrado: ${id}`);
        return false;
      }
      el.innerHTML = html;
      return true;
    }

    function showChartEmptyState(containerId, message = 'Dados insuficientes para gerar o gráfico.') {
      const el = safeGetEl(containerId);
      if (!el) {
        console.warn(`[SOAR Dashboard] Container não encontrado: ${containerId}`);
        return;
      }
      el.innerHTML = `<div class="chart-empty-state" style="display: flex; height: 100%; align-items: center; justify-content: center; color: var(--text-muted); font-size: 0.85rem;">${message}</div>`;
    }

    let filteredData = [...rawData];
    let activePriorityFilter = 'ALL';
    let filterRansomwareOnly = false;
    let searchTerm = '';
    let currentPage = 1;
    let pageSize = 25;
    let currentSortColumn = 'priority';
    let currentSortOrder = 'asc';

    const priorityRank = { 'Priority 1+': 0, 'Priority 1': 1, 'Priority 2': 2, 'Priority 3': 3, 'Priority 4': 4 };

    
    function activateTab(tabId, updateHash = true) {
      const validTabs = [
        'overview',
        'risk',
        'assets',
        'sla',
        'governance',
        'trends',
        'treatment',
        'status'
      ];

      if (!validTabs.includes(tabId)) {
        tabId = 'overview';
      }

      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
        btn.setAttribute('aria-selected', 'false');
      });

      document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.remove('active');
        panel.setAttribute('hidden', 'hidden');
      });

      const targetBtn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
      const targetPanel = document.getElementById(`tab-${tabId}`);

      if (targetBtn) {
        targetBtn.classList.add('active');
        targetBtn.setAttribute('aria-selected', 'true');
      }

      if (targetPanel) {
        targetPanel.classList.add('active');
        targetPanel.removeAttribute('hidden');
      }

      if (updateHash) {
        history.replaceState(null, '', `#${tabId}`);
      }

      window.scrollTo({
        top: 0,
        behavior: 'smooth'
      });
    }

    document.addEventListener('DOMContentLoaded', () => {
      const hash = (window.location.hash || '#overview').replace('#', '');
      activateTab(hash, false);

      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', event => {
          event.preventDefault();
          activateTab(btn.dataset.tab);
        });
      });

      const overviewCvssEl = document.getElementById('overview-cvss-limit');
      if (overviewCvssEl) overviewCvssEl.innerText = scanMeta.cvssThresh.toFixed(1);
      const overviewEpssEl = document.getElementById('overview-epss-limit');
      if (overviewEpssEl) overviewEpssEl.innerText = (scanMeta.epssThresh * 100).toFixed(0);
      const genTimeEl = document.getElementById('generation-time');
      if (genTimeEl) genTimeEl.innerText = scanMeta.genTime;
      const cvssLimitEl = document.getElementById('cvss-limit');
      if (cvssLimitEl) cvssLimitEl.innerText = scanMeta.cvssThresh.toFixed(1);
      const epssLimitEl = document.getElementById('epss-limit');
      if (epssLimitEl) epssLimitEl.innerText = (scanMeta.epssThresh * 100).toFixed(0);
      calculateMetrics();
      applyFilters();
      refreshOperationalStatus();
      refreshRiskIntelligence();
      refreshAssetContext();
      refreshExposureContext();
      refreshSlaSummary();
      refreshRiskAcceptance();
      refreshTrendSummary();
      refreshTreatmentPlan();
    });

    window.addEventListener('hashchange', () => {
      const hash = (window.location.hash || '#overview').replace('#', '');
      activateTab(hash, false);
    });

    function calculateMetrics() {
      document.getElementById('count-total').innerText = rawData.length;
      document.getElementById('count-p1plus').innerText = rawData.filter(r => r.priority === 'Priority 1+').length;
      document.getElementById('count-p1').innerText = rawData.filter(r => r.priority === 'Priority 1').length;
      document.getElementById('count-p2').innerText = rawData.filter(r => r.priority === 'Priority 2').length;
      document.getElementById('count-p3').innerText = rawData.filter(r => r.priority === 'Priority 3').length;
      document.getElementById('count-p4').innerText = rawData.filter(r => r.priority === 'Priority 4').length;
    }

    function filterByPriority(priority) {
      activePriorityFilter = priority;
      document.querySelectorAll('.metric-card').forEach(card => card.classList.remove('active'));
      const mapping = { 'ALL': '.all', 'Priority 1+': '.p1plus', 'Priority 1': '.p1', 'Priority 2': '.p2', 'Priority 3': '.p3', 'Priority 4': '.p4' };
      document.querySelector(mapping[priority]).classList.add('active');
      applyFilters();
    }

    function onSearchChange() { searchTerm = document.getElementById('search-box').value.trim().toLowerCase(); applyFilters(); }
    function onRansomwareToggle() { filterRansomwareOnly = document.getElementById('filter-ransomware').checked; applyFilters(); }
    
    function resetFilters() {
      document.getElementById('search-box').value = '';
      document.getElementById('filter-ransomware').checked = false;
      searchTerm = ''; filterRansomwareOnly = false;
      filterByPriority('ALL');
    }

    function applyFilters() {
      filteredData = rawData.filter(item => {
        if (activePriorityFilter !== 'ALL' && item.priority !== activePriorityFilter) return false;
        if (filterRansomwareOnly && !item.is_ransomware) return false;
        if (searchTerm) {
          const matchText = `${item.agent_id} ${item.agent_name} ${item.cve} ${item.package} ${item.version} ${item.severity} ${item.criticality || ''} ${item.environment || ''} ${item.exposure || ''} ${item.asset_type || ''} ${item.exposure_level || ''} ${item.network_zone || ''} ${(item.top_services || []).join(' ')} ${(item.tags || []).join(' ')} ${item.sla_status || ''} ${item.technical_owner || ''} ${item.business_owner || ''}`.toLowerCase();
          if (!matchText.includes(searchTerm)) return false;
        }
        return true;
      });
      currentPage = 1;
      sortData();
    }

    function sortTable(column) {
      if (currentSortColumn === column) { currentSortOrder = currentSortOrder === 'asc' ? 'desc' : 'asc'; }
      else { currentSortColumn = column; currentSortOrder = 'asc'; }
      sortData();
    }

    function sortData() {
      filteredData.sort((a, b) => {
        let valA = a[currentSortColumn]; let valB = b[currentSortColumn];
        if (currentSortColumn === 'priority') { valA = priorityRank[a.priority]; valB = priorityRank[b.priority]; }
        if (valA === null || valA === undefined) valA = -1;
        if (valB === null || valB === undefined) valB = -1;
        if (typeof valA === 'string') { return currentSortOrder === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA); }
        else { return currentSortOrder === 'asc' ? valA - valB : valB - valA; }
      });
      renderTable();
    }

    function onChangePageSize() {
      const selectedValue = document.getElementById('page-size').value;
      pageSize = selectedValue === 'ALL' ? filteredData.length : parseInt(selectedValue, 10);
      currentPage = 1; renderTable();
    }

    function renderTable() {
      const tbody = document.getElementById('vuln-table-body');
      tbody.innerHTML = ''; const totalCount = filteredData.length;
      document.getElementById('pagination-total').innerText = totalCount;

      if (totalCount === 0) {
        document.getElementById('empty-state-msg').style.display = 'block';
        document.getElementById('vuln-table').style.display = 'none';
        document.getElementById('pagination-start').innerText = '0';
        document.getElementById('pagination-end').innerText = '0';
        renderPagination(0); return;
      }

      document.getElementById('empty-state-msg').style.display = 'none';
      document.getElementById('vuln-table').style.display = 'table';

      const maxPage = Math.ceil(totalCount / pageSize) || 1;
      if (currentPage > maxPage) currentPage = maxPage;

      const startIndex = (currentPage - 1) * pageSize;
      const endIndex = Math.min(startIndex + pageSize, totalCount);

      document.getElementById('pagination-start').innerText = startIndex + 1;
      document.getElementById('pagination-end').innerText = endIndex;

      filteredData.slice(startIndex, endIndex).forEach(item => {
        const tr = document.createElement('tr');
        let pClass = 'badge-p4';
        if (item.priority === 'Priority 1+') pClass = 'badge-p1plus';
        else if (item.priority === 'Priority 1') pClass = 'badge-p1';
        else if (item.priority === 'Priority 2') pClass = 'badge-p2';
        else if (item.priority === 'Priority 3') pClass = 'badge-p3';
        
        let cvssClass = 'score-none';
        if (item.cvss !== null) {
          if (item.cvss >= 7.0) cvssClass = 'score-high';
          else if (item.cvss >= 4.0) cvssClass = 'score-medium';
          else cvssClass = 'score-low';
        }

        const cvssStr = item.cvss !== null ? item.cvss.toFixed(1) : 'N/A';
        const epssStr = item.epss !== null ? (item.epss * 100).toFixed(2) + '%' : '0.00%';

        let tagsHtml = '';
        if (item.is_kev) tagsHtml += `<span class="badge badge-kev" style="margin-right: 0.25rem;">KEV</span>`;
        if (item.is_ransomware) tagsHtml += `<span class="badge badge-ransomware" style="margin-right: 0.25rem;">Ransomware</span>`;
        
        if (item.criticality && item.criticality !== 'unknown') {
          let critClass = 'badge-p4';
          if (item.criticality === 'critical') critClass = 'badge-p1plus';
          else if (item.criticality === 'high') critClass = 'badge-p1';
          else if (item.criticality === 'medium') critClass = 'badge-p2';
          tagsHtml += `<span class="badge ${critClass}" style="margin-right: 0.25rem; font-size: 0.7rem; text-transform: capitalize;">${item.criticality}</span>`;
        }
        if (item.environment && item.environment !== 'unknown') {
          tagsHtml += `<span class="badge badge-p3" style="margin-right: 0.25rem; font-size: 0.7rem; text-transform: capitalize;">${item.environment}</span>`;
        }
        if (item.exposure && item.exposure !== 'unknown') {
          let expoColor = 'rgba(255,255,255,0.05)';
          let expoText = '#9ca3af';
          if (item.exposure === 'internet') { expoColor = 'rgba(239, 68, 68, 0.15)'; expoText = '#f87171'; }
          else if (item.exposure === 'dmz') { expoColor = 'rgba(249, 115, 22, 0.15)'; expoText = '#fb923c'; }
          tagsHtml += `<span class="badge" style="margin-right: 0.25rem; font-size: 0.7rem; text-transform: capitalize; background: ${expoColor}; color: ${expoText}; border: 1px solid ${expoText}50;">${item.exposure}</span>`;
        }
        if (item.exposure_level && item.exposure_level !== 'unknown') {
          let expoColor = 'rgba(255,255,255,0.05)';
          let expoText = '#9ca3af';
          if (item.exposure_level === 'internet') { expoColor = 'rgba(239, 68, 68, 0.15)'; expoText = '#f87171'; }
          else if (item.exposure_level === 'dmz') { expoColor = 'rgba(249, 115, 22, 0.15)'; expoText = '#fb923c'; }
          tagsHtml += `<span class="badge" style="margin-right: 0.25rem; font-size: 0.7rem; text-transform: capitalize; background: ${expoColor}; color: ${expoText}; border: 1px solid ${expoText}50;">exp: ${item.exposure_level}</span>`;
        }
        if (item.network_zone && item.network_zone !== 'unknown') {
          tagsHtml += `<span class="badge" style="margin-right: 0.25rem; font-size: 0.7rem; text-transform: capitalize; background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3);">${item.network_zone.replace('_', ' ')}</span>`;
        }
        if (item.top_services && item.top_services.length > 0) {
          item.top_services.forEach(svc => {
            tagsHtml += `<span class="badge" style="margin-right: 0.25rem; font-size: 0.7rem; background: rgba(167, 139, 250, 0.1); color: #c084fc; border: 1px solid rgba(167, 139, 250, 0.2);">${svc}</span>`;
          });
        }
        if (item.asset_type && item.asset_type !== 'unknown') {
          tagsHtml += `<span class="badge" style="margin-right: 0.25rem; font-size: 0.7rem; text-transform: capitalize; background: rgba(167, 139, 250, 0.15); color: #c084fc; border: 1px solid rgba(167, 139, 250, 0.3);">${item.asset_type.replace('_', ' ')}</span>`;
        }

        if (item.sla_status && item.sla_status !== 'no_sla' && item.sla_status !== 'unknown') {
          let slaClass = 'badge-within-sla';
          let slaLabel = 'Dentro do SLA';
          if (item.sla_status === 'overdue') { slaClass = 'badge-overdue'; slaLabel = 'Vencido'; }
          else if (item.sla_status === 'due_soon') { slaClass = 'badge-due-soon'; slaLabel = 'Vence Logo'; }
          tagsHtml += `<span class="badge ${slaClass}" style="margin-right: 0.25rem; font-size: 0.7rem;">SLA: ${slaLabel}</span>`;
        }
        if (item.persistent) {
          tagsHtml += `<span class="badge badge-persistent" style="margin-right: 0.25rem; font-size: 0.7rem;">Persistente</span>`;
        }
        if (item.recurring) {
          tagsHtml += `<span class="badge badge-recurring" style="margin-right: 0.25rem; font-size: 0.7rem;">Recorrente</span>`;
        }
        
        if (!tagsHtml) tagsHtml = `<span style="color: var(--text-muted); font-style: italic;">Nenhum</span>`;

        tr.innerHTML = `
          <td><span class="badge ${pClass}">${item.priority}</span></td>
          <td><div style="font-weight: 600;">${item.agent_id}</div><div style="font-size: 0.75rem; color: var(--text-muted);">${item.agent_name}</div></td>
          <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${item.cve}" target="_blank">${item.cve}</a></td>
          <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${item.package}">${item.package}</td>
          <td><code style="font-size: 0.75rem; color: var(--text-muted);">${item.version}</code></td>
          <td><span class="score ${cvssClass}">${cvssStr}</span></td>
          <td><span style="font-weight: 500;">${epssStr}</span></td>
          <td><span>${item.severity}</span></td>
          <td>${tagsHtml}</td>
        `;
        tbody.appendChild(tr);
      });
      renderPagination(maxPage);
    }

    function renderPagination(maxPage) {
      const controls = document.getElementById('page-controls'); controls.innerHTML = '';
      if (maxPage <= 1) return;

      const prevBtn = document.createElement('div');
      prevBtn.className = `page-btn ${currentPage === 1 ? 'disabled' : ''}`; prevBtn.innerText = '‹';
      prevBtn.onclick = () => { if (currentPage > 1) { currentPage--; renderTable(); } };
      controls.appendChild(prevBtn);

      const range = 2;
      for (let i = 1; i <= maxPage; i++) {
        if (i === 1 || i === maxPage || (i >= currentPage - range && i <= currentPage + range)) {
          const pageBtn = document.createElement('div');
          pageBtn.className = `page-btn ${currentPage === i ? 'active' : ''}`; pageBtn.innerText = i;
          pageBtn.onclick = () => { currentPage = i; renderTable(); };
          controls.appendChild(pageBtn);
        } else if (i === currentPage - range - 1 || i === currentPage + range + 1) {
          const dot = document.createElement('div'); dot.className = 'page-btn disabled'; dot.innerText = '...';
          controls.appendChild(dot);
        }
      }

      const nextBtn = document.createElement('div');
      nextBtn.className = `page-btn ${currentPage === maxPage ? 'disabled' : ''}`; nextBtn.innerText = '›';
      nextBtn.onclick = () => { if (currentPage < maxPage) { currentPage++; renderTable(); } };
      controls.appendChild(nextBtn);
    }

    function exportFilteredCSV() {
      if (filteredData.length === 0) { alert("Sem dados para exportar."); return; }
      let csvContent = "data:text/csv;charset=utf-8,Agent ID,Agent Name,CVE ID,Priority,CVSS Score,Severity,EPSS Score,Package Name,Version,CISA KEV,Ransomware Use\\n";
      filteredData.forEach(r => {
        const row = [`"${r.agent_id}"`,`"${r.agent_name.replace(/"/g, '""')}"`,`"${r.cve}"`,`"${r.priority}"`,`"${r.cvss !== null ? r.cvss : ''}"`,`"${r.severity}"`,`"${r.epss !== null ? r.epss : ''}"`,`"${r.package.replace(/"/g, '""')}"`,`"${r.version.replace(/"/g, '""')}"`,`"${r.is_kev ? 'TRUE' : 'FALSE'}"`,`"${r.is_ransomware ? 'TRUE' : 'FALSE'}"`];
        csvContent += row.join(",") + "\\n";
      });
      const encodedUri = encodeURI(csvContent); const link = document.createElement("a"); link.setAttribute("href", encodedUri);
      link.setAttribute("download", `relatorio_wazuh_filtrado_${new Date().toISOString().slice(0,10)}.csv`);
      document.body.appendChild(link); link.click(); document.body.removeChild(link);
    }

    // ==========================================
    // EXECUTAR ANÁLISE AGORA (Fase 1)
    // ==========================================

    function setRunStatus(text, cssClass) {
      const el = document.getElementById('run-status');
      el.textContent = text;
      el.className = 'run-status' + (cssClass ? ' ' + cssClass : '');
    }

    function setRunButtonState(running) {
      const btn = document.getElementById('btn-run-analysis');
      btn.disabled = running;
      if (running) {
        btn.classList.add('running');
        btn.textContent = '⏳ Executando...';
      } else {
        btn.classList.remove('running');
        btn.textContent = '🔄 Executar análise agora';
      }
    }

    let lastMTime = null;
    let pollInterval = null;

    async function runAnalysis() {
      setRunButtonState(true);
      setRunStatus('Iniciando análise...', 'running');

      try {
        const statusRes = await fetch('/soar-api/status', {
          credentials: 'same-origin',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        if (statusRes.ok) {
          const statusData = await statusRes.json();
          lastMTime = statusData.index_html_mtime;
        }
      } catch (e) {
        console.warn('Não foi possível obter o mtime inicial:', e);
      }

      try {
        const response = await fetch('/soar-api/run-analysis', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });

        const data = await response.json();

        if (response.status === 202) {
          setRunStatus('⏳ Executando análise... O painel será atualizado automaticamente ao concluir.', 'running');
          startAnalysisPolling();
        } else if (response.status === 409) {
          setRunStatus('⚠ ' + (data.message || 'Já existe uma análise em execução.'), 'error');
          setRunButtonState(false);
        } else {
          setRunStatus('✗ Erro: ' + (data.message || 'Falha ao iniciar análise.'), 'error');
          setRunButtonState(false);
        }
      } catch (err) {
        setRunStatus('✗ Não foi possível comunicar com a API local.', 'error');
        setRunButtonState(false);
      }
    }

    function startAnalysisPolling() {
      if (pollInterval) clearInterval(pollInterval);
      pollInterval = setInterval(async () => {
        try {
          const response = await fetch('/soar-api/status', {
            credentials: 'same-origin',
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
          });
          if (response.ok) {
            const data = await response.json();
            const svcInfo = data.service_info || {};
            const currentMTime = data.index_html_mtime;
            const isActive = svcInfo.report_service_active;

            if (!isActive) {
              if (lastMTime && currentMTime !== lastMTime && currentMTime !== 'N/A') {
                clearInterval(pollInterval);
                setRunStatus('✓ Análise concluída com sucesso! Atualizando painel...', 'success');
                setTimeout(() => {
                  window.location.reload();
                }, 1000);
              } else {
                if (data.wrapper_exit_code !== undefined && data.wrapper_exit_code !== 0 && data.wrapper_exit_code !== -1) {
                  clearInterval(pollInterval);
                  setRunStatus(`✗ Falha na execução da análise (Exit Code: ${data.wrapper_exit_code}).`, 'error');
                  setRunButtonState(false);
                } else {
                  clearInterval(pollInterval);
                  setRunStatus('✓ Análise finalizada. Atualizando...', 'success');
                  setTimeout(() => {
                    window.location.reload();
                  }, 1000);
                }
              }
            } else {
              setRunStatus('⏳ Executando análise... O painel será atualizado automaticamente ao concluir.', 'running');
            }
          }
        } catch (e) {
          // Ignorar erros temporários de comunicação
        }
      }, 3000);
    }

    async function refreshOperationalStatus() {
      const btn = document.getElementById('btn-refresh-status');
      if (btn) btn.disabled = true;

      // 1. Fetch Health
      try {
        const hRes = await fetch('/soar-api/health', {
          credentials: 'same-origin',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        if (hRes.ok) {
          const hData = await hRes.json();
          if (hData && hData.status === 'ok') {
            document.getElementById('status-api').innerHTML = '<span style="color: #10b981;">● Online</span>';
            document.getElementById('status-api-detail').textContent = 'Versão: ' + (hData.version || '1.0.0');
          } else {
            document.getElementById('status-api').innerHTML = '<span style="color: #ef4444;">● Resposta Inválida</span>';
            document.getElementById('status-api-detail').textContent = 'Dados de health incorretos';
          }
        } else {
          document.getElementById('status-api').innerHTML = '<span style="color: #ef4444;">● Erro HTTP ' + hRes.status + '</span>';
          document.getElementById('status-api-detail').textContent = 'Endpoint ativo com erro';
        }
      } catch (err) {
        document.getElementById('status-api').innerHTML = '<span style="color: #ef4444;">● Offline / Inacessível</span>';
        document.getElementById('status-api-detail').textContent = 'Sem comunicação com o proxy';
      }

      // 2. Fetch Status
      try {
        const sRes = await fetch('/soar-api/status', {
          credentials: 'same-origin',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        if (sRes.ok) {
          const sData = await sRes.json();
          const svc = sData.service_info || {};

          // Report service status
          if (svc.report_service_active) {
            document.getElementById('status-report-service').innerHTML = '<span style="color: #f59e0b;">● Executando</span>';
          } else if (svc.report_service_status === 'active' || svc.report_service_status === 'inactive') {
            document.getElementById('status-report-service').innerHTML = '<span style="color: #10b981;">● Pronto (Ocioso)</span>';
          } else {
            document.getElementById('status-report-service').innerHTML = '<span style="color: #ef4444;">● ' + (svc.report_service_status || 'desconhecido') + '</span>';
          }
          document.getElementById('status-report-detail').textContent = 'Último Exit Code: ' + (sData.wrapper_exit_code !== undefined ? sData.wrapper_exit_code : '-');

          // Timer Status
          if (svc.timer_status === 'active') {
            document.getElementById('status-timer').innerHTML = '<span style="color: #10b981;">● Ativo</span>';
            let nextTrigger = 'N/A';
            if (svc.next_trigger) {
              nextTrigger = isNaN(svc.next_trigger) ? svc.next_trigger : new Date(parseInt(svc.next_trigger)/1000).toLocaleString();
            }
            document.getElementById('status-timer-detail').textContent = 'Próxima: ' + nextTrigger;
          } else {
            document.getElementById('status-timer').innerHTML = '<span style="color: #ef4444;">● ' + (svc.timer_status || 'Inativo') + '</span>';
            document.getElementById('status-timer-detail').textContent = 'Agendamento desabilitado';
          }

          // HTML / JSON Mtimes
          const indexTime = sData.index_html_mtime && sData.index_html_mtime !== 'N/A' ? new Date(sData.index_html_mtime).toLocaleString() : 'N/A';
          const jsonTime = sData.latest_json_mtime && sData.latest_json_mtime !== 'N/A' ? new Date(sData.latest_json_mtime).toLocaleString() : 'N/A';
          document.getElementById('status-latest-report').textContent = sData.latest_report || 'N/A';
          document.getElementById('status-latest-report').title = sData.latest_report || '';
          document.getElementById('status-latest-report-detail').innerHTML = 'HTML: ' + indexTime + '<br/>JSON: ' + jsonTime;
        } else {
          document.getElementById('status-report-service').innerHTML = '<span style="color: #ef4444;">● Erro</span>';
          document.getElementById('status-timer').innerHTML = '<span style="color: #ef4444;">● Erro</span>';
          document.getElementById('status-latest-report').innerHTML = '<span style="color: #ef4444;">● Erro</span>';
        }
      } catch (err) {
        document.getElementById('status-report-service').innerHTML = '<span style="color: #ef4444;">● Falha</span>';
        document.getElementById('status-timer').innerHTML = '<span style="color: #ef4444;">● Falha</span>';
        document.getElementById('status-latest-report').innerHTML = '<span style="color: #ef4444;">● Falha</span>';
      }

      // 3. Fetch Audit Logs
      try {
        const aRes = await fetch('/soar-api/audit-actions?limit=10', {
          credentials: 'same-origin',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        if (aRes.ok) {
          const aData = await aRes.json();
          const tbody = document.getElementById('audit-table-body');
          tbody.innerHTML = '';
          const actions = aData.actions || [];
          document.getElementById('audit-last-checked').textContent = 'Atualizado em: ' + new Date().toLocaleTimeString();

          if (actions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhum registro de auditoria encontrado.</td></tr>';
          } else {
            actions.forEach(act => {
              const tr = document.createElement('tr');
              const actTime = act.timestamp ? new Date(act.timestamp).toLocaleString() : 'N/A';
              
              let resBadge = '<span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text-muted); border: 1px solid var(--border-color);">Desconhecido</span>';
              if (act.result === 'success') {
                resBadge = '<span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3);">Sucesso</span>';
              } else if (act.result === 'rejected') {
                resBadge = '<span class="badge" style="background: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3);">Rejeitado</span>';
              } else if (act.result === 'error') {
                resBadge = '<span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3);">Erro</span>';
              }

              const exitVal = act.exit_code !== undefined ? act.exit_code : '-';
              
              tr.innerHTML = `
                <td>${actTime}</td>
                <td style="font-weight: 600;">${act.remote_user || 'unknown'}</td>
                <td><code>${act.client_ip || 'unknown'}</code></td>
                <td><code>${act.action || 'run-analysis'}</code></td>
                <td>${resBadge}</td>
                <td><code>${exitVal}</code></td>
                <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${act.message || ''}">${act.message || '-'}</td>
              `;
              tbody.appendChild(tr);
            });
          }
        }
      } catch (err) {
        document.getElementById('audit-table-body').innerHTML = '<tr><td colspan="7" style="text-align: center; color: #ef4444; padding: 1.5rem;">Falha ao carregar registros de auditoria.</td></tr>';
      }

      
      const ovStatApi = document.getElementById('overview-status-api');
      const ovStatSvc = document.getElementById('overview-status-service');
      if (ovStatApi && ovStatSvc) {
        ovStatApi.innerHTML = document.getElementById('status-api').innerHTML;
        ovStatSvc.innerHTML = 'Report Service: ' + document.getElementById('status-report-service').innerHTML;
      }
if (btn) btn.disabled = false;
    }

    async function refreshRiskIntelligence() {
      const btn = document.getElementById('btn-refresh-risk');
      if (btn) btn.disabled = true;

      // 1. Fetch Risk Summary
      try {
        const rRes = await fetch('/soar-api/risk-summary', {
          credentials: 'same-origin',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        if (rRes.ok) {
          const rData = await rRes.json();
          const sum = rData.summary || {};
          
          document.getElementById('risk-total').textContent = sum.total_vulnerabilities !== undefined ? sum.total_vulnerabilities : '-';
          document.getElementById('risk-critical').textContent = sum.critical !== undefined ? sum.critical : '-';
          document.getElementById('risk-high').textContent = sum.high !== undefined ? sum.high : '-';
          document.getElementById('risk-kev').textContent = sum.kev_count !== undefined ? sum.kev_count : '-';
          document.getElementById('risk-epss').textContent = sum.epss_high_count !== undefined ? sum.epss_high_count : '-';
          
          const ovTotal = document.getElementById('overview-total-vulns');
          if (ovTotal) ovTotal.textContent = sum.total_vulnerabilities !== undefined ? sum.total_vulnerabilities : '-';
          const ovCrit = document.getElementById('overview-risk-critical');
          if (ovCrit) ovCrit.textContent = sum.critical !== undefined ? sum.critical : '-';
          const ovHigh = document.getElementById('overview-risk-high');
          if (ovHigh) ovHigh.textContent = sum.high !== undefined ? sum.high : '-';
          const ovKev = document.getElementById('overview-risk-kev');
          if (ovKev) ovKev.textContent = sum.kev_count !== undefined ? sum.kev_count : '-';
          const ovEpss = document.getElementById('overview-risk-epss');
          if (ovEpss) ovEpss.textContent = sum.epss_high_count !== undefined ? sum.epss_high_count : '-';
          const ovAgents = document.getElementById('overview-risk-agents');
          if (ovAgents) ovAgents.textContent = sum.affected_agents !== undefined ? sum.affected_agents : '-';
          
          if (rData.timestamp) {
            const rDate = new Date(rData.timestamp);
            const now = new Date();
            const diffMs = now - rDate;
            const diffMins = Math.max(0, Math.floor(diffMs / 60000));
            let ageStr = '';
            if (diffMins < 60) {
              ageStr = diffMins + ' min' + (diffMins !== 1 ? 's' : '') + ' atrás';
            } else if (diffMins < 1440) {
              const diffHours = Math.floor(diffMins / 60);
              ageStr = diffHours + ' hora' + (diffHours !== 1 ? 's' : '') + ' atrás';
            } else {
              const diffDays = Math.floor(diffMins / 1440);
              ageStr = diffDays + ' dia' + (diffDays !== 1 ? 's' : '') + ' atrás';
            }
            document.getElementById('overview-generation-age').textContent = ageStr;
            document.getElementById('overview-generation-time').textContent = 'Gerado em: ' + rDate.toLocaleString();
          }
document.getElementById('risk-agents').textContent = sum.affected_agents !== undefined ? sum.affected_agents : '-';

          // Calcular idade do relatório
          if (rData.timestamp) {
            const reportDate = new Date(rData.timestamp);
            const now = new Date();
            const diffMs = now - reportDate;
            const diffMins = Math.max(0, Math.floor(diffMs / 60000));
            if (diffMins < 60) {
              document.getElementById('risk-age').textContent = diffMins + ' min' + (diffMins !== 1 ? 's' : '') + ' atrás';
            } else if (diffMins < 1440) {
              const diffHours = Math.floor(diffMins / 60);
              document.getElementById('risk-age').textContent = diffHours + ' hora' + (diffHours !== 1 ? 's' : '') + ' atrás';
            } else {
              const diffDays = Math.floor(diffMins / 1440);
              document.getElementById('risk-age').textContent = diffDays + ' dia' + (diffDays !== 1 ? 's' : '') + ' atrás';
            }
            document.getElementById('risk-age').title = reportDate.toLocaleString();
          } else {
            document.getElementById('risk-age').textContent = 'N/A';
          }

          // Atualizar Alertas
          const alertsContainer = document.getElementById('risk-alerts-container');
          alertsContainer.innerHTML = '';
          const alerts = rData.alerts || [];
          if (alerts.length === 0) {
            alertsContainer.innerHTML = '<div class="alert-item alert-info">✓ Nenhum alerta de risco pendente. Ambiente estável.</div>';
          } else {
            alerts.forEach(al => {
              const div = document.createElement('div');
              let alertClass = 'alert-info';
              if (al.level === 'critical') alertClass = 'alert-critical';
              else if (al.level === 'warning') alertClass = 'alert-warning';
              div.className = 'alert-item ' + alertClass;
              div.innerHTML = `<strong>${al.title || 'Alerta'}:</strong> ${al.message || ''}`;
              alertsContainer.appendChild(div);
            });
          }

          // Atualizar Top 10 Prioridades
          const priorities = Array.isArray(rData.top_priorities) ? rData.top_priorities : [];
          const prioritiesTbody = document.getElementById('risk-priorities-tbody');
          if (prioritiesTbody) {
            prioritiesTbody.innerHTML = '';
            if (priorities.length === 0) {
              prioritiesTbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 2rem;">Nenhuma prioridade de correção detectada.</td></tr>';
            } else {
              priorities.forEach(p => {
                const tr = document.createElement('tr');
                
                const kevBadge = p.kev 
                  ? '<span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3);">Sim</span>' 
                  : '<span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text-muted); border: 1px solid var(--border-color);">Não</span>';
                
                const epssVal = p.epss !== null && p.epss !== undefined ? (p.epss * 100).toFixed(2) + '%' : '-';
                
                let sevColor = 'var(--text-muted)';
                if (String(p.severity).toLowerCase() === 'critical') sevColor = '#f87171';
                else if (String(p.severity).toLowerCase() === 'high') sevColor = '#fb923c';
                
                let scoreColor = '#34d399';
                if (p.priority_score >= 80) scoreColor = '#f87171';
                else if (p.priority_score >= 50) scoreColor = '#fb923c';
                
                tr.innerHTML = `
                  <td style="font-weight: 700; text-align: center;">${p.rank || '-'}</td>
                  <td style="font-weight: 700; color: var(--text-main);">${p.cve || '-'}</td>
                  <td><code>${p.package || '-'}</code></td>
                  <td><span style="font-weight: 600; color: ${sevColor};">${p.severity || '-'}</span></td>
                  <td style="text-align: center;">${kevBadge}</td>
                  <td><code style="color: #a78bfa;">${epssVal}</code></td>
                  <td style="text-align: center; font-weight: 600; color: #3b82f6;">${p.affected_agents || 0}</td>
                  <td style="text-align: center;"><span class="badge" style="font-weight: 800; background: rgba(255,255,255,0.05); color: ${scoreColor}; border: 1px solid ${scoreColor}50;">${p.priority_score || 0}</span></td>
                  <td style="font-size: 0.85rem; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${p.reason || ''}">${p.reason || '-'}</td>
                `;
                prioritiesTbody.appendChild(tr);
              });
            }
          }

          // ==========================================
          // Fase 3H.2 - Renderizar Gráficos de Risco
          // ==========================================
          
          // 1. Visão Geral - Donut de Severidade
          if (document.getElementById('overview-chart-severity')) {
            renderDonutChart('overview-chart-severity', [
              { label: 'Críticas', value: sum.critical || 0, color: '#f87171' },
              { label: 'Altas', value: sum.high || 0, color: '#fb923c' },
              { label: 'Médias', value: sum.medium || 0, color: '#facc15' },
              { label: 'Baixas', value: sum.low || 0, color: '#3b82f6' }
            ], { totalLabel: 'Severidade' });
          }

          // 2. Visão Geral - Top 10 Prioridades Table Compacta
          const ovTop10Tbody = document.getElementById('overview-top10-tbody');
          if (ovTop10Tbody) {
            ovTop10Tbody.innerHTML = '';
            const top10 = priorities.slice(0, 10);
            if (top10.length === 0) {
              ovTop10Tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhuma prioridade de correção detectada.</td></tr>';
            } else {
              top10.forEach(p => {
                const tr = document.createElement('tr');
                const epssVal = p.epss !== null && p.epss !== undefined ? (p.epss * 100).toFixed(2) + '%' : '-';
                let sevColor = 'var(--text-muted)';
                if (String(p.severity).toLowerCase() === 'critical') sevColor = '#f87171';
                else if (String(p.severity).toLowerCase() === 'high') sevColor = '#fb923c';
                
                let pClass = 'badge-p4';
                if (p.priority === 'Priority 1+') pClass = 'badge-p1plus';
                else if (p.priority === 'Priority 1') pClass = 'badge-p1';
                else if (p.priority === 'Priority 2') pClass = 'badge-p2';
                else if (p.priority === 'Priority 3') pClass = 'badge-p3';

                let tagsHtml = '';
                if (p.kev) tagsHtml += `<span class="badge badge-kev" style="margin-right: 0.25rem;">KEV</span>`;
                
                tr.innerHTML = `
                  <td style="font-weight: 700; text-align: center;">${p.rank || '-'}</td>
                  <td><span class="badge ${pClass}">${p.priority || 'P1'}</span></td>
                  <td style="text-align: center; font-weight: 600; color: #3b82f6;">${p.affected_agents || 0}</td>
                  <td style="font-weight: 700; color: var(--text-main);">${p.cve || '-'}</td>
                  <td><code>${p.package || '-'}</code></td>
                  <td><code>${p.cvss !== null && p.cvss !== undefined ? p.cvss.toFixed(1) : '-'}</code></td>
                  <td><code style="color: #a78bfa;">${epssVal}</code></td>
                  <td><span style="font-weight: 600; color: ${sevColor};">${p.severity || '-'}</span></td>
                  <td style="font-size: 0.85rem;" title="${p.reason || ''}">${tagsHtml}${p.reason || '-'}</td>
                `;
                ovTop10Tbody.appendChild(tr);
              });
            }
          }

          // 3. Risco & Prioridades - Donut de Severidade
          if (document.getElementById('risk-chart-severity')) {
            renderDonutChart('risk-chart-severity', [
              { label: 'Críticas', value: sum.critical || 0, color: '#f87171' },
              { label: 'Altas', value: sum.high || 0, color: '#fb923c' },
              { label: 'Médias', value: sum.medium || 0, color: '#facc15' },
              { label: 'Baixas', value: sum.low || 0, color: '#3b82f6' }
            ], { totalLabel: 'Severidade' });
          }

          // 4. Risco & Prioridades - Distribuição por Prioridade
          let pCount = { 'P1+': 0, 'P1': 0, 'P2': 0, 'P3': 0, 'P4': 0 };
          rawData.forEach(r => {
            if (r.priority === 'Priority 1+') pCount['P1+']++;
            else if (r.priority === 'Priority 1') pCount['P1']++;
            else if (r.priority === 'Priority 2') pCount['P2']++;
            else if (r.priority === 'Priority 3') pCount['P3']++;
            else if (r.priority === 'Priority 4') pCount['P4']++;
          });
          if (document.getElementById('risk-chart-priority')) {
            renderStackedBar('risk-chart-priority', [
              { label: 'P1+', value: pCount['P1+'], color: '#ef4444' },
              { label: 'P1', value: pCount['P1'], color: '#f97316' },
              { label: 'P2', value: pCount['P2'], color: '#eab308' },
              { label: 'P3', value: pCount['P3'], color: '#3b82f6' },
              { label: 'P4', value: pCount['P4'], color: '#10b981' }
            ]);
          }

          // 5. Risco & Prioridades - KEV x EPSS Alto
          if (document.getElementById('risk-chart-kev-epss')) {
            renderMetricComparison('risk-chart-kev-epss', [
              { label: 'CISA KEV Ativo', value: sum.kev_count || 0, color: '#fb923c' },
              { label: 'EPSS >= 20%', value: sum.epss_high_count || 0, color: '#a78bfa' }
            ]);
          }

          // 6. Risco & Prioridades - Top Pacotes por Recorrência
          let pkgCounts = {};
          rawData.forEach(r => {
            if (r.package_name) {
              pkgCounts[r.package_name] = (pkgCounts[r.package_name] || 0) + 1;
            }
          });
          let topPkgs = Object.entries(pkgCounts)
            .map(([pkg, val]) => ({ label: pkg, value: val, color: '#60a5fa' }))
            .sort((a,b) => b.value - a.value)
            .slice(0, 5);
          if (document.getElementById('risk-chart-packages')) {
            renderMiniBarChart('risk-chart-packages', topPkgs);
          }

          // 7. Risco & Prioridades - Top Agentes por Risco (contagem de vulns)
          let agentCounts = {};
          rawData.forEach(r => {
            if (r.agent_name) {
              agentCounts[r.agent_name] = (agentCounts[r.agent_name] || 0) + 1;
            }
          });
          let topAgents = Object.entries(agentCounts)
            .map(([agent, val]) => ({ label: agent, value: val, color: '#f87171' }))
            .sort((a,b) => b.value - a.value)
            .slice(0, 5);
          if (document.getElementById('risk-chart-agents')) {
            renderMiniBarChart('risk-chart-agents', topAgents);
          }

        } else {
          document.getElementById('risk-alerts-container').innerHTML = '<div class="alert-item alert-critical">Erro HTTP ao carregar inteligência de risco (' + rRes.status + ').</div>';
          clearRiskCharts('Erro HTTP');
        }
      } catch (err) {
        document.getElementById('risk-alerts-container').innerHTML = '<div class="alert-item alert-critical">Falha de rede ao carregar inteligência de risco.</div>';
        clearRiskCharts(err.message);
      }

      function clearRiskCharts(msg) {
        const charts = ['overview-chart-severity', 'risk-chart-severity', 'risk-chart-priority', 'risk-chart-kev-epss', 'risk-chart-packages', 'risk-chart-agents'];
        charts.forEach(id => {
          const c = document.getElementById(id);
          if (c) c.innerHTML = `<div style="display: flex; height: 100%; align-items: center; justify-content: center; color: var(--text-muted); font-size: 0.85rem;">Gráfico indisponível: ${msg}</div>`;
        });
        const ovTop10 = document.getElementById('overview-top10-tbody');
        if (ovTop10) ovTop10.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Tabela indisponível: ${msg}</td></tr>`;
      }

      // 2. Fetch Risk Delta
      try {
        const dRes = await fetch('/soar-api/risk-delta', {
          credentials: 'same-origin',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        if (dRes.ok) {
          const dData = await dRes.json();
          const delta = dData.delta || {};
          
          const setDeltaMetricValue = (id, val, isDelta = false, isGood = false) => {
            const el = document.getElementById(id);
            if (!el) return;
            if (val === undefined || val === null || dData.status === 'no_baseline') {
              el.textContent = '-';
              el.className = 'metric-value';
              el.style.color = '';
              return;
            }
            el.textContent = val;
            if (isDelta) {
              if (val > 0) {
                el.className = 'metric-value ' + (isGood ? 'delta-badge-resolved' : 'delta-badge-new');
                el.textContent = '+' + val;
                el.style.color = isGood ? '#34d399' : '#f87171';
              } else {
                el.className = 'metric-value';
                el.style.color = '';
              }
            }
          };

          setDeltaMetricValue('delta-new', delta.new_vulnerabilities, true, false);
          setDeltaMetricValue('delta-resolved', delta.resolved_vulnerabilities, true, true);
          setDeltaMetricValue('delta-persistent', delta.persistent_vulnerabilities, false);
          setDeltaMetricValue('delta-new-kev', delta.new_kev, true, false);
          setDeltaMetricValue('delta-new-critical', delta.new_critical, true, false);
          setDeltaMetricValue('delta-worsened-agents', delta.agents_worsened, true, false);
          setDeltaMetricValue('delta-improved-agents', delta.agents_improved, true, true);
        }
      } catch (err) {
        // Silently handle delta error
      }

      if (btn) btn.disabled = false;
    }

    async function refreshAssetContext() {
      const btn = document.getElementById('btn-refresh-assets');
      if (btn) btn.disabled = true;

      try {
        const response = await fetch('/soar-api/asset-context', {
          credentials: 'same-origin',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        if (response.ok) {
          const data = await response.json();
          if (data.status === 'ok') {
            const assets = data.assets || {};
            const expo = data.exposure || {};
            
            document.getElementById('assets-total').textContent = assets.total_seen !== undefined ? assets.total_seen : '-';
            document.getElementById('assets-classified').textContent = assets.classified !== undefined ? assets.classified : '-';
            document.getElementById('assets-unclassified').textContent = assets.unclassified !== undefined ? assets.unclassified : '-';
            document.getElementById('assets-critical-count').textContent = assets.critical !== undefined ? assets.critical : '-';
            document.getElementById('assets-unknown-crit').textContent = assets.unknown !== undefined ? assets.unknown : '-';
            
            const exposed = (expo.internet || 0) + (expo.dmz || 0);
            document.getElementById('assets-exposed-count').textContent = exposed;
            
            const alertEl = document.getElementById('assets-alerts-container');
            if (assets.unclassified > 0) {
              alertEl.style.display = 'block';
            } else {
              alertEl.style.display = 'none';
            }
            
            const riskTbody = document.getElementById('assets-risk-tbody');
            riskTbody.innerHTML = '';
            const topAssets = data.top_risky_assets || [];
            if (topAssets.length === 0) {
              riskTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhum ativo listado.</td></tr>';
            } else {
              topAssets.forEach(a => {
                const tr = document.createElement('tr');
                let critColor = 'var(--text-muted)';
                if (a.criticality === 'critical') critColor = '#f87171';
                else if (a.criticality === 'high') critColor = '#fb923c';
                
                tr.innerHTML = `
                  <td><code>${a.agent_id}</code></td>
                  <td style="font-weight: 600;">${a.agent_name}</td>
                  <td><span style="font-weight:600; color:${critColor}">${a.criticality}</span></td>
                  <td><code>${a.exposure}</code></td>
                  <td><code>${a.asset_type}</code></td>
                  <td style="text-align: right; font-weight:700; color:#fb923c">${a.risk_score}</td>
                `;
                riskTbody.appendChild(tr);
              });
            }
            
            const pendingTbody = document.getElementById('assets-pending-tbody');
            pendingTbody.innerHTML = '';
            const pendingAssets = data.unclassified_assets || [];
            if (pendingAssets.length === 0) {
              pendingTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #10b981; padding: 1.5rem; font-weight:600;">✓ Todos os ativos estão devidamente classificados!</td></tr>';
            } else {
              pendingAssets.forEach(a => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                  <td><code>${a.agent_id}</code></td>
                  <td style="font-weight: 600;">${a.agent_name}</td>
                  <td><span class="badge badge-p2" style="background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3);">Pendente</span></td>
                  <td style="font-style: italic; color: var(--text-muted);">Adicionar à seção "agents" do assets_context.json</td>
                `;
                pendingTbody.appendChild(tr);
              });
            }

            // ==========================================
            // Fase 3H.2 - Renderizar Gráficos de Ativos
            // ==========================================
            
            // 1. Ativos por Criticidade
            if (document.getElementById('assets-chart-criticality')) {
              renderDonutChart('assets-chart-criticality', [
                { label: 'Crítico', value: assets.critical || 0, color: '#f87171' },
                { label: 'Alto', value: assets.high || 0, color: '#fb923c' },
                { label: 'Médio', value: assets.medium || 0, color: '#facc15' },
                { label: 'Baixo', value: assets.low || 0, color: '#34d399' },
                { label: 'Desconhecido', value: assets.unknown || 0, color: '#9ca3af' }
              ], { totalLabel: 'Criticidade' });
            }

            // 2. Top Ativos por Risco Contextual
            let topRisky = topAssets.slice(0, 5).map(a => ({
              label: a.agent_name,
              value: a.risk_score,
              color: '#f87171'
            }));
            if (document.getElementById('assets-chart-top-risk')) {
              renderMiniBarChart('assets-chart-top-risk', topRisky);
            }

          } else {
            showFallbackAssets(data.message || 'Status degraded');
          }
        } else {
          showFallbackAssets('Falha HTTP ao contatar a API');
        }
      } catch (e) {
        showFallbackAssets('Erro de comunicação com o servidor');
      } finally {
        if (btn) btn.disabled = false;
      }
    }
    
    function showFallbackAssets(msg) {
      document.getElementById('assets-total').textContent = '-';
      document.getElementById('assets-classified').textContent = '-';
      document.getElementById('assets-unclassified').textContent = '-';
      document.getElementById('assets-critical-count').textContent = '-';
      document.getElementById('assets-exposed-count').textContent = '-';
      document.getElementById('assets-unknown-crit').textContent = '-';
      document.getElementById('assets-alerts-container').style.display = 'none';
      
      document.getElementById('assets-risk-tbody').innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Contexto indisponível: ${msg}</td></tr>`;
      document.getElementById('assets-pending-tbody').innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Indisponível: ${msg}</td></tr>`;

      const charts = ['assets-chart-criticality', 'assets-chart-top-risk'];
      charts.forEach(id => {
        const c = document.getElementById(id);
        if (c) c.innerHTML = `<div style="display: flex; height: 100%; align-items: center; justify-content: center; color: var(--text-muted); font-size: 0.85rem;">Gráfico indisponível: ${msg}</div>`;
      });
    }

    async function refreshExposureContext() {
      const btn = document.getElementById('btn-refresh-exposure');
      if (btn) btn.disabled = true;

      try {
        const response = await fetch('/soar-api/exposure-context', {
          credentials: 'same-origin',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        if (response.ok) {
          const data = await response.json();
          const assets = data.assets || {};
          const services = data.services || {};
          const external = data.external_assets || {};
          const alerts = data.exposure_alerts || [];
          const topAssets = data.top_exposed_assets || [];
          const missingAssets = data.assets_missing_exposure_context || [];
          const extList = data.external_assets_list || [];
          
          document.getElementById('expo-with-context').textContent = assets.with_exposure_context !== undefined ? assets.with_exposure_context : '-';
          document.getElementById('expo-without-context').textContent = assets.without_exposure_context !== undefined ? assets.without_exposure_context : '-';
          document.getElementById('expo-internet-facing').textContent = assets.internet_facing !== undefined ? assets.internet_facing : '-';
          document.getElementById('expo-dmz').textContent = assets.dmz !== undefined ? assets.dmz : '-';
          document.getElementById('expo-critical-services').textContent = services.critical_services !== undefined ? services.critical_services : '-';
          document.getElementById('expo-internet-services').textContent = services.internet_exposed_services !== undefined ? services.internet_exposed_services : '-';
          document.getElementById('expo-external-no-agent').textContent = external.without_wazuh_agent !== undefined ? external.without_wazuh_agent : '-';
          document.getElementById('expo-alerts-count').textContent = alerts.length;
          
          const alertEl = document.getElementById('exposure-alerts-container');
          if (alerts.length > 0) {
            alertEl.style.display = 'flex';
            alertEl.innerHTML = '';
            alerts.forEach(al => {
              const div = document.createElement('div');
              let alertClass = 'alert-info';
              if (al.level === 'critical') alertClass = 'alert-critical';
              else if (al.level === 'warning') alertClass = 'alert-warning';
              div.className = 'alert-item ' + alertClass;
              div.innerHTML = `<strong>${al.title || 'Alerta'}:</strong> ${al.message || ''}`;
              alertEl.appendChild(div);
            });
          } else {
            alertEl.style.display = 'none';
          }
          
          // Render top_exposed_assets table
          const topTbody = document.getElementById('expo-top-assets-tbody');
          topTbody.innerHTML = '';
          if (topAssets.length === 0) {
            topTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhum ativo exposto.</td></tr>';
          } else {
            topAssets.forEach(a => {
              const tr = document.createElement('tr');
              let badgeColor = 'rgba(255,255,255,0.05)';
              let badgeText = '#9ca3af';
              if (a.exposure_level === 'internet') { badgeColor = 'rgba(239, 68, 68, 0.15)'; badgeText = '#f87171'; }
              else if (a.exposure_level === 'dmz') { badgeColor = 'rgba(249, 115, 22, 0.15)'; badgeText = '#fb923c'; }
              
              tr.innerHTML = `
                <td><code>${a.agent_id}</code></td>
                <td style="font-weight: 600;">${a.agent_name}</td>
                <td><span class="badge" style="background: ${badgeColor}; color: ${badgeText}; border: 1px solid ${badgeText}50;">${a.exposure_level}</span></td>
                <td><code>${a.network_zone}</code></td>
                <td><code>${a.internet_facing ? 'Sim' : 'Não'}</code></td>
                <td style="text-align: right; font-weight:700; color:#fb923c">${a.exposure_score}</td>
              `;
              topTbody.appendChild(tr);
            });
          }
          
          // Render assets_missing_exposure_context table
          const missingTbody = document.getElementById('expo-missing-tbody');
          missingTbody.innerHTML = '';
          if (missingAssets.length === 0) {
            missingTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #10b981; padding: 1.5rem; font-weight:600;">✓ Todos os ativos vulneráveis possuem contexto de exposição!</td></tr>';
          } else {
            missingAssets.forEach(a => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td><code>${a.agent_id}</code></td>
                <td style="font-weight: 600;">${a.agent_name}</td>
                <td><span class="badge badge-p2" style="background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3);">Pendente</span></td>
                <td style="font-style: italic; color: var(--text-muted);">Adicionar à seção "agents" do exposure_context.json</td>
              `;
              missingTbody.appendChild(tr);
            });
          }
          
          // Render exposure_alerts table
          const alertsTbody = document.getElementById('expo-alerts-tbody');
          alertsTbody.innerHTML = '';
          if (alerts.length === 0) {
            alertsTbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: #10b981; padding: 1.5rem; font-weight:600;">✓ Nenhuma inconsistência de exposição/superfície detectada!</td></tr>';
          } else {
            alerts.forEach(al => {
              const tr = document.createElement('tr');
              let lvlBadge = '<span class="badge badge-p4">Info</span>';
              if (al.level === 'critical') lvlBadge = '<span class="badge badge-p1plus">Crítico</span>';
              else if (al.level === 'warning') lvlBadge = '<span class="badge badge-p1">Aviso</span>';
              
              tr.innerHTML = `
                <td>${lvlBadge}</td>
                <td style="font-weight: 600;">${al.title || 'Alerta'}</td>
                <td>${al.message || ''}</td>
              `;
              alertsTbody.appendChild(tr);
            });
          }

          // Render external_assets table
          const extTbody = document.getElementById('expo-external-tbody');
          extTbody.innerHTML = '';
          if (extList.length === 0) {
            extTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhum ativo externo cadastrado.</td></tr>';
          } else {
            extList.forEach(ext => {
              const tr = document.createElement('tr');
              let agentBadge = ext.has_wazuh_agent 
                ? '<span class="badge badge-p4">Com Agente</span>' 
                : '<span class="badge badge-p1plus">Sem Agente</span>';
              tr.innerHTML = `
                <td><div style="font-weight:600;">${ext.asset_name || '-'}</div><div>${agentBadge}</div></td>
                <td><code>${ext.ip || '-'}</code><br/><code style="font-size:0.75rem;">${ext.hostname || '-'}</code></td>
                <td><span class="badge badge-p1">${ext.exposure_level || '-'}</span><br/><code style="font-size:0.75rem;">${ext.network_zone || '-'}</code></td>
                <td><code>${ext.source || '-'}</code><br/><span style="font-size:0.75rem; color:var(--text-muted);">Confiança: ${ext.confidence || '-'}</span></td>
              `;
              extTbody.appendChild(tr);
            });
          }

          // ==========================================
          // Fase 3H.2 - Renderizar Gráficos de Exposição
          // ==========================================
          
          // 1. Ativos por Exposição
          const internalExpo = Math.max(0, (assets.with_exposure_context || 0) - (assets.internet_facing || 0) - (assets.dmz || 0));
          if (document.getElementById('assets-chart-exposure')) {
            renderDonutChart('assets-chart-exposure', [
              { label: 'Internet', value: assets.internet_facing || 0, color: '#ef4444' },
              { label: 'DMZ', value: assets.dmz || 0, color: '#f97316' },
              { label: 'Interno', value: internalExpo, color: '#34d399' }
            ], { totalLabel: 'Exposição' });
          }

          // 2. Serviços Críticos e Expostos
          if (document.getElementById('assets-chart-services')) {
            renderMetricComparison('assets-chart-services', [
              { label: 'Serviços Críticos', value: services.critical_services || 0, color: '#f87171' },
              { label: 'Serviços Expostos', value: services.internet_exposed_services || 0, color: '#fb923c' },
              { label: 'Externos sem Wazuh', value: external.without_wazuh_agent || 0, color: '#a855f7' }
            ]);
          }
          
        } else {
          showFallbackExposure('Falha HTTP ao contatar a API');
        }
      } catch (e) {
        showFallbackExposure('Erro de comunicação com o servidor');
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    function showFallbackExposure(msg) {
      document.getElementById('expo-with-context').textContent = '-';
      document.getElementById('expo-without-context').textContent = '-';
      document.getElementById('expo-internet-facing').textContent = '-';
      document.getElementById('expo-dmz').textContent = '-';
      document.getElementById('expo-critical-services').textContent = '-';
      document.getElementById('expo-internet-services').textContent = '-';
      document.getElementById('expo-external-no-agent').textContent = '-';
      document.getElementById('expo-alerts-count').textContent = '-';
      
      document.getElementById('exposure-alerts-container').style.display = 'none';
      
      document.getElementById('expo-top-assets-tbody').innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Superfície de ataque indisponível: ${msg}</td></tr>`;
      document.getElementById('expo-missing-tbody').innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Indisponível: ${msg}</td></tr>`;
      document.getElementById('expo-alerts-tbody').innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Indisponível: ${msg}</td></tr>`;
      document.getElementById('expo-external-tbody').innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Indisponível: ${msg}</td></tr>`;

      const charts = ['assets-chart-exposure', 'assets-chart-services'];
      charts.forEach(id => {
        const c = document.getElementById(id);
        if (c) c.innerHTML = `<div style="display: flex; height: 100%; align-items: center; justify-content: center; color: var(--text-muted); font-size: 0.85rem;">Gráfico indisponível: ${msg}</div>`;
      });
    }

    async function refreshSlaSummary() {
      const btn = document.getElementById('btn-refresh-sla');
      if (btn) btn.disabled = true;

      try {
        const response = await fetch('/soar-api/sla-summary', {
          credentials: 'same-origin',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        if (response.ok) {
          const data = await response.json();
          const sum = data.summary || {};
          const alerts = data.sla_alerts || [];
          const topOverdue = data.top_overdue || [];
          const topDueSoon = data.top_due_soon || [];
          const topPersistent = data.top_persistent_cves || [];
          const topRecurring = data.top_recurring_cves || [];
          const backlogAssets = data.top_backlog_assets || [];
          const backlogOwners = data.top_backlog_owners || [];
          
          document.getElementById('sla-total-open').textContent = sum.total_open !== undefined ? sum.total_open : '-';
          document.getElementById('sla-overdue').textContent = sum.overdue !== undefined ? sum.overdue : '-';
          document.getElementById('sla-due-soon').textContent = sum.due_soon !== undefined ? sum.due_soon : '-';
          document.getElementById('sla-within-sla').textContent = sum.within_sla !== undefined ? sum.within_sla : '-';
          document.getElementById('sla-no-sla').textContent = sum.unknown !== undefined ? sum.unknown : '-';
          document.getElementById('sla-avg-age').textContent = sum.average_age_days !== undefined ? sum.average_age_days + 'd' : '-';
          document.getElementById('sla-max-age').textContent = sum.max_age_days !== undefined ? sum.max_age_days + 'd' : '-';
          document.getElementById('sla-persistent').textContent = sum.persistent_vulnerabilities !== undefined ? sum.persistent_vulnerabilities : '-';
          
          const ovSlaStatus = document.getElementById('overview-sla-status');
          const ovSlaDetails = document.getElementById('overview-sla-details');
          if (ovSlaStatus && ovSlaDetails) {
            const overdue = sum.overdue || 0;
            const dueSoon = sum.due_soon || 0;
            ovSlaStatus.innerHTML = `<span style="color: #f87171;">${overdue}</span> / <span style="color: #fb923c;">${dueSoon}</span>`;
            ovSlaDetails.textContent = `Overdue: ${overdue} | Due soon: ${dueSoon}`;
          }
          document.getElementById('sla-recurring').textContent = sum.recurring_vulnerabilities !== undefined ? sum.recurring_vulnerabilities : '-';
          
          const alertEl = document.getElementById('sla-alerts-container');
          if (alerts.length > 0) {
            alertEl.style.display = 'flex';
            alertEl.innerHTML = '';
            alerts.forEach(al => {
              const div = document.createElement('div');
              let alertClass = 'alert-info';
              if (al.level === 'critical') alertClass = 'alert-critical';
              else if (al.level === 'warning') alertClass = 'alert-warning';
              div.className = 'alert-item ' + alertClass;
              div.innerHTML = `<strong>${al.title || 'Alerta'}:</strong> ${al.message || ''}`;
              alertEl.appendChild(div);
            });
          } else {
            alertEl.style.display = 'none';
          }
          
          // Render overdue table
          const overdueTbody = document.getElementById('sla-overdue-tbody');
          overdueTbody.innerHTML = '';
          if (topOverdue.length === 0) {
            overdueTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #10b981; padding: 1.5rem; font-weight:600;">✓ Nenhuma vulnerabilidade vencida!</td></tr>';
          } else {
            topOverdue.forEach(v => {
              const tr = document.createElement('tr');
              let sevColor = 'var(--text-muted)';
              if (String(v.severity).toLowerCase() === 'critical') sevColor = '#f87171';
              else if (String(v.severity).toLowerCase() === 'high') sevColor = '#fb923c';
              
              tr.innerHTML = `
                <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${v.cve}" target="_blank">${v.cve}</a></td>
                <td><code>${v.agent_id}</code><br/><span style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">${v.agent_name}</span></td>
                <td><code>${v.package_name || '-'}</code></td>
                <td><span style="font-weight:600; color:${sevColor}">${v.severity}</span></td>
                <td style="text-align: right; font-weight: 700; color: #f87171;">${v.days_overdue}d</td>
                <td><code style="font-size:0.75rem;">${v.due_date ? new Date(v.due_date).toLocaleString() : '-'}</code></td>
              `;
              overdueTbody.appendChild(tr);
            });
          }
          
          // Render due soon table
          const dueSoonTbody = document.getElementById('sla-due-soon-tbody');
          dueSoonTbody.innerHTML = '';
          if (topDueSoon.length === 0) {
            dueSoonTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhuma vulnerabilidade próxima do vencimento.</td></tr>';
          } else {
            topDueSoon.forEach(v => {
              const tr = document.createElement('tr');
              let sevColor = 'var(--text-muted)';
              if (String(v.severity).toLowerCase() === 'critical') sevColor = '#f87171';
              else if (String(v.severity).toLowerCase() === 'high') sevColor = '#fb923c';
              
              tr.innerHTML = `
                <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${v.cve}" target="_blank">${v.cve}</a></td>
                <td><code>${v.agent_id}</code><br/><span style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">${v.agent_name}</span></td>
                <td><code>${v.package_name || '-'}</code></td>
                <td><span style="font-weight:600; color:${sevColor}">${v.severity}</span></td>
                <td style="text-align: right; font-weight: 700; color: #fb923c;">${v.days_to_due}d</td>
                <td><code style="font-size:0.75rem;">${v.due_date ? new Date(v.due_date).toLocaleString() : '-'}</code></td>
              `;
              dueSoonTbody.appendChild(tr);
            });
          }
          
          // Render persistent table
          const persistentTbody = document.getElementById('sla-persistent-tbody');
          persistentTbody.innerHTML = '';
          if (topPersistent.length === 0) {
            persistentTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhuma vulnerabilidade persistente detectada.</td></tr>';
          } else {
            topPersistent.forEach(v => {
              const tr = document.createElement('tr');
              let sevColor = 'var(--text-muted)';
              if (String(v.severity).toLowerCase() === 'critical') sevColor = '#f87171';
              else if (String(v.severity).toLowerCase() === 'high') sevColor = '#fb923c';
              
              tr.innerHTML = `
                <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${v.cve}" target="_blank">${v.cve}</a></td>
                <td><code>${v.agent_id}</code><br/><span style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">${v.agent_name}</span></td>
                <td><code>${v.package_name || '-'}</code></td>
                <td><span style="font-weight:600; color:${sevColor}">${v.severity}</span></td>
                <td style="text-align: right; font-weight: 700; color: #c084fc;">${v.age_days}d</td>
              `;
              persistentTbody.appendChild(tr);
            });
          }
          
          // Render recurring table
          const recurringTbody = document.getElementById('sla-recurring-tbody');
          recurringTbody.innerHTML = '';
          if (topRecurring.length === 0) {
            recurringTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhuma vulnerabilidade recorrente detectada.</td></tr>';
          } else {
            topRecurring.forEach(v => {
              const tr = document.createElement('tr');
              let sevColor = 'var(--text-muted)';
              if (String(v.severity).toLowerCase() === 'critical') sevColor = '#f87171';
              else if (String(v.severity).toLowerCase() === 'high') sevColor = '#fb923c';
              
              tr.innerHTML = `
                <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${v.cve}" target="_blank">${v.cve}</a></td>
                <td><code>${v.agent_id}</code><br/><span style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">${v.agent_name}</span></td>
                <td><code>${v.package_name || '-'}</code></td>
                <td><span style="font-weight:600; color:${sevColor}">${v.severity}</span></td>
                <td style="text-align: right; font-weight: 700; color: #60a5fa;">${v.snapshot_occurrences}</td>
              `;
              recurringTbody.appendChild(tr);
            });
          }
          
          // Render backlog asset table
          const backlogAssetTbody = document.getElementById('sla-backlog-asset-tbody');
          backlogAssetTbody.innerHTML = '';
          if (backlogAssets.length === 0) {
            backlogAssetTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhum backlog por ativo listado.</td></tr>';
          } else {
            backlogAssets.forEach(a => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td><code>${a.agent_id}</code></td>
                <td style="font-weight:600;">${a.agent_name}</td>
                <td style="font-weight:700;">${a.total}</td>
                <td style="font-weight:700; color:#f87171;">${a.overdue}</td>
                <td style="font-weight:700; color:#fb923c;">${a.due_soon}</td>
                <td style="font-weight:700; color:#34d399;">${a.within_sla}</td>
              `;
              backlogAssetTbody.appendChild(tr);
            });
          }
          
          // Render backlog owner table
          const backlogOwnerTbody = document.getElementById('sla-backlog-owner-tbody');
          backlogOwnerTbody.innerHTML = '';
          if (backlogOwners.length === 0) {
            backlogOwnerTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhum backlog por owner técnico listado.</td></tr>';
          } else {
            backlogOwners.forEach(o => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td style="font-weight:600; color: var(--text-main);">${o.technical_owner}</td>
                <td style="font-weight:700;">${o.total}</td>
                <td style="font-weight:700; color:#f87171;">${o.overdue}</td>
                <td style="font-weight:700; color:#fb923c;">${o.due_soon}</td>
                <td style="font-weight:700; color:#34d399;">${o.within_sla}</td>
              `;
              backlogOwnerTbody.appendChild(tr);
            });
          }

          // Render alerts table
          const alertsTbody = document.getElementById('sla-alerts-tbody');
          alertsTbody.innerHTML = '';
          if (alerts.length === 0) {
            alertsTbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: #10b981; padding: 1.5rem; font-weight:600;">✓ Nenhum alerta de SLA ou backlog pendente!</td></tr>';
          } else {
            alerts.forEach(al => {
              const tr = document.createElement('tr');
              let lvlBadge = '<span class="badge badge-p4">Info</span>';
              if (al.level === 'critical') lvlBadge = '<span class="badge badge-p1plus">Crítico</span>';
              else if (al.level === 'warning') lvlBadge = '<span class="badge badge-p1">Aviso</span>';
              
              tr.innerHTML = `
                <td>${lvlBadge}</td>
                <td style="font-weight: 600;">${al.title || 'Alerta'}</td>
                <td>${al.message || ''}</td>
              `;
              alertsTbody.appendChild(tr);
            });
          }
          
          // ==========================================
          // Fase 3H.2 - Renderizar Gráficos de SLA
          // ==========================================
          
          // 1. Visão Geral - Donut de SLA
          if (document.getElementById('overview-chart-sla')) {
            renderDonutChart('overview-chart-sla', [
              { label: 'Vencidas', value: sum.overdue || 0, color: '#f87171' },
              { label: 'Próximas', value: sum.due_soon || 0, color: '#fb923c' },
              { label: 'Dentro SLA', value: sum.within_sla || 0, color: '#34d399' }
            ], { totalLabel: 'SLA Status' });
          }

          // 2. SLA & Backlog - Stacked de Cumprimento de SLA
          if (document.getElementById('sla-chart-compliance')) {
            renderStackedBar('sla-chart-compliance', [
              { label: 'Vencidas', value: sum.overdue || 0, color: '#f87171' },
              { label: 'Próximas', value: sum.due_soon || 0, color: '#fb923c' },
              { label: 'Dentro SLA', value: sum.within_sla || 0, color: '#34d399' }
            ]);
          }

          // 3. SLA & Backlog - Cards de Comparação de Idade
          if (document.getElementById('sla-chart-aging')) {
            renderMetricComparison('sla-chart-aging', [
              { label: 'Média de Idade', value: (sum.average_age_days || 0) + 'd', color: '#60a5fa' },
              { label: 'Idade Máxima', value: (sum.max_age_days || 0) + 'd', color: '#a78bfa' },
              { label: 'CVEs Persistentes', value: sum.persistent_vulnerabilities || 0, color: '#fb923c' },
              { label: 'CVEs Recorrentes', value: sum.recurring_vulnerabilities || 0, color: '#f59e0b' }
            ]);
          }

          // 4. SLA & Backlog - Top Backlog por Ativo
          let assetBacklog = backlogAssets.slice(0, 5).map(a => ({
            label: a.agent_name,
            value: a.total,
            color: '#fb923c'
          }));
          if (document.getElementById('sla-chart-backlog-asset')) {
            renderMiniBarChart('sla-chart-backlog-asset', assetBacklog);
          }

          // 5. SLA & Backlog - Top Backlog por Owner
          let ownerBacklog = backlogOwners.slice(0, 5).map(o => ({
            label: o.technical_owner,
            value: o.total,
            color: '#60a5fa'
          }));
          if (document.getElementById('sla-chart-backlog-owner')) {
            renderMiniBarChart('sla-chart-backlog-owner', ownerBacklog);
          }
          
        } else {
          showFallbackSla('Falha HTTP ao contatar a API');
        }
      } catch (e) {
        showFallbackSla('Erro de comunicação com o servidor');
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    function showFallbackSla(msg) {
      safeSetHtml('sla-total-open', '-');
      safeSetHtml('sla-overdue', '-');
      safeSetHtml('sla-due-soon', '-');
      safeSetHtml('sla-within-sla', '-');
      safeSetHtml('sla-no-sla', '-');
      safeSetHtml('sla-avg-age', '-');
      safeSetHtml('sla-max-age', '-');
      safeSetHtml('sla-persistent', '-');
      safeSetHtml('sla-recurring', '-');
      
      const alertsContainer = safeGetEl('sla-alerts-container');
      if (alertsContainer) alertsContainer.style.display = 'none';
      
      safeSetHtml('sla-overdue-tbody', `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">SLA indisponível: ${msg}</td></tr>`);
      safeSetHtml('sla-due-soon-tbody', `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">SLA indisponível: ${msg}</td></tr>`);
      safeSetHtml('sla-persistent-tbody', `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">SLA indisponível: ${msg}</td></tr>`);
      safeSetHtml('sla-recurring-tbody', `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">SLA indisponível: ${msg}</td></tr>`);
      safeSetHtml('sla-backlog-asset-tbody', `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">SLA indisponível: ${msg}</td></tr>`);
      safeSetHtml('sla-backlog-owner-tbody', `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">SLA indisponível: ${msg}</td></tr>`);
      safeSetHtml('sla-alerts-tbody', `<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">SLA indisponível: ${msg}</td></tr>`);

      const charts = ['overview-chart-sla', 'sla-chart-compliance', 'sla-chart-aging', 'sla-chart-backlog-asset', 'sla-chart-backlog-owner'];
      charts.forEach(id => {
        showChartEmptyState(id, `Gráfico indisponível: ${msg}`);
      });
    }

    async function refreshRiskAcceptance() {
      const btn = document.getElementById('btn-refresh-ra');
      if (btn) btn.disabled = true;

      try {
        const response = await fetch('/soar-api/risk-acceptance', {
          credentials: 'same-origin',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        if (response.ok) {
          const data = await response.json();
          const sum = data.summary || {};
          const alerts = data.acceptance_alerts || [];
          const expiredAcceptances = data.expired_acceptances || [];
          const expiringSoon = data.expiring_soon || [];
          const invalidRules = data.invalid_rules || [];
          const matchedSample = data.matched_items_sample || [];
          
          document.getElementById('ra-rules-total').textContent = sum.rules_total !== undefined ? sum.rules_total : '-';
          document.getElementById('ra-rules-invalid').textContent = sum.rules_invalid !== undefined ? sum.rules_invalid : '-';
          document.getElementById('ra-accepted-count').textContent = sum.accepted !== undefined ? sum.accepted : '-';
          document.getElementById('ra-fp-count').textContent = sum.false_positive !== undefined ? sum.false_positive : '-';
          document.getElementById('ra-planned-count').textContent = sum.planned_remediation !== undefined ? sum.planned_remediation : '-';
          document.getElementById('ra-compensating-count').textContent = sum.compensating_control !== undefined ? sum.compensating_control : '-';
          document.getElementById('ra-waiting-count').textContent = sum.waiting_change_window !== undefined ? sum.waiting_change_window : '-';
          document.getElementById('ra-expired-count').textContent = sum.expired !== undefined ? sum.expired : '-';
          
          const ovAct = document.getElementById('overview-actionable-priorities');
          if (ovAct) ovAct.textContent = sum.actionable_after_acceptance !== undefined ? sum.actionable_after_acceptance : '-';
          document.getElementById('ra-actionable-count').textContent = sum.actionable_after_acceptance !== undefined ? sum.actionable_after_acceptance : '-';
          
          const alertEl = document.getElementById('ra-alerts-container');
          if (alerts.length > 0) {
            alertEl.style.display = 'flex';
            alertEl.innerHTML = '';
            alerts.forEach(al => {
              const div = document.createElement('div');
              let alertClass = 'alert-info';
              if (al.level === 'critical') alertClass = 'alert-critical';
              else if (al.level === 'warning') alertClass = 'alert-warning';
              div.className = 'alert-item ' + alertClass;
              div.innerHTML = `<strong>${al.title || 'Alerta'}:</strong> ${al.message || ''}`;
              alertEl.appendChild(div);
            });
          } else {
            alertEl.style.display = 'none';
          }
          
          // Helper: format CVE or Package
          const formatCveOrPkg = (item) => {
            if (item.cve) {
              return `<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${item.cve}" target="_blank">${item.cve}</a>${item.package_name ? '<br/><span style="font-size:0.7rem; color:var(--text-muted);">' + item.package_name + '</span>' : ''}`;
            }
            return item.package_name ? `<code>${item.package_name}</code>` : '-';
          };

          // Helper: format Agent
          const formatAgent = (item) => {
            return `<code>${item.agent_id || '-'}</code>${item.agent_name ? '<br/><span style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">' + item.agent_name + '</span>' : ''}`;
          };

          const getStatusBadge = (status, expired = false) => {
            if (expired) {
              return `<span class="badge badge-p1plus">Exceção Vencida</span>`;
            }
            switch (status) {
              case 'accepted':
                return `<span class="badge badge-p4">Risco Aceito</span>`;
              case 'false_positive':
                return `<span class="badge badge-p3">Falso Positivo</span>`;
              case 'planned_remediation':
                return `<span class="badge badge-p2">Correção Planejada</span>`;
              case 'compensating_control':
                return `<span class="badge badge-persistent">Controle Compensatório</span>`;
              case 'waiting_change_window':
                return `<span class="badge badge-p1">Aguardando Janela</span>`;
              case 'out_of_scope':
                return `<span class="badge" style="background: rgba(156, 163, 175, 0.15); color: #9ca3af; border: 1px solid rgba(156, 163, 175, 0.3);">Fora de Escopo</span>`;
              case 'duplicate':
                return `<span class="badge" style="background: rgba(156, 163, 175, 0.15); color: #9ca3af; border: 1px solid rgba(156, 163, 175, 0.3);">Duplicado</span>`;
              case 'under_review':
                return `<span class="badge" style="background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3);">Em Investigação</span>`;
              case 'expired':
                return `<span class="badge badge-p1plus">Vencido</span>`;
              case 'invalid':
                return `<span class="badge badge-p1plus">Inválida</span>`;
              default:
                return `<span class="badge" style="background: rgba(156, 163, 175, 0.15); color: #9ca3af; border: 1px solid rgba(156, 163, 175, 0.3);">${status || 'Nenhum'}</span>`;
            }
          };

          // 1. Render Expired Table
          const expiredTbody = document.getElementById('ra-expired-tbody');
          expiredTbody.innerHTML = '';
          if (expiredAcceptances.length === 0) {
            expiredTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #10b981; padding: 1.5rem; font-weight:600;">✓ Nenhuma exceção vencida!</td></tr>';
          } else {
            expiredAcceptances.forEach(v => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${v.cve}" target="_blank">${v.cve}</a></td>
                <td>${formatAgent(v)}</td>
                <td><code>${v.rule_id || '-'}</code></td>
                <td><code style="font-size:0.75rem;">${v.valid_until ? new Date(v.valid_until).toLocaleString() : '-'}</code></td>
                <td style="text-align: right; font-weight: 700; color: #f87171;">${v.days_overdue}d</td>
              `;
              expiredTbody.appendChild(tr);
            });
          }
          
          // 2. Render Expiring Soon Table
          const expiringSoonTbody = document.getElementById('ra-expiring-soon-tbody');
          expiringSoonTbody.innerHTML = '';
          if (expiringSoon.length === 0) {
            expiringSoonTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhuma exceção próxima do vencimento.</td></tr>';
          } else {
            expiringSoon.forEach(v => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${v.cve}" target="_blank">${v.cve}</a></td>
                <td>${formatAgent(v)}</td>
                <td><code>${v.rule_id || '-'}</code></td>
                <td><code style="font-size:0.75rem;">${v.valid_until ? new Date(v.valid_until).toLocaleString() : '-'}</code></td>
                <td style="text-align: right; font-weight: 700; color: #fb923c;">${v.days_to_expiration}d</td>
              `;
              expiringSoonTbody.appendChild(tr);
            });
          }
          
          // 3. Render FP Table
          const fpTbody = document.getElementById('ra-fp-tbody');
          fpTbody.innerHTML = '';
          const fps = matchedSample.filter(item => item.status === 'false_positive');
          if (fps.length === 0) {
            fpTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhum falso positivo cadastrado ou correspondido.</td></tr>';
          } else {
            fps.forEach(item => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td>${formatCveOrPkg(item)}</td>
                <td>${formatAgent(item)}</td>
                <td>${item.reason || item.business_justification || '-'}</td>
                <td>${item.approved_by || '-'}</td>
              `;
              fpTbody.appendChild(tr);
            });
          }
          
          // 4. Render Riscos Aceitos Table
          const acceptedTbody = document.getElementById('ra-accepted-tbody');
          acceptedTbody.innerHTML = '';
          const accepteds = matchedSample.filter(item => item.status === 'accepted');
          if (accepteds.length === 0) {
            acceptedTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhum risco aceito ativo.</td></tr>';
          } else {
            accepteds.forEach(item => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td>${formatCveOrPkg(item)}</td>
                <td>${formatAgent(item)}</td>
                <td><strong>Motivo:</strong> ${item.reason || '-'}<br/><span style="font-size:0.75rem; color:var(--text-muted);"><strong>Justificativa:</strong> ${item.business_justification || '-'}</span></td>
                <td><code style="font-size:0.75rem;">${item.valid_until ? new Date(item.valid_until).toLocaleString() : '-'}</code></td>
              `;
              acceptedTbody.appendChild(tr);
            });
          }
          
          // 5. Render Planned Table
          const plannedTbody = document.getElementById('ra-planned-tbody');
          plannedTbody.innerHTML = '';
          const planneds = matchedSample.filter(item => item.status === 'planned_remediation');
          if (planneds.length === 0) {
            plannedTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhuma correção planejada.</td></tr>';
          } else {
            planneds.forEach(item => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td>${formatCveOrPkg(item)}</td>
                <td>${formatAgent(item)}</td>
                <td><code>${item.ticket || '-'}</code></td>
                <td><code style="font-size:0.75rem;">${item.valid_until ? new Date(item.valid_until).toLocaleString() : '-'}</code></td>
              `;
              plannedTbody.appendChild(tr);
            });
          }
          
          // 6. Render Compensating Table
          const compensatingTbody = document.getElementById('ra-compensating-tbody');
          compensatingTbody.innerHTML = '';
          const compensatings = matchedSample.filter(item => item.status === 'compensating_control');
          if (compensatings.length === 0) {
            compensatingTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhum controle compensatório.</td></tr>';
          } else {
            compensatings.forEach(item => {
              const tr = document.createElement('tr');
              let controlsHtml = '-';
              if (item.compensating_controls) {
                if (Array.isArray(item.compensating_controls)) {
                  controlsHtml = `<ul style="margin: 0; padding-left: 1rem;">${item.compensating_controls.map(c => `<li>${c}</li>`).join('')}</ul>`;
                } else {
                  controlsHtml = item.compensating_controls;
                }
              }
              tr.innerHTML = `
                <td>${formatCveOrPkg(item)}</td>
                <td>${formatAgent(item)}</td>
                <td>${controlsHtml}</td>
                <td><strong>Dono:</strong> ${item.owner || '-'}<br/><span style="font-size:0.75rem; color:var(--text-muted);"><strong>Validade:</strong> ${item.valid_until ? new Date(item.valid_until).toLocaleDateString() : '-'}</span></td>
              `;
              compensatingTbody.appendChild(tr);
            });
          }
          
          // 7. Render Invalid Rules Table
          const invalidTbody = document.getElementById('ra-invalid-rules-tbody');
          invalidTbody.innerHTML = '';
          if (invalidRules.length === 0) {
            invalidTbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: #10b981; padding: 1.5rem; font-weight:600;">✓ Nenhuma regra inválida detectada!</td></tr>';
          } else {
            invalidRules.forEach((rule, idx) => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td><code>${rule.id || 'Regra ' + idx}</code></td>
                <td><span class="badge badge-p1plus">Erro</span></td>
                <td style="color: #f87171;">${rule.validation_error || 'Erro desconhecido na validação de campos.'}</td>
              `;
              invalidTbody.appendChild(tr);
            });
          }
          
          // 8. Render Matched Sample Table
          const matchedSampleTbody = document.getElementById('ra-matched-sample-tbody');
          matchedSampleTbody.innerHTML = '';
          if (matchedSample.length === 0) {
            matchedSampleTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhuma vulnerabilidade correspondida por regras.</td></tr>';
          } else {
            matchedSample.forEach(item => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td>${formatCveOrPkg(item)}</td>
                <td>${formatAgent(item)}</td>
                <td><code>${item.rule_id || '-'}</code></td>
                <td>${getStatusBadge(item.status, item.days_to_expiration !== null && item.days_to_expiration < 0)}</td>
              `;
              matchedSampleTbody.appendChild(tr);
            });
          }
          
          // 9. Render Alerts Table
          const alertsTbody = document.getElementById('ra-alerts-tbody');
          alertsTbody.innerHTML = '';
          if (alerts.length === 0) {
            alertsTbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: #10b981; padding: 1.5rem; font-weight:600;">✓ Nenhum alerta de governança ou exceção pendente!</td></tr>';
          } else {
            alerts.forEach(al => {
              const tr = document.createElement('tr');
              let lvlBadge = '<span class="badge badge-p4">Info</span>';
              if (al.level === 'critical') lvlBadge = '<span class="badge badge-p1plus">Crítico</span>';
              else if (al.level === 'warning') lvlBadge = '<span class="badge badge-p1">Aviso</span>';
              
              tr.innerHTML = `
                <td>${lvlBadge}</td>
                <td style="font-weight: 600;">${al.title || 'Alerta'}</td>
                <td>${al.message || ''}</td>
              `;
              alertsTbody.appendChild(tr);
            });
          }

          // ==========================================
          // Fase 3H.2 - Renderizar Gráficos de Governança
          // ==========================================
          const govContainers = ['gov-chart-status', 'gov-chart-acceptance', 'gov-chart-fps', 'gov-chart-expired'];
          if (!sum.rules_total || sum.rules_total === 0) {
            govContainers.forEach(id => {
              showChartEmptyState(id, 'Nenhuma exceção configurada no momento.');
            });
          } else {
            // 1. Status das Exceções
            if (document.getElementById('gov-chart-status')) {
              renderStackedBar('gov-chart-status', [
                { label: 'Aceito', value: sum.accepted || 0, color: '#34d399' },
                { label: 'Falso Positivo', value: sum.false_positive || 0, color: '#60a5fa' },
                { label: 'Correção Planejada', value: sum.planned_remediation || 0, color: '#fb923c' },
                { label: 'Ctrl Compensatório', value: sum.compensating_control || 0, color: '#a78bfa' }
              ]);
            }

            // 2. Aceites de Risco
            if (document.getElementById('gov-chart-acceptance')) {
              renderMetricComparison('gov-chart-acceptance', [
                { label: 'Total Regras', value: sum.rules_total || 0, color: '#60a5fa' },
                { label: 'Regras Inválidas', value: sum.rules_invalid || 0, color: '#ef4444' }
              ]);
            }

            // 3. Falsos Positivos
            if (document.getElementById('gov-chart-fps')) {
              renderMetricComparison('gov-chart-fps', [
                { label: 'Falsos Positivos', value: sum.false_positive || 0, color: '#3b82f6' },
                { label: 'Aguardando Janela', value: sum.waiting_change_window || 0, color: '#f59e0b' }
              ]);
            }

            // 4. Exceções Expiradas
            if (document.getElementById('gov-chart-expired')) {
              renderMetricComparison('gov-chart-expired', [
                { label: 'Exceções Vencidas', value: sum.expired || 0, color: '#ef4444' },
                { label: 'Acionáveis pós-exceção', value: sum.actionable_after_acceptance || 0, color: '#fb923c' }
              ]);
            }
          }
          
        } else {
          showFallbackRiskAcceptance('Falha HTTP ao contatar a API');
        }
      } catch (e) {
        showFallbackRiskAcceptance('Erro de comunicação com o servidor: ' + e.message);
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    function showFallbackRiskAcceptance(msg) {
      safeSetHtml('ra-rules-total', '-');
      safeSetHtml('ra-rules-invalid', '-');
      safeSetHtml('ra-accepted-count', '-');
      safeSetHtml('ra-fp-count', '-');
      safeSetHtml('ra-planned-count', '-');
      safeSetHtml('ra-compensating-count', '-');
      safeSetHtml('ra-waiting-count', '-');
      safeSetHtml('ra-expired-count', '-');
      safeSetHtml('ra-actionable-count', '-');
      
      const alertEl = safeGetEl('ra-alerts-container');
      if (alertEl) alertEl.style.display = 'none';
      
      safeSetHtml('ra-expired-tbody', `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Exceções indisponíveis: ${msg}</td></tr>`);
      safeSetHtml('ra-expiring-soon-tbody', `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Exceções indisponíveis: ${msg}</td></tr>`);
      safeSetHtml('ra-fp-tbody', `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Exceções indisponíveis: ${msg}</td></tr>`);
      safeSetHtml('ra-accepted-tbody', `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Exceções indisponíveis: ${msg}</td></tr>`);
      safeSetHtml('ra-planned-tbody', `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Exceções indisponíveis: ${msg}</td></tr>`);
      safeSetHtml('ra-compensating-tbody', `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Exceções indisponíveis: ${msg}</td></tr>`);
      safeSetHtml('ra-invalid-rules-tbody', `<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Exceções indisponíveis: ${msg}</td></tr>`);
      safeSetHtml('ra-matched-sample-tbody', `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Exceções indisponíveis: ${msg}</td></tr>`);
      safeSetHtml('ra-alerts-tbody', `<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Exceções indisponíveis: ${msg}</td></tr>`);

      const charts = ['gov-chart-status', 'gov-chart-acceptance', 'gov-chart-fps', 'gov-chart-expired'];
      charts.forEach(id => {
        showChartEmptyState(id, `Gráfico indisponível: ${msg}`);
      });
    }

    async function refreshTreatmentPlan() {
      const btn = document.getElementById('btn-refresh-treatment');
      if (btn) btn.disabled = true;

      try {
        const response = await fetch('/soar-api/treatment-plan', {
          credentials: 'same-origin',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        if (response.ok) {
          const data = await response.json();
          const sum = data.summary || {};
          const byOwner = data.by_owner || [];
          const byBucket = data.by_bucket || [];
          const byEffort = data.by_effort || [];
          const quickWins = data.quick_wins || [];
          const changeCandidates = data.change_window_candidates || [];
          const topItems = data.top_treatment_items || [];
          const ownerWorkload = data.owner_workload || [];
          const alerts = data.treatment_alerts || [];
          
          // Render Metrics Cards
          
          const ovTreatNow = document.getElementById('overview-treatment-now');
          if (ovTreatNow) ovTreatNow.textContent = sum.now !== undefined ? sum.now : '-';
          document.getElementById('treatment-metrics-now').textContent = sum.now !== undefined ? sum.now : '-';
          document.getElementById('treatment-metrics-7d').textContent = sum.next_7_days !== undefined ? sum.next_7_days : '-';
          document.getElementById('treatment-metrics-15d').textContent = sum.next_15_days !== undefined ? sum.next_15_days : '-';
          document.getElementById('treatment-metrics-30d').textContent = sum.next_30_days !== undefined ? sum.next_30_days : '-';
          document.getElementById('treatment-metrics-monitor').textContent = sum.monitor !== undefined ? sum.monitor : '-';
          document.getElementById('treatment-metrics-exc-fp').textContent = `Exceções: ${sum.accepted_or_exception || 0} | FP: ${sum.false_positive || 0}`;
          document.getElementById('treatment-metrics-owners').textContent = sum.owners !== undefined ? sum.owners : '-';
          document.getElementById('treatment-metrics-wins-change').textContent = `Quick Wins: ${sum.quick_wins || 0} | Janelas: ${sum.change_window_candidates || 0}`;
          
          // Render Alertas de Tratativa
          const alertEl = document.getElementById('treatment-alerts-container');
          if (alerts.length > 0 && alerts[0].title !== "Plano Operacional Estável") {
            alertEl.style.display = 'flex';
            alertEl.innerHTML = '';
            alerts.forEach(al => {
              const div = document.createElement('div');
              let alertClass = 'alert-info';
              if (al.level === 'critical') alertClass = 'alert-critical';
              else if (al.level === 'warning') alertClass = 'alert-warning';
              div.className = 'alert-item ' + alertClass;
              div.innerHTML = `<strong>${al.title || 'Alerta'}:</strong> ${al.message || ''}`;
              alertEl.appendChild(div);
            });
          } else {
            alertEl.style.display = 'none';
          }
          
          // Render Top Items Table
          const topTbody = document.getElementById('treatment-top-tbody');
          topTbody.innerHTML = '';
          if (topItems.length === 0) {
            topTbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhum item pendente de tratativa!</td></tr>';
          } else {
            topItems.forEach(i => {
              const tr = document.createElement('tr');
              let scoreColor = '#34d399';
              if (i.treatment_score >= 80) scoreColor = '#f87171';
              else if (i.treatment_score >= 50) scoreColor = '#fb923c';
              
              let effortBadge = '<span class="badge badge-p4">Baixo</span>';
              if (i.effort === 'high') effortBadge = '<span class="badge badge-p1plus">Alto</span>';
              else if (i.effort === 'medium') effortBadge = '<span class="badge badge-p2">Médio</span>';
              
              tr.innerHTML = `
                <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${i.cve}" target="_blank">${i.cve}</a></td>
                <td><code>${i.agent_id}</code><br/><span style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">${i.agent_name}</span></td>
                <td><code>${i.package_name}</code></td>
                <td><span style="font-size:0.85rem; font-weight:600;">${i.technical_owner}</span></td>
                <td><span style="font-size:0.85rem; font-weight:600;">${i.asset_criticality}</span><br/><span style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">${i.exposure_level}</span></td>
                <td style="text-align: center;"><span class="badge" style="font-weight: 800; background: rgba(255,255,255,0.05); color: ${scoreColor}; border: 1px solid ${scoreColor}50;">${i.treatment_score}</span></td>
                <td><span class="badge ${i.treatment_bucket === 'now' ? 'badge-p1plus' : (i.treatment_bucket === 'next_7_days' ? 'badge-p1' : (i.treatment_bucket === 'next_15_days' ? 'badge-p2' : 'badge-p3'))}">${i.treatment_bucket}</span><br/><span style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">${i.suggested_action_type}</span></td>
                <td>${effortBadge}</td>
                <td style="font-size:0.8rem; color: var(--text-muted); font-weight: 500;">${i.reason}</td>
              `;
              topTbody.appendChild(tr);
            });
          }
          
          // Render Workload por Owner
          const workloadTbody = document.getElementById('treatment-workload-tbody');
          workloadTbody.innerHTML = '';
          if (ownerWorkload.length === 0) {
            workloadTbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhum workload listado.</td></tr>';
          } else {
            ownerWorkload.forEach(ow => {
              const tr = document.createElement('tr');
              let assetsList = ow.top_assets.map(a => `${a.agent_name} (${a.total_vulnerabilities})`).join('<br/>') || '-';
              let cvesList = ow.top_cves.map(c => `${c.cve} (${c.count})`).join(', ') || '-';
              tr.innerHTML = `
                <td style="font-weight:600; color: var(--text-main);">${ow.technical_owner}</td>
                <td><code>${ow.total_actionable}</code></td>
                <td><span style="font-weight:700; color:#f87171;">${ow.now}</span></td>
                <td>${ow.next_7_days} / ${ow.next_15_days} / ${ow.next_30_days}</td>
                <td><span style="color:#f87171; font-weight:700;">${ow.overdue}</span> / <span style="color:#fb923c; font-weight:700;">${ow.due_soon}</span></td>
                <td><span style="color:#f87171;">${ow.critical}</span> / <span style="color:#fb923c;">${ow.high}</span></td>
                <td>${ow.estimated_effort.low} / ${ow.estimated_effort.medium} / ${ow.estimated_effort.high}</td>
                <td style="font-size: 0.75rem; color: var(--text-muted);"><span style="color:var(--text-main); font-weight:600;">Ativos:</span><br/>${assetsList}<br/><span style="color:var(--text-main); font-weight:600;">CVEs:</span> ${cvesList}</td>
              `;
              workloadTbody.appendChild(tr);
            });
          }
          
          // Render Quick Wins
          const winsTbody = document.getElementById('treatment-wins-tbody');
          winsTbody.innerHTML = '';
          if (quickWins.length === 0) {
            winsTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #10b981; padding: 1.5rem; font-weight:600;">✓ Nenhum Quick Win detectado no momento.</td></tr>';
          } else {
            quickWins.forEach(qw => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td style="font-weight:700; color:#34d399;">${qw.title}</td>
                <td><span style="font-size:0.85rem; font-weight:600;">${qw.owner}</span></td>
                <td><code>${qw.affected_assets}</code></td>
                <td><span class="badge badge-p4">${qw.suggested_window}</span></td>
                <td style="text-align: center; font-weight:700; color:#34d399;">${qw.treatment_score}</td>
                <td style="font-size:0.8rem; color: var(--text-muted);">${qw.reason}</td>
              `;
              winsTbody.appendChild(tr);
            });
          }
          
          // Render Change Window
          const changeTbody = document.getElementById('treatment-change-tbody');
          changeTbody.innerHTML = '';
          if (changeCandidates.length === 0) {
            changeTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhuma janela de mudança de alta complexidade listada.</td></tr>';
          } else {
            changeCandidates.forEach(cc => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td style="font-weight:700; color:#fb923c;">${cc.title}</td>
                <td><span style="font-size:0.85rem; font-weight:600;">${cc.owner}</span></td>
                <td><code>${cc.affected_assets}</code></td>
                <td><span class="badge badge-p1plus">${cc.effort}</span></td>
                <td><span class="badge badge-p1">${cc.suggested_window}</span></td>
                <td style="font-size:0.8rem; color: var(--text-muted);">${cc.reason}</td>
              `;
              changeTbody.appendChild(tr);
            });
          }
          
          // Render Plan Alerts Table
          const alertsTbody = document.getElementById('treatment-plan-alerts-tbody');
          alertsTbody.innerHTML = '';
          alerts.forEach(al => {
            const tr = document.createElement('tr');
            let badgeClass = 'badge-p3';
            if (al.level === 'critical') badgeClass = 'badge-p1plus';
            else if (al.level === 'warning') badgeClass = 'badge-p1';
            
            tr.innerHTML = `
              <td><span class="badge ${badgeClass}">${al.level}</span></td>
              <td style="font-weight:700; color: var(--text-main);">${al.title}</td>
              <td style="font-size:0.85rem; color: var(--text-muted);">${al.message}</td>
            `;
            alertsTbody.appendChild(tr);
          });
          
          // Render Buckets and Effort Lists
          const bucketsUl = document.getElementById('treatment-summary-buckets');
          bucketsUl.innerHTML = '';
          byBucket.forEach(b => {
            const li = document.createElement('li');
            li.style.padding = '0.25rem 0';
            li.innerHTML = `<span style="font-weight:700; text-transform:capitalize;">${b.bucket}:</span> <code>${b.count}</code>`;
            bucketsUl.appendChild(li);
          });
          
          const effortUl = document.getElementById('treatment-summary-effort');
          effortUl.innerHTML = '';
          byEffort.forEach(e => {
            const li = document.createElement('li');
            li.style.padding = '0.25rem 0';
            li.innerHTML = `<span style="font-weight:700; text-transform:capitalize;">Esforço ${e.effort}:</span> <code>${e.count}</code>`;
            effortUl.appendChild(li);
          });

          // ==========================================
          // Fase 3H.2 - Renderizar Gráficos de Tratativa
          // ==========================================
          
          // 1. Visão Geral - Mini Bar de Buckets de Tratativa
          if (document.getElementById('overview-chart-treatment')) {
            renderMiniBarChart('overview-chart-treatment', [
              { label: 'Imediato (Now)', value: sum.now || 0, color: '#ef4444' },
              { label: 'Próx. 7 Dias', value: sum.next_7_days || 0, color: '#f97316' },
              { label: 'Próx. 15 Dias', value: sum.next_15_days || 0, color: '#eab308' },
              { label: 'Próx. 30 Dias', value: sum.next_30_days || 0, color: '#3b82f6' }
            ]);
          }

          // 2. Plano de Tratativa - Buckets Stacked Bar
          if (document.getElementById('treat-chart-buckets')) {
            renderStackedBar('treat-chart-buckets', [
              { label: 'Imediato', value: sum.now || 0, color: '#f87171' },
              { label: '7 Dias', value: sum.next_7_days || 0, color: '#fb923c' },
              { label: '15 Dias', value: sum.next_15_days || 0, color: '#facc15' },
              { label: '30 Dias', value: sum.next_30_days || 0, color: '#3b82f6' },
              { label: 'Monitorar', value: sum.monitor || 0, color: '#10b981' }
            ]);
          }

          // 3. Plano de Tratativa - Workload por Owner
          let topWorkloads = ownerWorkload.slice(0, 5).map(ow => ({
            label: ow.technical_owner,
            value: ow.total_actionable,
            color: '#60a5fa'
          }));
          if (document.getElementById('treat-chart-workload')) {
            renderMiniBarChart('treat-chart-workload', topWorkloads);
          }

          // 4. Plano de Tratativa - Quick Wins Metric Comparison
          if (document.getElementById('treat-chart-quickwins')) {
            renderMetricComparison('treat-chart-quickwins', [
              { label: 'Quick Wins', value: sum.quick_wins || 0, color: '#34d399' },
              { label: 'Janelas / Complexo', value: sum.change_window_candidates || 0, color: '#fb923c' }
            ]);
          }

          // 5. Plano de Tratativa - Esforço Estimado Stacked Bar
          let lowCount = 0, medCount = 0, highCount = 0;
          byEffort.forEach(e => {
            if (e.effort === 'low') lowCount = e.count;
            else if (e.effort === 'medium') medCount = e.count;
            else if (e.effort === 'high') highCount = e.count;
          });
          if (document.getElementById('treat-chart-changes')) {
            renderStackedBar('treat-chart-changes', [
              { label: 'Esforço Baixo', value: lowCount, color: '#34d399' },
              { label: 'Esforço Médio', value: medCount, color: '#facc15' },
              { label: 'Esforço Alto', value: highCount, color: '#f87171' }
            ]);
          }
          
        } else {
          showFallbackTreatmentPlan(response.statusText);
        }
      } catch (err) {
        showFallbackTreatmentPlan(err.message);
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    function showFallbackTreatmentPlan(msg) {
      document.getElementById('treatment-metrics-now').textContent = '-';
      document.getElementById('treatment-metrics-7d').textContent = '-';
      document.getElementById('treatment-metrics-15d').textContent = '-';
      document.getElementById('treatment-metrics-30d').textContent = '-';
      document.getElementById('treatment-metrics-monitor').textContent = '-';
      document.getElementById('treatment-metrics-exc-fp').textContent = '-';
      document.getElementById('treatment-metrics-owners').textContent = '-';
      document.getElementById('treatment-metrics-wins-change').textContent = '-';
      
      document.getElementById('treatment-alerts-container').style.display = 'none';
      
      document.getElementById('treatment-top-tbody').innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Plano indisponível: ${msg}</td></tr>`;
      document.getElementById('treatment-workload-tbody').innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Plano indisponível: ${msg}</td></tr>`;
      document.getElementById('treatment-wins-tbody').innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Plano indisponível: ${msg}</td></tr>`;
      document.getElementById('treatment-change-tbody').innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Plano indisponível: ${msg}</td></tr>`;
      document.getElementById('treatment-plan-alerts-tbody').innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Plano indisponível: ${msg}</td></tr>`;
      
      document.getElementById('treatment-summary-buckets').innerHTML = '<li>indisponível</li>';
      document.getElementById('treatment-summary-effort').innerHTML = '<li>indisponível</li>';

      const charts = ['overview-chart-treatment', 'treat-chart-buckets', 'treat-chart-workload', 'treat-chart-quickwins', 'treat-chart-changes'];
      charts.forEach(id => {
        const c = document.getElementById(id);
        if (c) c.innerHTML = `<div style="display: flex; height: 100%; align-items: center; justify-content: center; color: var(--text-muted); font-size: 0.85rem;">Gráfico indisponível: ${msg}</div>`;
      });
    }

    async function refreshTrendSummary() {
      const btn = document.getElementById('btn-refresh-trend');
      if (btn) btn.disabled = true;

      try {
        const response = await fetch('/soar-api/trend-summary', {
          credentials: 'same-origin',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        if (response.ok) {
          const data = await response.json();
          const sum = data.summary || {};
          const curr = data.current || {};
          const delta = data.delta || {};
          
          const alerts = data.executive_alerts || [];
          const worseningAssets = data.top_worsening_assets || [];
          const improvingAssets = data.top_improving_assets || [];
          const ownerTrend = data.owner_trend || [];
          const persistentCves = data.top_persistent_cves || [];
          
          const severityTrend = data.severity_trend || [];
          const slaTrend = data.sla_trend || [];
          const acceptanceTrend = data.acceptance_trend || [];
          
          // Formatar status executivo
          let execHealthHtml = '-';
          if (sum.executive_health === 'healthy') {
            execHealthHtml = '<span style="color: #10b981; font-weight: 700;">🟢 Saudável</span>';
          } else if (sum.executive_health === 'attention') {
            execHealthHtml = '<span style="color: #eab308; font-weight: 700;">🟡 Atenção</span>';
          } else if (sum.executive_health === 'critical') {
            execHealthHtml = '<span style="color: #ef4444; font-weight: 700;">🔴 Crítico</span>';
          } else {
            execHealthHtml = '<span style="color: var(--text-muted); font-weight: 700;">Cinza / Desconhecido</span>';
          }
          
          const ovTrendHealth = document.getElementById('overview-trend-health');
          const ovTrendDir = document.getElementById('overview-trend-direction');
          if (ovTrendHealth && ovTrendDir) {
            ovTrendHealth.innerHTML = execHealthHtml;
            ovTrendDir.innerHTML = 'Direção Risco: -';
          }
          document.getElementById('trend-exec-health').innerHTML = execHealthHtml;
          document.getElementById('trend-period-days').textContent = `Período: ${sum.period_days !== undefined ? sum.period_days : 0} Dias`;
          
          // Formatar direção do risco
          let riskDirHtml = '-';
          if (sum.risk_direction === 'improving') {
            riskDirHtml = '<span style="color: #10b981; font-weight: 700;">↘ Melhora</span>';
          } else if (sum.risk_direction === 'worsening') {
            riskDirHtml = '<span style="color: #ef4444; font-weight: 700;">↗ Piora</span>';
          } else if (sum.risk_direction === 'stable') {
            riskDirHtml = '<span style="color: #3b82f6; font-weight: 700;">→ Estável</span>';
          } else {
            riskDirHtml = '<span style="color: var(--text-muted); font-weight: 700;">Desconhecido</span>';
          }
          document.getElementById('trend-risk-direction').innerHTML = riskDirHtml;

          const ovTrendDirAfter = document.getElementById('overview-trend-direction');
          if (ovTrendDirAfter) {
            ovTrendDirAfter.innerHTML = `Direção Risco: ${riskDirHtml}`;
          }
          document.getElementById('trend-snapshots-analyzed').textContent = `Snapshots analisados: ${sum.snapshots_analyzed || 0} (${sum.trend_status || 'unknown'})`;
          
          // Delta total
          let deltaTotalVal = delta.total_vulnerabilities || 0;
          let deltaTotalColor = deltaTotalVal > 0 ? '#ef4444' : (deltaTotalVal < 0 ? '#10b981' : 'var(--text-main)');
          let deltaTotalSign = deltaTotalVal > 0 ? '+' : '';
          document.getElementById('trend-delta-total').innerHTML = `<span style="color: ${deltaTotalColor}; font-weight: 800;">${deltaTotalSign}${deltaTotalVal}</span>`;
          document.getElementById('trend-delta-critical-high').textContent = `Críticas: ${delta.critical > 0 ? '+' : ''}${delta.critical || 0} | Altas: ${delta.high > 0 ? '+' : ''}${delta.high || 0}`;
          
          // Delta SLA / Backlog
          let deltaSlaVal = delta.sla_overdue || 0;
          let deltaSlaColor = deltaSlaVal > 0 ? '#ef4444' : (deltaSlaVal < 0 ? '#10b981' : 'var(--text-main)');
          let deltaSlaSign = deltaSlaVal > 0 ? '+' : '';
          document.getElementById('trend-delta-sla-actionable').innerHTML = `<span style="color: ${deltaSlaColor}; font-weight: 800;">${deltaSlaSign}${deltaSlaVal}</span>`;
          document.getElementById('trend-delta-details').textContent = `SLA Vencido: ${delta.sla_overdue > 0 ? '+' : ''}${delta.sla_overdue || 0} | KEV: ${delta.kev_count > 0 ? '+' : ''}${delta.kev_count || 0}`;
          
          // Alertas
          const alertEl = document.getElementById('trend-alerts-container');
          if (alerts.length > 0 && sum.executive_health !== 'healthy') {
            alertEl.style.display = 'flex';
            alertEl.innerHTML = '';
            alerts.forEach(al => {
              const div = document.createElement('div');
              let alertClass = 'alert-info';
              if (al.level === 'critical') alertClass = 'alert-critical';
              else if (al.level === 'warning') alertClass = 'alert-warning';
              div.className = 'alert-item ' + alertClass;
              div.innerHTML = `<strong>${al.title || 'Alerta'}:</strong> ${al.message || ''}`;
              alertEl.appendChild(div);
            });
          } else {
            alertEl.style.display = 'none';
          }
          
          // Formatar direção em texto/badge
          const getDirBadge = (dir) => {
            if (dir === 'worsening') return '<span class="badge badge-p1plus" style="font-size:0.7rem;">Piora ↗</span>';
            if (dir === 'improving') return '<span class="badge badge-p4" style="font-size:0.7rem;">Melhora ↘</span>';
            return '<span class="badge badge-p3" style="font-size:0.7rem;">Estável →</span>';
          };
          
          const formatAgentLink = (agent_id, agent_name) => {
            return `<code>${agent_id || '-'}</code><br/><span style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">${agent_name || ''}</span>`;
          };

          // 1. Render Worsening Table
          const worseningTbody = document.getElementById('trend-worsening-tbody');
          worseningTbody.innerHTML = '';
          if (worseningAssets.length === 0) {
            worseningTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #10b981; padding: 1.5rem; font-weight: 600;">✓ Nenhum ativo piorou o risco!</td></tr>';
          } else {
            worseningAssets.forEach(a => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td>${formatAgentLink(a.agent_id, a.agent_name)}</td>
                <td><span style="font-size:0.85rem; font-weight:600;">${a.technical_owner}</span></td>
                <td><code>${a.previous_critical}</code> -> <code style="color:#f87171; font-weight:700;">${a.current_critical}</code> (<span style="color:#f87171; font-weight:700;">+${a.delta_critical}</span>)</td>
                <td><code>${a.previous_total}</code> -> <code style="color:#f87171; font-weight:700;">${a.current_total}</code> (<span style="color:#f87171; font-weight:700;">+${a.delta_total}</span>)</td>
                <td>${getDirBadge(a.risk_direction)}</td>
              `;
              worseningTbody.appendChild(tr);
            });
          }
          
          // 2. Render Improving Table
          const improvingTbody = document.getElementById('trend-improving-tbody');
          improvingTbody.innerHTML = '';
          if (improvingAssets.length === 0) {
            improvingTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhum ativo com melhora registrada.</td></tr>';
          } else {
            improvingAssets.forEach(a => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td>${formatAgentLink(a.agent_id, a.agent_name)}</td>
                <td><span style="font-size:0.85rem; font-weight:600;">${a.technical_owner}</span></td>
                <td><code>${a.previous_critical}</code> -> <code style="color:#34d399; font-weight:700;">${a.current_critical}</code> (<span style="color:#34d399; font-weight:700;">${a.delta_critical}</span>)</td>
                <td><code>${a.previous_total}</code> -> <code style="color:#34d399; font-weight:700;">${a.current_total}</code> (<span style="color:#34d399; font-weight:700;">${a.delta_total}</span>)</td>
                <td>${getDirBadge(a.risk_direction)}</td>
              `;
              improvingTbody.appendChild(tr);
            });
          }
          
          // 3. Render Owner Trend Table
          const ownerTbody = document.getElementById('trend-owner-tbody');
          ownerTbody.innerHTML = '';
          if (ownerTrend.length === 0) {
            ownerTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Nenhuma tendência por owner listada.</td></tr>';
          } else {
            ownerTrend.forEach(o => {
              const tr = document.createElement('tr');
              let dtSign = o.delta_total > 0 ? '+' : '';
              let doSign = o.delta_overdue > 0 ? '+' : '';
              tr.innerHTML = `
                <td style="font-weight:600; color: var(--text-main);">${o.technical_owner}</td>
                <td><code>${o.previous_total}</code> -> <code style="font-weight:700;">${o.current_total}</code> (<span style="font-weight:700; color:${o.delta_total > 0 ? '#f87171' : (o.delta_total < 0 ? '#34d399' : 'inherit')}">${dtSign}${o.delta_total}</span>)</td>
                <td><code>${o.previous_overdue}</code> -> <code style="font-weight:700;">${o.current_overdue}</code> (<span style="font-weight:700; color:${o.delta_overdue > 0 ? '#f87171' : (o.delta_overdue < 0 ? '#34d399' : 'inherit')}">${doSign}${o.delta_overdue}</span>)</td>
                <td>${getDirBadge(o.risk_direction)}</td>
              `;
              ownerTbody.appendChild(tr);
            });
          }
          
          // 4. Render Persistent Table
          const persistentTbody = document.getElementById('trend-persistent-tbody');
          persistentTbody.innerHTML = '';
          if (persistentCves.length === 0) {
            persistentTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #10b981; padding: 1.5rem; font-weight:600;">✓ Nenhuma vulnerabilidade persistente!</td></tr>';
          } else {
            persistentCves.forEach(v => {
              const tr = document.createElement('tr');
              let slaClass = 'badge-p4';
              if (v.sla_status === 'overdue') slaClass = 'badge-p1plus';
              else if (v.sla_status === 'due_soon') slaClass = 'badge-p1';
              tr.innerHTML = `
                <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${v.cve}" target="_blank">${v.cve}</a></td>
                <td><code>${v.agent_id}</code><br/><span style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">${v.agent_name}</span></td>
                <td><span style="font-weight:600;">${v.severity}</span></td>
                <td style="text-align: right; font-weight: 700; color:#c084fc;">${v.age_days}d</td>
                <td><span class="badge ${slaClass}">${v.sla_status}</span></td>
              `;
              persistentTbody.appendChild(tr);
            });
          }
          
          // Helper for timestamp formatting
          const formatTime = (ts) => {
            if (!ts) return '-';
            try {
              return new Date(ts).toLocaleString();
            } catch(e) {
              return ts;
            }
          };

          // 5. Severity Trend Table
          const severityTbody = document.getElementById('trend-severity-tbody');
          severityTbody.innerHTML = '';
          if (severityTrend.length === 0) {
            severityTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Sem histórico disponível.</td></tr>';
          } else {
            const reversed = [...severityTrend].reverse().slice(0, 7);
            reversed.forEach(s => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td><code>${formatTime(s.timestamp)}</code></td>
                <td style="color:#f87171; font-weight:700;">${s.critical}</td>
                <td style="color:#fb923c; font-weight:700;">${s.high}</td>
                <td style="color:#facc15; font-weight:700;">${s.medium}</td>
                <td style="color:#34d399; font-weight:700;">${s.low}</td>
              `;
              severityTbody.appendChild(tr);
            });
          }
          
          // 6. SLA Trend Table
          const slaTbody = document.getElementById('trend-sla-tbody');
          slaTbody.innerHTML = '';
          if (slaTrend.length === 0) {
            slaTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Sem histórico de SLA disponível.</td></tr>';
          } else {
            const reversed = [...slaTrend].reverse().slice(0, 7);
            reversed.forEach(s => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td><code>${formatTime(s.timestamp)}</code></td>
                <td style="color:#f87171; font-weight:700;">${s.overdue}</td>
                <td style="color:#fb923c; font-weight:700;">${s.due_soon}</td>
                <td style="color:#34d399; font-weight:700;">${s.within_sla}</td>
              `;
              slaTbody.appendChild(tr);
            });
          }
          
          // 7. Risk Acceptance Trend Table
          const acceptanceTbody = document.getElementById('trend-acceptance-tbody');
          acceptanceTbody.innerHTML = '';
          if (acceptanceTrend.length === 0) {
            acceptanceTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Sem histórico de aceites disponível.</td></tr>';
          } else {
            const reversed = [...acceptanceTrend].reverse().slice(0, 7);
            reversed.forEach(s => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td><code>${formatTime(s.timestamp)}</code></td>
                <td style="color:#34d399; font-weight:700;">${s.accepted_risks}</td>
                <td style="color:#60a5fa; font-weight:700;">${s.false_positive_risks}</td>
                <td style="color:#f87171; font-weight:700;">${s.expired_acceptances}</td>
                <td style="font-weight:700;">${s.actionable_priorities}</td>
              `;
              acceptanceTbody.appendChild(tr);
            });
          }
          
          // 8. Alerts Table
          const alertsTbody = document.getElementById('trend-alerts-tbody');
          alertsTbody.innerHTML = '';
          if (alerts.length === 0) {
            alertsTbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: #10b981; padding: 1.5rem; font-weight:600;">✓ Nenhum desvio de tendência detectado! Estabilidade geral.</td></tr>';
          } else {
            alerts.forEach(al => {
              const tr = document.createElement('tr');
              let lvlBadge = '<span class="badge badge-p4">Info</span>';
              if (al.level === 'critical') lvlBadge = '<span class="badge badge-p1plus">Crítico</span>';
              else if (al.level === 'warning') lvlBadge = '<span class="badge badge-p1">Aviso</span>';
              
              tr.innerHTML = `
                <td>${lvlBadge}</td>
                <td style="font-weight: 600;">${al.title || 'Alerta'}</td>
                <td>${al.message || ''}</td>
              `;
              alertsTbody.appendChild(tr);
            });
          }
          
          // Renderização de Gráficos (Fase 3H.2)
          if (severityTrend && severityTrend.length > 0) {
            // 1. Visão Geral - Evolução do Risco
            const totalTrendData = severityTrend.map(s => ({
              timestamp: s.timestamp,
              total: (s.critical || 0) + (s.high || 0) + (s.medium || 0) + (s.low || 0)
            }));
            if (document.getElementById('overview-chart-trend')) {
              renderTrendSvgChart('overview-chart-trend', [
                { key: 'total', label: 'Risco Geral', color: '#60a5fa' }
              ], { data: totalTrendData });
            }

            // 2. Tendências - Evolução do Total
            if (document.getElementById('trend-chart-total')) {
              renderTrendSvgChart('trend-chart-total', [
                { key: 'total', label: 'Total', color: '#3b82f6' }
              ], { data: totalTrendData });
            }

            // 3. Tendências - Críticas e Altas
            if (document.getElementById('trend-chart-crit-high')) {
              renderTrendSvgChart('trend-chart-crit-high', [
                { key: 'critical', label: 'Críticas', color: '#f87171' },
                { key: 'high', label: 'Altas', color: '#fb923c' }
              ], { data: severityTrend });
            }
          }

          if (slaTrend && slaTrend.length > 0) {
            // 4. Tendências - Cumprimento de SLA
            if (document.getElementById('trend-chart-sla')) {
              renderTrendSvgChart('trend-chart-sla', [
                { key: 'overdue', label: 'SLA Vencido', color: '#ef4444' },
                { key: 'within_sla', label: 'Dentro SLA', color: '#34d399' }
              ], { data: slaTrend });
            }
          }

          if (acceptanceTrend && acceptanceTrend.length > 0) {
            // 5. Tendências - Backlog Acionável
            if (document.getElementById('trend-chart-actionable')) {
              renderTrendSvgChart('trend-chart-actionable', [
                { key: 'actionable_priorities', label: 'Backlog Acionável', color: '#facc15' }
              ], { data: acceptanceTrend });
            }
          }

        } else {
          showFallbackTrend('Falha HTTP ao contatar a API');
        }
      } catch (e) {
        showFallbackTrend('Erro de comunicação com o servidor: ' + e.message);
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    function showFallbackTrend(msg) {
      document.getElementById('trend-exec-health').innerHTML = '<span style="color: var(--text-muted); font-weight: 700;">Indisponível</span>';
      document.getElementById('trend-risk-direction').innerHTML = '<span style="color: var(--text-muted); font-weight: 700;">Indisponível</span>';
      document.getElementById('trend-period-days').textContent = 'Período: -';
      document.getElementById('trend-snapshots-analyzed').textContent = 'Snapshots analisados: -';
      
      document.getElementById('trend-delta-total').textContent = '-';
      document.getElementById('trend-delta-critical-high').textContent = 'Críticas: - | Altas: -';
      document.getElementById('trend-delta-sla-actionable').textContent = '-';
      document.getElementById('trend-delta-details').textContent = 'SLA Vencido: - | KEV: -';
      
      document.getElementById('trend-alerts-container').style.display = 'none';
      
      document.getElementById('trend-worsening-tbody').innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Indisponível: ${msg}</td></tr>`;
      document.getElementById('trend-improving-tbody').innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Indisponível: ${msg}</td></tr>`;
      document.getElementById('trend-owner-tbody').innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Indisponível: ${msg}</td></tr>`;
      document.getElementById('trend-persistent-tbody').innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Indisponível: ${msg}</td></tr>`;
      document.getElementById('trend-severity-tbody').innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Indisponível: ${msg}</td></tr>`;
      document.getElementById('trend-sla-tbody').innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Indisponível: ${msg}</td></tr>`;
      document.getElementById('trend-acceptance-tbody').innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Indisponível: ${msg}</td></tr>`;
      document.getElementById('trend-alerts-tbody').innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Indisponível: ${msg}</td></tr>`;

      const tTotal = document.getElementById('trend-chart-total');
      if (tTotal) tTotal.innerHTML = `<div style="display: flex; height: 100%; align-items: center; justify-content: center; color: var(--text-muted); font-size: 0.85rem;">Gráfico indisponível: ${msg}</div>`;
      const tCritHigh = document.getElementById('trend-chart-crit-high');
      if (tCritHigh) tCritHigh.innerHTML = `<div style="display: flex; height: 100%; align-items: center; justify-content: center; color: var(--text-muted); font-size: 0.85rem;">Gráfico indisponível: ${msg}</div>`;
      const tSla = document.getElementById('trend-chart-sla');
      if (tSla) tSla.innerHTML = `<div style="display: flex; height: 100%; align-items: center; justify-content: center; color: var(--text-muted); font-size: 0.85rem;">Gráfico indisponível: ${msg}</div>`;
      const tActionable = document.getElementById('trend-chart-actionable');
      if (tActionable) tActionable.innerHTML = `<div style="display: flex; height: 100%; align-items: center; justify-content: center; color: var(--text-muted);">Gráfico indisponível: ${msg}</div>`;
    }

    // ==========================================================
    // Fase 3H.2 - Componentes Gráficos Nativos
    // ==========================================================

    function renderMiniBarChart(containerId, items, options = {}) {
      const container = safeGetEl(containerId);
      if (!container) {
        console.warn(`[SOAR Dashboard] Container ausente: ${containerId}`);
        return;
      }

      if (!Array.isArray(items) || items.length === 0) {
        showChartEmptyState(containerId);
        return;
      }

      try {
        const validItems = items.filter(i => i && typeof i === 'object');
        if (validItems.length === 0) {
          showChartEmptyState(containerId);
          return;
        }

        const maxVal = Math.max(...validItems.map(i => Number(i.value) || 0), 0);
        if (maxVal === 0) {
          showChartEmptyState(containerId);
          return;
        }

        let html = '<div style="display: flex; flex-direction: column; gap: 0.6rem; width: 100%; justify-content: center; padding: 0.5rem 0;">';
        validItems.forEach(item => {
          const val = Number(item.value) || 0;
          const pct = maxVal > 0 ? (val / maxVal) * 100 : 0;
          const color = item.color || '#3b82f6';
          const label = item.label || '';
          html += `
            <div style="display: flex; flex-direction: column; gap: 0.2rem;">
              <div style="display: flex; justify-content: space-between; font-size: 0.75rem; font-weight: 600; color: var(--text-main);">
                <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 70%;" title="${label}">${label}</span>
                <span>${val}${options.unit || ''}</span>
              </div>
              <div style="width: 100%; height: 6px; background: rgba(255,255,255,0.06); border-radius: 3px; overflow: hidden;">
                <div style="width: ${pct}%; height: 100%; background: ${color}; border-radius: 3px; transition: width 0.4s ease;"></div>
              </div>
            </div>
          `;
        });
        html += '</div>';
        container.innerHTML = html;
      } catch (err) {
        console.error(`[SOAR Dashboard] Erro ao renderizar ${containerId}:`, err);
        showChartEmptyState(containerId, 'Erro ao gerar o gráfico.');
      }
    }

    function renderDonutChart(containerId, items, options = {}) {
      // NB: nome mantido por compatibilidade; renderiza PIE CHART (pizza).
      const container = safeGetEl(containerId);
      if (!container) {
        console.warn(`[SOAR Dashboard] Container ausente: ${containerId}`);
        return;
      }

      if (!Array.isArray(items) || items.length === 0) {
        showChartEmptyState(containerId);
        return;
      }

      try {
        const validItems = items.filter(i => i && typeof i === 'object');
        const total = validItems.reduce((sum, item) => sum + (Number(item.value) || 0), 0);
        if (total === 0) {
          showChartEmptyState(containerId);
          return;
        }

        // Geometria do pie: viewBox 240x170, pizza grande e centralizada à esquerda.
        const cx = 85, cy = 85, r = 72;
        const TAU = Math.PI * 2;
        const polar = (deg) => {
          const a = (deg - 90) * Math.PI / 180;
          return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
        };
        const drawn = validItems.filter(i => (Number(i.value) || 0) > 0);

        let svgHtml = `<svg class="pie-svg" viewBox="0 0 240 170" preserveAspectRatio="xMidYMid meet" role="img" aria-label="${options.totalLabel || 'Total'}: ${total}">`;

        if (drawn.length === 1) {
          // Categoria única: círculo completo (arco fecharia em si mesmo).
          const only = drawn[0];
          const color = only.color || '#3b82f6';
          const label = only.label || '';
          svgHtml += `<circle class="pie-slice" cx="${cx}" cy="${cy}" r="${r}" fill="${color}" stroke="var(--card-bg)" stroke-width="2">
              <title>${label}: ${only.value} (100.0%)</title>
            </circle>`;
        } else {
          let startAngle = 0;
          drawn.forEach(item => {
            const val = Number(item.value) || 0;
            const pct = val / total;
            const sweep = pct * 360;
            const endAngle = startAngle + sweep;
            const [x1, y1] = polar(startAngle);
            const [x2, y2] = polar(endAngle);
            const largeArc = sweep > 180 ? 1 : 0;
            const color = item.color || '#3b82f6';
            const label = item.label || '';
            const d = `M${cx},${cy} L${x1.toFixed(2)},${y1.toFixed(2)} A${r},${r} 0 ${largeArc} 1 ${x2.toFixed(2)},${y2.toFixed(2)} Z`;
            svgHtml += `<path class="pie-slice" d="${d}" fill="${color}" stroke="var(--card-bg)" stroke-width="2" stroke-linejoin="round" style="transition: opacity 0.3s ease;">
                <title>${label}: ${val} (${(pct*100).toFixed(1)}%)</title>
              </path>`;
            startAngle = endAngle;
          });
        }
        svgHtml += `</svg>`;

        let legendHtml = '<div class="pie-legend">';
        validItems.forEach(item => {
          const val = Number(item.value) || 0;
          const pct = total > 0 ? (val / total * 100).toFixed(0) : 0;
          const color = item.color || '#3b82f6';
          const label = item.label || '';
          legendHtml += `
            <div class="pie-legend-row">
              <span class="pie-dot" style="background: ${color};"></span>
              <span class="pie-label" title="${label}">${label}</span>
              <span class="pie-value">${val} <span class="pie-pct">${pct}%</span></span>
            </div>
          `;
        });
        legendHtml += '</div>';

        container.innerHTML = `
          <div class="pie-chart-layout">
            ${svgHtml}
            ${legendHtml}
          </div>
        `;
      } catch (err) {
        console.error(`[SOAR Dashboard] Erro ao renderizar ${containerId}:`, err);
        showChartEmptyState(containerId, 'Erro ao gerar o gráfico.');
      }
    }
    function renderTrendSvgChart(containerId, series, options = {}) {
      const container = safeGetEl(containerId);
      if (!container) {
        console.warn(`[SOAR Dashboard] Container ausente: ${containerId}`);
        return;
      }

      const trendData = options.data;
      if (!Array.isArray(trendData) || trendData.length === 0 || !Array.isArray(series) || series.length === 0) {
        showChartEmptyState(containerId);
        return;
      }

      try {
        const data = [...trendData].sort((a, b) => new Date(a.timestamp || a.date) - new Date(b.timestamp || b.date));
        const width = container.clientWidth || 300;
        const height = container.clientHeight || 160;
        const paddingLeft = 30;
        const paddingRight = 10;
        const paddingTop = 10;
        const paddingBottom = 30;
        const plotWidth = width - paddingLeft - paddingRight;
        const plotHeight = height - paddingTop - paddingBottom;

        let maxValue = 0;
        data.forEach(d => {
          if (!d) return;
          series.forEach(s => {
            if (!s) return;
            const val = d[s.key] !== undefined ? Number(d[s.key]) : (Number(d[s.label]) || 0);
            if (val > maxValue) maxValue = val;
          });
        });
        maxValue = Math.ceil(maxValue * 1.1) || 10;

        let svgHtml = `<svg width="100%" height="100%" viewBox="0 0 ${width} ${height}" style="overflow: visible;">`;
        const yTicks = 3;
        for (let i = 0; i <= yTicks; i++) {
          const val = Math.round((maxValue / yTicks) * i);
          const y = paddingTop + plotHeight - (plotHeight / yTicks) * i;
          svgHtml += `<line x1="${paddingLeft}" y1="${y}" x2="${width - paddingRight}" y2="${y}" stroke="rgba(255,255,255,0.06)" stroke-width="1" />`;
          svgHtml += `<text x="${paddingLeft - 6}" y="${y + 3}" fill="var(--text-muted)" font-size="9" text-anchor="end">${val}</text>`;
        }

        const xPoints = data.length;
        const xStep = xPoints > 1 ? plotWidth / (xPoints - 1) : plotWidth;

        data.forEach((d, idx) => {
          if (!d) return;
          const x = paddingLeft + idx * xStep;
          svgHtml += `<line x1="${x}" y1="${paddingTop}" x2="${x}" y2="${paddingTop + plotHeight}" stroke="rgba(255,255,255,0.04)" stroke-dasharray="2,2" stroke-width="1" />`;
          const rawDate = d.timestamp || d.date;
          const date = new Date(rawDate);
          const label = (date.getMonth() + 1) + '/' + date.getDate();
          if (xPoints <= 6 || idx === 0 || idx === xPoints - 1 || idx === Math.floor(xPoints / 2)) {
            svgHtml += `<text x="${x}" y="${paddingTop + plotHeight + 12}" fill="var(--text-muted)" font-size="8" text-anchor="middle">${label}</text>`;
          }
        });

        series.forEach(s => {
          if (!s) return;
          const color = s.color || '#3b82f6';
          const key = s.key;
          let pathD = '';
          data.forEach((d, idx) => {
            if (!d) return;
            const val = d[key] !== undefined ? Number(d[key]) : 0;
            const x = paddingLeft + idx * xStep;
            const y = paddingTop + plotHeight - (plotHeight * val / maxValue);
            if (idx === 0) pathD += `M ${x} ${y}`;
            else pathD += ` L ${x} ${y}`;
          });

          svgHtml += `<path d="${pathD}" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />`;
          data.forEach((d, idx) => {
            if (!d) return;
            const val = d[key] !== undefined ? Number(d[key]) : 0;
            const x = paddingLeft + idx * xStep;
            const y = paddingTop + plotHeight - (plotHeight * val / maxValue);
            svgHtml += `<circle cx="${x}" cy="${y}" r="3.5" fill="${color}" stroke="#0f172a" stroke-width="1">
              <title>${s.label}: ${val}\n${new Date(d.timestamp || d.date).toLocaleString()}</title>
            </circle>`;
          });
        });

        let legendHtml = '<div style="display:flex; justify-content:center; gap:0.6rem; font-size:0.7rem; margin-top:0.4rem; flex-wrap:wrap;">';
        series.forEach(s => {
          if (!s) return;
          legendHtml += `
            <div style="display:flex; align-items:center; gap:0.2rem;">
              <span style="display:inline-block; width:10px; height:3px; background:${s.color || '#3b82f6'}; border-radius:1px;"></span>
              <span style="color:var(--text-muted); font-weight:600;">${s.label || ''}</span>
            </div>`;
        });
        legendHtml += '</div>';

        svgHtml += `</svg>`;
        container.innerHTML = svgHtml + legendHtml;
      } catch (err) {
        console.error(`[SOAR Dashboard] Erro ao renderizar ${containerId}:`, err);
        showChartEmptyState(containerId, 'Erro ao gerar o gráfico.');
      }
    }

    function renderStackedBar(containerId, items, options = {}) {
      const container = safeGetEl(containerId);
      if (!container) {
        console.warn(`[SOAR Dashboard] Container ausente: ${containerId}`);
        return;
      }

      if (!Array.isArray(items) || items.length === 0) {
        showChartEmptyState(containerId);
        return;
      }

      try {
        const validItems = items.filter(i => i && typeof i === 'object');
        const total = validItems.reduce((sum, item) => sum + (Number(item.value) || 0), 0);
        if (total === 0) {
          showChartEmptyState(containerId);
          return;
        }

        let html = '<div style="display: flex; flex-direction: column; gap: 0.8rem; width: 100%; justify-content: center; padding: 0.5rem 0;">';
        html += `<div style="display: flex; width: 100%; height: ${options.height || 20}px; background: rgba(255,255,255,0.04); border-radius: 4px; overflow: hidden; border: 1px solid rgba(255,255,255,0.04);">`;
        validItems.forEach(item => {
          const val = Number(item.value) || 0;
          if (val === 0) return;
          const pct = (val / total * 100).toFixed(1);
          const color = item.color || '#3b82f6';
          const label = item.label || '';
          html += `
            <div style="width: ${pct}%; height: 100%; background: ${color}; display: flex; align-items: center; justify-content: center; color: #fff; font-size: 0.7rem; font-weight: 700; transition: width 0.4s ease;" title="${label}: ${val} (${pct}%)">
              ${pct > 10 ? pct + '%' : ''}
            </div>
          `;
        });
        html += '</div>';

        html += '<div style="display: flex; flex-wrap: wrap; gap: 0.75rem; justify-content: center; font-size: 0.75rem; margin-top: 0.1rem;">';
        validItems.forEach(item => {
          const val = Number(item.value) || 0;
          const color = item.color || '#3b82f6';
          const label = item.label || '';
          html += `
            <div style="display: flex; align-items: center; gap: 0.3rem;">
              <span style="display: inline-block; width: 10px; height: 10px; background: ${color}; border-radius: 2px;"></span>
              <span style="color: var(--text-muted); font-weight: 500;">${label}:</span>
              <span style="color: var(--text-main); font-weight: 700;">${val}</span>
            </div>
          `;
        });
        html += '</div>';
        html += '</div>';

        container.innerHTML = html;
      } catch (err) {
        console.error(`[SOAR Dashboard] Erro ao renderizar ${containerId}:`, err);
        showChartEmptyState(containerId, 'Erro ao gerar o gráfico.');
      }
    }

    function renderMetricComparison(containerId, items, options = {}) {
      const container = safeGetEl(containerId);
      if (!container) {
        console.warn(`[SOAR Dashboard] Container ausente: ${containerId}`);
        return;
      }

      if (!Array.isArray(items) || items.length === 0) {
        showChartEmptyState(containerId);
        return;
      }

      try {
        const validItems = items.filter(i => i && typeof i === 'object');
        if (validItems.length === 0) {
          showChartEmptyState(containerId);
          return;
        }

        let html = `<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 0.5rem; width: 100%; height: 100%; align-content: center; padding: 0.2rem;">`;
        validItems.forEach(item => {
          let diffHtml = '';
          if (item.previousValue !== undefined && item.previousValue !== null && item.previousValue !== '-') {
            const diff = Number(item.value) - Number(item.previousValue);
            const diffColor = diff > 0 ? '#ef4444' : (diff < 0 ? '#10b981' : 'var(--text-muted)');
            const diffSign = diff > 0 ? '+' : '';
            diffHtml = `<span style="font-size: 0.7rem; font-weight: 700; color: ${diffColor}; margin-top: 0.1rem;">${diffSign}${diff} vs ant.</span>`;
          }
          const color = item.color || 'var(--text-main)';
          const label = item.label || '';
          const value = item.value !== undefined ? item.value : '';
          html += `
            <div style="background: rgba(255,255,255,0.01); border: 1px solid rgba(255,255,255,0.04); border-radius: 8px; padding: 0.5rem; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; gap: 0.15rem;">
              <span style="font-size: 0.65rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; height: 24px; line-height: 1.2;">${label}</span>
              <span style="font-size: 1.25rem; font-weight: 800; color: ${color}; line-height: 1.1;">${value}</span>
              ${diffHtml}
            </div>
          `;
        });
        html += '</div>';
        container.innerHTML = html;
      } catch (err) {
        console.error(`[SOAR Dashboard] Erro ao renderizar ${containerId}:`, err);
        showChartEmptyState(containerId, 'Erro ao gerar o gráfico.');
      }
    }
  </script>

  <!-- Footer institucional -->
  <footer style="margin-top: var(--space-2xl); padding-top: var(--space-lg); border-top: 1px solid var(--border-subtle); text-align: center; color: var(--text-muted); font-size: 0.72rem; letter-spacing: 0.02em; opacity: 0.7;">
    <span>HMG Wazuh SOAR Brain v{{SCRIPT_VERSION}}</span>
    <span style="margin: 0 0.5rem;">·</span>
    <span>Gerado em <span id="footer-gen-time">{{GEN_TIME}}</span></span>
    <span style="margin: 0 0.5rem;">·</span>
    <span>Modo: {{{EXEC_MODE}}}</span>
    <span style="margin: 0 0.5rem;">·</span>
    <span>Painel passivo &amp; analítico</span>
  </footer>

</body>
</html>
"""


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nExecução interrompida pelo operador.")
        raise SystemExit(130)
    except Exception as exc:
        logger.critical(f"Falha catastrófica na execução: {exc}")
        raise SystemExit(1)