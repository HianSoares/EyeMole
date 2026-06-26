#!/usr/bin/env python3
"""
context_bootstrap.py - Automatização pós-instalação para o EyeMole SOAR.
Garante o provisionamento inicial dos JSONs de contexto e políticas.
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime, timezone

# Ativos padrão caso o relatório ainda não tenha rodado
KNOWN_AGENTS = {
    "001": "windows-server-sscapps",
    "003": "linux-server-asc-linux-02",
    "004": "linux-server-asc-linux-01",
    "005": "linux-siemapps",
}

def set_file_permissions(filepath: Path):
    """Ajusta permissões para hmg-soar:www-data e 0640."""
    try:
        # Modificar owner/group se rodando com privilégios suficientes
        import shutil
        filepath.chmod(0o640)
        shutil.chown(str(filepath), user="hmg-soar", group="www-data")
    except Exception as e:
        # Silencioso caso esteja em ambiente de desenvolvimento (ex: Windows)
        pass

def bootstrap(config_dir: Path, latest_json_path: Path):
    config_dir.mkdir(parents=True, exist_ok=True)
    try:
        import shutil
        shutil.chown(str(config_dir), user="hmg-soar", group="www-data")
        config_dir.chmod(0o750)
    except Exception:
        pass

    # 1. Obter lista de agentes/ativos
    agents = {}
    if latest_json_path.exists():
        try:
            with open(latest_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                aid = v.get("agent_id")
                aname = v.get("agent_name")
                if aid and aid != "N/A":
                    agents[str(aid)] = aname or f"agent-{aid}"
            print(f"[+] {len(agents)} agentes identificados a partir do relatório em {latest_json_path}.")
        except Exception as e:
            print(f"[!] Falha ao ler {latest_json_path}: {e}. Utilizando fallbacks padrão.")

    if not agents:
        agents = KNOWN_AGENTS.copy()
        print(f"[+] Utilizando {len(agents)} agentes padrão como fallback.")

    # 2. Inicializar / Atualizar assets_context.json
    assets_path = config_dir / "assets_context.json"
    assets_data = {
        "metadata": {
            "version": "1.0",
            "description": "Mapa de criticidade e contexto de ativos para priorização de risco",
            "updated_by": "system-bootstrap",
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        "defaults": {
            "criticality": "unknown",
            "environment": "unknown",
            "exposure": "unknown",
            "asset_type": "unknown",
            "business_owner": "unknown",
            "technical_owner": "unknown",
            "tags": []
        },
        "agents": {}
    }

    if assets_path.exists():
        try:
            with open(assets_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
            assets_data["metadata"] = existing.get("metadata", assets_data["metadata"])
            assets_data["defaults"] = existing.get("defaults", assets_data["defaults"])
            assets_data["agents"] = existing.get("agents", {})
            print(f"[+] Arquivo assets_context.json existente carregado.")
        except Exception as e:
            print(f"[!] Erro ao analisar assets_context.json existente: {e}. Recriando.")

    added_assets = 0
    for aid, name in agents.items():
        if aid not in assets_data["agents"]:
            assets_data["agents"][aid] = {
                "id": aid,
                "asset_name": name,
                "hostname": name,
                "criticality": "unknown",
                "technical_owner": "unknown",
                "business_owner": "unknown",
                "environment": "unknown",
                "classification_status": "pending"
            }
            added_assets += 1

    with open(assets_path, "w", encoding="utf-8") as f:
        json.dump(assets_data, f, indent=4, ensure_ascii=False)
    print(f"[+] assets_context.json atualizado. Adicionados: {added_assets} ativo(s).")
    set_file_permissions(assets_path)

    # 3. Inicializar / Atualizar exposure_context.json
    exposure_path = config_dir / "exposure_context.json"
    exposure_data = {
        "metadata": {
            "version": "1.0",
            "description": "Mapa de exposição e superfície de ataque para priorização de risco",
            "updated_by": "system-bootstrap",
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        "defaults": {
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
        },
        "agents": {},
        "external_assets": []
    }

    if exposure_path.exists():
        try:
            with open(exposure_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
            exposure_data["metadata"] = existing.get("metadata", exposure_data["metadata"])
            exposure_data["defaults"] = existing.get("defaults", exposure_data["defaults"])
            exposure_data["agents"] = existing.get("agents", {})
            exposure_data["external_assets"] = existing.get("external_assets", [])
            print(f"[+] Arquivo exposure_context.json existente carregado.")
        except Exception as e:
            print(f"[!] Erro ao analisar exposure_context.json existente: {e}. Recriando.")

    added_exposures = 0
    for aid, name in agents.items():
        if aid not in exposure_data["agents"]:
            exposure_data["agents"][aid] = {
                "asset_id": aid,
                "asset_name": name,
                "hostname": name,
                "exposure_level": "unknown",
                "internet_exposed": False,
                "internet_facing": False,
                "critical_services": [],
                "open_services": [],
                "notes": ""
            }
            added_exposures += 1

    with open(exposure_path, "w", encoding="utf-8") as f:
        json.dump(exposure_data, f, indent=4, ensure_ascii=False)
    print(f"[+] exposure_context.json atualizado. Adicionados: {added_exposures} ativo(s).")
    set_file_permissions(exposure_path)

    # 4. sla_policy.json (Criar apenas se ausente)
    sla_path = config_dir / "sla_policy.json"
    if not sla_path.exists():
        sla_data = {
            "metadata": {
                "version": "1.0",
                "description": "Política de SLA para gestão operacional de vulnerabilidades",
                "updated_by": "system-bootstrap",
                "updated_at": datetime.now(timezone.utc).isoformat()
            },
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
        with open(sla_path, "w", encoding="utf-8") as f:
            json.dump(sla_data, f, indent=4, ensure_ascii=False)
        print(f"[+] Criado sla_policy.json.")
        set_file_permissions(sla_path)

    # 5. risk_acceptance.json (Criar apenas se ausente)
    risk_path = config_dir / "risk_acceptance.json"
    if not risk_path.exists():
        risk_data = {
            "metadata": {
                "version": "1.0",
                "description": "Mapa declarativo de exceções, aceite de risco e falsos positivos - baseline HMG",
                "updated_by": "system-bootstrap",
                "updated_at": datetime.now(timezone.utc).isoformat()
            },
            "defaults": {
                "max_acceptance_days": 180,
                "require_expiration": True,
                "require_approver": True,
                "require_reason": True,
                "expired_action": "flag_only"
            },
            "rules": []
        }
        with open(risk_path, "w", encoding="utf-8") as f:
            json.dump(risk_data, f, indent=4, ensure_ascii=False)
        print(f"[+] Criado risk_acceptance.json.")
        set_file_permissions(risk_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootstrap de Contexto Operacional EyeMole SOAR")
    parser.add_argument("--auto", action="store_true", help="Gera com base no arquivo latest.json")
    parser.add_argument("--config-dir", default="/opt/hmg-soar/config", help="Diretório de configuração")
    parser.add_argument("--latest-json", default="/var/www/wazuh-soar/data/latest.json", help="Caminho do latest.json")
    args = parser.parse_args()

    bootstrap(Path(args.config_dir), Path(args.latest_json))
