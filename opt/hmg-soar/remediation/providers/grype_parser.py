"""
Parser de relatórios JSON gerados pelo Anchore Grype.
"""

from __future__ import annotations

import json
from typing import List, Optional
from remediation.models import GrypeVulnRecord


def parse_grype_output(raw_json: dict, agent_id: str) -> List[GrypeVulnRecord]:
    """Faz o parsing do JSON bruto do Grype e retorna uma lista de registros normalizados.

    Args:
        raw_json: O dicionário Python contendo o JSON bruto de saída do Grype.
        agent_id: O ID do agente associado ao scan.

    Returns:
        List[GrypeVulnRecord]: Lista de vulnerabilidades identificadas.
    """
    if not isinstance(raw_json, dict):
        return []

    # Extrair a versão do banco de dados do descriptor sob descriptor.db.status
    descriptor = raw_json.get("descriptor", {}) or {}
    db_info = descriptor.get("db", {}) or {}
    db_status = db_info.get("status", {}) or {}
    schema_ver = db_status.get("schemaVersion")
    built_ts = db_status.get("built")

    if schema_ver and built_ts:
        db_version = f"{schema_ver} (built: {built_ts})"
    elif built_ts:
        db_version = f"built: {built_ts}"
    elif schema_ver:
        db_version = schema_ver
    else:
        db_version = "unknown"

    matches = raw_json.get("matches", []) or []
    records = []

    for match in matches:
        if not isinstance(match, dict):
            continue

        vuln = match.get("vulnerability", {}) or {}
        artifact = match.get("artifact", {}) or {}
        match_details = match.get("matchDetails", []) or []

        # 1. Extrair ID do Advisory
        advisory_id = str(vuln.get("id") or "unknown").strip()

        # 2. Extrair o CVE real de relatedVulnerabilities
        cve = advisory_id
        related = match.get("relatedVulnerabilities", []) or []
        for rel in related:
            if not isinstance(rel, dict):
                continue
            rel_id = str(rel.get("id") or "").strip()
            if rel_id.upper().startswith("CVE-"):
                cve = rel_id.upper()
                break

        # 3. Extrair dados do artefato
        package_name = str(artifact.get("name") or "").strip()
        installed_version = str(artifact.get("version") or "").strip()
        purl = str(artifact.get("purl") or "").strip()

        if not package_name or not installed_version:
            continue

        # 4. Extrair status e fix
        fix_info = vuln.get("fix", {}) or {}
        fix_state = str(fix_info.get("state") or "unknown").lower().strip()
        
        # Mapeamento do status (fail-closed)
        if fix_state == "fixed":
            status = "fixed"
        elif fix_state == "not-fixed":
            status = "not-fixed"
        elif fix_state == "wont-fix":
            status = "wont-fix"
        else:
            status = "unknown"

        # Extrair versões corrigidas
        fix_versions = fix_info.get("versions", []) or []
        if not isinstance(fix_versions, list):
            fix_versions = [fix_versions] if fix_versions else []
        fixed_versions = [str(v).strip() for v in fix_versions if v]

        # Fail-closed logic: fixed_version só é preenchida se status for "fixed"
        fixed_version = None
        if status == "fixed" and fixed_versions:
            fixed_version = fixed_versions[0]

        # 5. Extrair match type e confidence
        match_type = ""
        confidence = "none"
        if match_details:
            first_detail = match_details[0]
            if isinstance(first_detail, dict):
                match_type = str(first_detail.get("type") or "").strip()

        # Mapeamento de confidence
        if match_type in ("exact-direct-match", "exact-indirect-match"):
            confidence = "high"
        elif match_type == "cpe-match":
            confidence = "low" # cpe-match rebaixado conforme arquitetura
        elif match_type:
            confidence = "medium"

        record = GrypeVulnRecord(
            cve=cve,
            advisory_id=advisory_id,
            agent_id=agent_id,
            package_name=package_name,
            installed_version=installed_version,
            fixed_version=fixed_version,
            fixed_versions=fixed_versions,
            confidence=confidence,
            match_type=match_type,
            purl=purl,
            source="grype",
            db_version=db_version,
            status=status
        )
        records.append(record)

    return records
