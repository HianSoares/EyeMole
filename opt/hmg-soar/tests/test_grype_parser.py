"""
Testes unitários para o parser de relatórios do Grype com fixture real.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from remediation.models import GrypeVulnRecord
from remediation.providers.grype_parser import parse_grype_output


@pytest.fixture
def real_grype_output():
    """Carrega o arquivo JSON real do scan de lodash na pasta de fixtures."""
    json_path = Path(__file__).resolve().parent / "fixtures" / "grype_lodash_sample.json"
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_parse_real_output_matches(real_grype_output):
    """Garante o parsing correto de todos os 6 matches reais do arquivo."""
    records = parse_grype_output(real_grype_output, agent_id="agent-007")
    
    # Valida contagem dos matches reais detectados no lodash@4.17.15
    assert len(records) == 6
    
    # Todos devem referenciar a mesma biblioteca analisada no teste
    for r in records:
        assert r.agent_id == "agent-007"
        assert r.package_name == "lodash"
        assert r.installed_version == "4.17.15"
        assert r.purl == "pkg:npm/lodash@4.17.15"
        assert r.confidence == "high" # todos são exact-direct-match no teste real
        assert r.match_type == "exact-direct-match"
        assert r.db_version == "v6.1.9 (built: 2026-08-11T06:26:49Z)" # Versão combinada do DB
        assert r.status == "fixed"

    # Verificar o mapeamento específico do primeiro registro (GHSA-35jh-r3h4-6jhm -> CVE-2021-23337)
    cves = {r.cve: r for r in records}
    assert "CVE-2021-23337" in cves
    
    match_cve = cves["CVE-2021-23337"]
    assert match_cve.advisory_id == "GHSA-35jh-r3h4-6jhm"
    assert match_cve.fixed_version == "4.17.21"
    assert match_cve.fixed_versions == ["4.17.21"]


def test_parse_fallback_to_advisory_id():
    """Garante que usa vulnerability.id se relatedVulnerabilities estiver vazio."""
    payload = {
        "matches": [
            {
                "vulnerability": {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "relatedVulnerabilities": [],
                    "fix": {"versions": [], "state": "fixed"}
                },
                "artifact": {"name": "lodash", "version": "4.17.15"}
            }
        ]
    }
    records = parse_grype_output(payload, agent_id="003")
    assert len(records) == 1
    assert records[0].cve == "GHSA-xxxx-yyyy-zzzz"


def test_parse_fail_closed_on_not_fixed():
    """Valida a lógica fail-closed para status 'not-fixed'."""
    payload = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-9999",
                    "fix": {
                        "versions": ["1.2.3"], # Mesmo com versão listada
                        "state": "not-fixed"   # Status manda que não tem fix
                    }
                },
                "artifact": {"name": "badpackage", "version": "1.0.0"}
            }
        ]
    }
    records = parse_grype_output(payload, agent_id="003")
    assert len(records) == 1
    assert records[0].status == "not-fixed"
    assert records[0].fixed_version is None  # FAIL-CLOSED


def test_parse_cpe_match_confidence_low():
    """Garante que matches do tipo 'cpe-match' herdam confiança 'low'."""
    payload = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-1234",
                    "fix": {"versions": [], "state": "unknown"}
                },
                "artifact": {"name": "sys-package", "version": "1.0.0"},
                "matchDetails": [{"type": "cpe-match"}]
            }
        ]
    }
    records = parse_grype_output(payload, agent_id="003")
    assert len(records) == 1
    assert records[0].confidence == "low"
    assert records[0].match_type == "cpe-match"


def test_parse_invalid_input():
    """Valida comportamento robusto com entradas nulas ou vazias."""
    assert parse_grype_output(None, agent_id="003") == []
    assert parse_grype_output({}, agent_id="003") == []
    assert parse_grype_output({"matches": None}, agent_id="003") == []
