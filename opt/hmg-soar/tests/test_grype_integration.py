"""
Testes unitários de integração e lógica de fusão do RemediationEngine com GrypeProvider.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from remediation.models import ProviderResult, GrypeVulnRecord, generate_vulnerability_key
from remediation.engine import RemediationEngine


@pytest.fixture
def mock_context(tmp_path):
    """Monta arquivos JSON simulados para carregar os snapshots nos testes."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    
    # remediation_providers.json
    (config_dir / "remediation_providers.json").write_text(
        json.dumps({
            "providers": [
                {"name": "wazuh_snapshot", "enabled": True, "priority": 1},
                {"name": "grype_snapshot", "enabled": True, "priority": 2}
            ]
        })
    )

    # templates (mock mínimo para não dar fail-closed na renderização)
    templates_path = tmp_path / "remediation_templates.json"
    templates_path.write_text(
        json.dumps({
            "templates": {
                "apt": {
                    "remediation": {
                        "with_version": "apt-get install --only-upgrade -y {package_name}={fixed_version}",
                        "generic_update": "apt-get install --only-upgrade -y {package_name}"
                    },
                    "verification": {
                        "check_version": "dpkg -s {package_name}"
                    }
                }
            }
        })
    )

    # Wazuh snapshot (latest.json)
    wazuh_snapshot = tmp_path / "latest.json"
    wazuh_snapshot.write_text(
        json.dumps({
            "vulnerabilities": [
                {
                    "cve": "CVE-2021-23337",
                    "agent_id": "003",
                    "agent_name": "db-server",
                    "package": "lodash",
                    "version": "4.17.15",
                    "severity": "High",
                    "operating_system": "ubuntu",
                    "fixed_version": "N/D" # Wazuh não sabe o fix
                }
            ]
        })
    )

    # Grype snapshot (grype_latest.json)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    grype_snapshot = output_dir / "grype_latest.json"
    
    return {
        "config_dir": config_dir,
        "wazuh_snapshot": wazuh_snapshot,
        "grype_snapshot": grype_snapshot,
        "templates_path": templates_path
    }


def test_fusion_consensus_resolved_fixed_version(mock_context):
    """Garante que fixed_version do Grype preenche o N/D do Wazuh e eleva confiança a 'high'."""
    mock_context["grype_snapshot"].write_text(
        json.dumps({
            "vulnerabilities": [
                {
                    "cve": "CVE-2021-23337",
                    "advisory_id": "GHSA-35jh-r3h4-6jhm",
                    "agent_id": "003",
                    "package_name": "lodash",
                    "installed_version": "4.17.15",
                    "fixed_version": "4.17.21",
                    "fixed_versions": ["4.17.21"],
                    "confidence": "high",
                    "match_type": "exact-direct-match",
                    "status": "fixed"
                }
            ]
        })
    )

    engine = RemediationEngine(
        config_dir=mock_context["config_dir"],
        snapshot_path=mock_context["wazuh_snapshot"],
        templates_path=mock_context["templates_path"]
    )
    engine._grype_provider._grype_path = mock_context["grype_snapshot"]

    finding_id = generate_vulnerability_key("CVE-2021-23337", "003", "lodash", "High")

    guidance = engine.generate_guidance(finding_id)
    
    assert guidance.status == "success"
    assert guidance.fixed_version == "4.17.21"
    assert guidance.confidence == "high"
    assert "apt-get install" in guidance.command


def test_fusion_fixed_status_without_fixed_version_is_unknown(mock_context):
    """Cobre o BUG 1: se o status do Grype for fixed mas fixed_version for None,
    a confiança cai para medium e o status final é no_guidance."""
    mock_context["grype_snapshot"].write_text(
        json.dumps({
            "vulnerabilities": [
                {
                    "cve": "CVE-2021-23337",
                    "advisory_id": "GHSA-35jh-r3h4-6jhm",
                    "agent_id": "003",
                    "package_name": "lodash",
                    "installed_version": "4.17.15",
                    "fixed_version": None,
                    "fixed_versions": [],
                    "confidence": "high",
                    "match_type": "exact-direct-match",
                    "status": "fixed"
                }
            ]
        })
    )

    engine = RemediationEngine(
        config_dir=mock_context["config_dir"],
        snapshot_path=mock_context["wazuh_snapshot"],
        templates_path=mock_context["templates_path"]
    )
    engine._grype_provider._grype_path = mock_context["grype_snapshot"]

    finding_id = generate_vulnerability_key("CVE-2021-23337", "003", "lodash", "High")

    guidance = engine.generate_guidance(finding_id)
    
    assert guidance.status == "no_guidance"
    assert guidance.fixed_version is None
    assert guidance.confidence == "medium"


def test_fusion_fail_closed_on_not_fixed(mock_context):
    """Garante que se o Grype retornar 'not-fixed', a orientação cai em fail-closed (sem comando)."""
    mock_context["grype_snapshot"].write_text(
        json.dumps({
            "vulnerabilities": [
                {
                    "cve": "CVE-2021-23337",
                    "advisory_id": "GHSA-35jh-r3h4-6jhm",
                    "agent_id": "003",
                    "package_name": "lodash",
                    "installed_version": "4.17.15",
                    "fixed_version": None,
                    "fixed_versions": [],
                    "confidence": "high",
                    "match_type": "exact-direct-match",
                    "status": "not-fixed"
                }
            ]
        })
    )

    engine = RemediationEngine(
        config_dir=mock_context["config_dir"],
        snapshot_path=mock_context["wazuh_snapshot"],
        templates_path=mock_context["templates_path"]
    )
    engine._grype_provider._grype_path = mock_context["grype_snapshot"]

    finding_id = generate_vulnerability_key("CVE-2021-23337", "003", "lodash", "High")

    guidance = engine.generate_guidance(finding_id)
    
    assert guidance.status == "insufficient_confidence"
    assert guidance.fixed_version is None
    assert guidance.confidence == "none"
    assert guidance.command is None


def test_single_finding_wazuh_confidence_degraded(mock_context):
    """Garante que se o Grype estiver ativo mas não achar, o achado único do Wazuh tem a confiança degradada."""
    mock_context["grype_snapshot"].write_text(json.dumps({"vulnerabilities": []}))

    engine = RemediationEngine(
        config_dir=mock_context["config_dir"],
        snapshot_path=mock_context["wazuh_snapshot"],
        templates_path=mock_context["templates_path"]
    )
    engine._grype_provider._grype_path = mock_context["grype_snapshot"]

    finding_id = generate_vulnerability_key("CVE-2021-23337", "003", "lodash", "High")

    wazuh_snapshot = mock_context["wazuh_snapshot"]
    wazuh_snapshot.write_text(
        json.dumps({
            "vulnerabilities": [
                {
                    "cve": "CVE-2021-23337",
                    "agent_id": "003",
                    "agent_name": "db-server",
                    "package": "lodash",
                    "version": "4.17.15",
                    "severity": "High",
                    "operating_system": "ubuntu",
                    "fixed_version": "4.17.21"
                }
            ]
        })
    )

    guidance = engine.generate_guidance(finding_id)
    
    assert guidance.status == "success"
    assert guidance.confidence == "medium"
    assert "Vulnerabilidade não confirmada pelo scanner Grype" in guidance.warnings[0]
