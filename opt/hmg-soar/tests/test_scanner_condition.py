from __future__ import annotations

import json
import logging
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent))

from remediation.providers.wazuh_provider import WazuhProvider, _generate_vulnerability_key
from remediation.scanner_condition import parse_scanner_condition


def test_package_less_than_windows_version():
    parsed = parse_scanner_condition("Package less than 10.0.17763.9020")

    assert parsed.fixed_version == "10.0.17763.9020"
    assert parsed.confidence == "high"
    assert parsed.status == "fixed"


def test_package_less_than_rpm_epoch_is_preserved():
    parsed = parse_scanner_condition("Package less than 0:5.14.0-687.12.1.el9_8")

    assert parsed.fixed_version == "0:5.14.0-687.12.1.el9_8"
    assert parsed.confidence == "high"
    assert parsed.status == "fixed"


def test_package_default_status_has_no_fixed_version():
    parsed = parse_scanner_condition("Package default status")

    assert parsed.fixed_version is None
    assert parsed.confidence == "none"
    assert parsed.status == "default_status"


def test_unknown_format_fails_closed_and_logs_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="hmg-soar-remediation.scanner_condition"):
        parsed = parse_scanner_condition("Package below 1.2.3")

    assert parsed.fixed_version is None
    assert parsed.confidence == "none"
    assert parsed.status == "unknown_format"
    assert "Formato scanner.condition não reconhecido" in caplog.text


def test_wazuh_provider_uses_scanner_condition_fixed_version(tmp_path):
    snapshot_path = tmp_path / "latest.json"
    assets_context_path = tmp_path / "assets_context.json"
    vuln = {
        "cve": "CVE-2026-53071",
        "agent_id": "005",
        "agent_name": "linux-siemapps",
        "package": "kernel",
        "version": "5.14.0-611.30.1.el9_7",
        "severity": "High",
        "operating_system": "rocky",
        "os_version": "9.7",
        "scanner_condition": "Package less than 0:5.14.0-687.12.1.el9_8",
    }
    snapshot_path.write_text(
        json.dumps({"vulnerabilities": [vuln]}),
        encoding="utf-8",
    )
    assets_context_path.write_text(json.dumps({"agents": {}}), encoding="utf-8")

    provider = WazuhProvider(
        snapshot_path=snapshot_path,
        assets_context_path=assets_context_path,
    )
    finding_id = _generate_vulnerability_key("CVE-2026-53071", "005", "kernel", "High")

    result = provider.query(finding_id)

    assert result is not None
    assert result.fixed_version == "0:5.14.0-687.12.1.el9_8"
    assert result.confidence == "high"
    assert result.source == "wazuh_snapshot"
    assert "fixed_version extraída de vulnerability.scanner.condition" in result.warnings


def test_wazuh_provider_fails_closed_for_default_status(tmp_path):
    snapshot_path = tmp_path / "latest.json"
    assets_context_path = tmp_path / "assets_context.json"
    vuln = {
        "cve": "CVE-2026-53071",
        "agent_id": "005",
        "agent_name": "linux-siemapps",
        "package": "kernel",
        "version": "5.14.0-611.30.1.el9_7",
        "severity": "High",
        "operating_system": "rocky",
        "scanner_condition": "Package default status",
    }
    snapshot_path.write_text(
        json.dumps({"vulnerabilities": [vuln]}),
        encoding="utf-8",
    )
    assets_context_path.write_text(json.dumps({"agents": {}}), encoding="utf-8")

    provider = WazuhProvider(
        snapshot_path=snapshot_path,
        assets_context_path=assets_context_path,
    )
    finding_id = _generate_vulnerability_key("CVE-2026-53071", "005", "kernel", "High")

    result = provider.query(finding_id)

    assert result is not None
    assert result.fixed_version is None
    assert result.confidence == "low"
