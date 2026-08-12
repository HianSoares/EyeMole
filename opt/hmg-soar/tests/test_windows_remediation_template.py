from __future__ import annotations

import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent))

from remediation.engine import RemediationEngine
from remediation.providers.wazuh_provider import _generate_vulnerability_key
from remediation.templates import TemplateRepository


TEMPLATES_PATH = (
    Path(__file__).parent.parent
    / "remediation"
    / "data"
    / "remediation_templates.json"
)


def test_windows_template_generates_manual_guidance_with_real_build():
    repo = TemplateRepository(templates_path=TEMPLATES_PATH)

    result = repo.render_command(
        package_manager="windows",
        package_name="Microsoft Windows Server 2019",
        installed_version="10.0.17763.7919",
        fixed_version="10.0.17763.8389",
    )

    assert result is not None
    assert "Windows Update" in result.remediation
    assert "10.0.17763.8389" in result.remediation
    assert "KB X" not in result.remediation
    assert "Install-WindowsUpdate" not in result.remediation
    assert result.verification == "(Get-CimInstance Win32_OperatingSystem).Version"


def test_windows_wazuh_scanner_condition_generates_guidance(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    snapshot_path = tmp_path / "latest.json"

    (config_dir / "remediation_providers.json").write_text(
        json.dumps({
            "providers": [
                {"name": "wazuh_snapshot", "enabled": True, "priority": 1},
                {"name": "grype_snapshot", "enabled": False, "priority": 2},
            ]
        }),
        encoding="utf-8",
    )
    (config_dir / "generic_update_policy.json").write_text(
        json.dumps({"enabled": False, "allowed_combinations": []}),
        encoding="utf-8",
    )
    (config_dir / "assets_context.json").write_text(
        json.dumps({"agents": {}}),
        encoding="utf-8",
    )

    vuln = {
        "cve": "CVE-2026-21510",
        "agent_id": "001",
        "agent_name": "windows-server-sscapps",
        "package": "Microsoft Windows Server 2019",
        "version": "10.0.17763.7919",
        "severity": "High",
        "operating_system": "windows",
        "os_version": "10.0.17763.7919",
        "scanner_condition": "Package less than 10.0.17763.8389",
    }
    snapshot_path.write_text(
        json.dumps({"vulnerabilities": [vuln]}),
        encoding="utf-8",
    )

    engine = RemediationEngine(
        config_dir=config_dir,
        snapshot_path=snapshot_path,
        templates_path=TEMPLATES_PATH,
    )
    finding_id = _generate_vulnerability_key(
        "CVE-2026-21510",
        "001",
        "Microsoft Windows Server 2019",
        "High",
    )

    guidance = engine.generate_guidance(finding_id)

    assert guidance.status == "success"
    assert guidance.package_manager == "windows"
    assert guidance.fixed_version == "10.0.17763.8389"
    assert "Windows Update" in guidance.command
    assert "10.0.17763.8389" in guidance.command
    assert "KB X" not in guidance.command
    assert "Install-WindowsUpdate" not in guidance.command
    assert guidance.verification_command == "(Get-CimInstance Win32_OperatingSystem).Version"
