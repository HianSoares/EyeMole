"""
Orientação Windows: texto, diagnósticos e justificativa separados do comando.

Antes, uma frase genérica em português era publicada no campo `command` com
status "success" e a justificativa ficava vazia. Agora o Windows recebe
orientação textual (guidance_kind="textual"), sem comando de instalação, com
diagnósticos somente leitura e justificativa explícita.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent))

from remediation.engine import RemediationEngine
from remediation.models import generate_finding_id
from remediation.providers.wazuh_provider import _generate_vulnerability_key
from remediation.templates import TemplateRepository


TEMPLATES_PATH = (
    Path(__file__).parent.parent
    / "remediation"
    / "data"
    / "remediation_templates.json"
)


def _engine(tmp_path, vuln, evidence_path=None):
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
    snapshot_path.write_text(json.dumps({"vulnerabilities": [vuln]}), encoding="utf-8")
    kwargs = {}
    if evidence_path is not None:
        kwargs["evidence_path"] = evidence_path
    return RemediationEngine(
        config_dir=config_dir,
        snapshot_path=snapshot_path,
        templates_path=TEMPLATES_PATH,
        **kwargs,
    )


def test_windows_template_never_renders_install_command():
    repo = TemplateRepository(templates_path=TEMPLATES_PATH)

    result = repo.render_command(
        package_manager="windows",
        package_name="Microsoft Windows Server 2019",
        installed_version="10.0.17763.7919",
        fixed_version="10.0.17763.8389",
    )

    assert result is None
    assert repo.is_textual_only("windows")
    diagnostics = repo.render_diagnostics("windows", "Microsoft Windows Server 2019")
    scripts = [d["script"] for d in diagnostics]
    assert any("CurrentBuild" in s and "UBR" in s for s in scripts)
    assert all("Install-" not in s and "wusa" not in s.lower() for s in scripts)


def test_windows_wazuh_scanner_condition_generates_textual_guidance(tmp_path):
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
    engine = _engine(tmp_path, vuln)
    finding_id = _generate_vulnerability_key(
        "CVE-2026-21510", "001", "Microsoft Windows Server 2019", "High",
    )

    guidance = engine.generate_guidance(finding_id)
    data = guidance.to_dict()

    assert guidance.status == "textual_guidance"
    assert guidance.guidance_kind == "textual"
    assert guidance.command is None and "command" not in data
    assert guidance.verification_command is None
    assert guidance.fixed_version == "10.0.17763.8389"
    assert "17763" in guidance.guidance_text and "8389" in guidance.guidance_text
    assert guidance.rationale and "7919" in guidance.rationale and "8389" in guidance.rationale
    # Sem evidência do fabricante: não inventa KB e limita a confiança.
    assert not re.search(r"KB[0-9]+", guidance.guidance_text)
    assert guidance.confidence == "medium"
    assert "vendor_fix_evidence" in guidance.missing_context
    assert "architecture" in guidance.missing_context
    assert data["execution_allowed"] is False
    assert data["contract_version"] == "2"


def test_cve_2025_59287_server_2019_case(tmp_path):
    """Caso da imagem: Server 2019, build 17763.7919, correção 17763.7922 (KB5070883)."""
    package = "Microsoft Windows Server 2019 Datacenter"
    vuln = {
        "cve": "CVE-2025-59287",
        "agent_id": "001",
        "agent_name": "wsus-01",
        "package": package,
        "version": "10.0.17763.7919",
        "severity": "Critical",
        "operating_system": "windows",
        "os_version": "10.0.17763.7919",
        "package_type": "windows",
        "scanner_condition": "Package less than 10.0.17763.7922",
    }
    engine = _engine(tmp_path, vuln)
    finding_id = generate_finding_id(
        "CVE-2025-59287", "001", package, "10.0.17763.7919", "windows",
    )

    guidance = engine.generate_guidance(finding_id)
    data = guidance.to_dict()

    assert guidance.status == "textual_guidance"
    assert guidance.command is None and "command" not in data
    # Evidência oficial vem do catálogo controlado — nunca do campo de comando.
    assert "KB5070883" in guidance.guidance_text
    assert "17763.7922" in guidance.rationale
    assert "WSUS" in guidance.rationale
    assert "substitu" in guidance.guidance_text  # atualizações substitutas
    urls = [s["url"] for s in guidance.sources]
    assert any(u.startswith("https://support.microsoft.com/") for u in urls)
    assert any(u.startswith("https://msrc.microsoft.com/") for u in urls)
    assert guidance.reboot_required == "maybe"
    assert any("KB5005112" in p for p in guidance.prerequisites)
    assert any("WSUS" in w for w in guidance.warnings)
    assert "affected_component_state" in guidance.missing_context
    scripts = [d["script"] for d in guidance.diagnostics]
    assert "Get-WindowsFeature -Name UpdateServices*" in scripts
    assert any("CurrentBuild" in s and "UBR" in s for s in scripts)
    assert guidance.expected_result and "7922" in guidance.expected_result
    assert guidance.confidence == "high"
    assert data["execution_allowed"] is False


def test_windows_different_branch_is_not_compared(tmp_path):
    vuln = {
        "cve": "CVE-2026-0100",
        "agent_id": "001",
        "package": "Microsoft Windows Server 2019",
        "version": "10.0.17763.7919",
        "severity": "High",
        "operating_system": "windows",
        "package_type": "windows",
        "scanner_condition": "Package less than 10.0.20348.100",
    }
    engine = _engine(tmp_path, vuln)
    guidance = engine.generate_guidance(_generate_vulnerability_key(
        "CVE-2026-0100", "001", "Microsoft Windows Server 2019", "High"))

    assert guidance.status == "no_guidance"
    assert guidance.command is None
    assert any("mesmo ramo" in w for w in guidance.warnings)


def test_windows_installed_already_newer_is_not_actionable(tmp_path):
    vuln = {
        "cve": "CVE-2026-0101",
        "agent_id": "001",
        "package": "Microsoft Windows Server 2019",
        "version": "10.0.17763.8000",
        "severity": "High",
        "operating_system": "windows",
        "package_type": "windows",
        "scanner_condition": "Package less than 10.0.17763.7922",
    }
    engine = _engine(tmp_path, vuln)
    guidance = engine.generate_guidance(_generate_vulnerability_key(
        "CVE-2026-0101", "001", "Microsoft Windows Server 2019", "High"))

    assert guidance.status == "no_guidance"
    assert guidance.command is None
    assert "downgrade" in guidance.reason
