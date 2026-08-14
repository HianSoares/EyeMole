from __future__ import annotations

import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent))

from remediation.engine import RemediationEngine
from remediation.providers.wazuh_provider import _generate_vulnerability_key


TEMPLATES_PATH = (
    Path(__file__).parent.parent
    / "remediation"
    / "data"
    / "remediation_templates.json"
)


def _write_config(config_dir: Path) -> None:
    config_dir.mkdir()
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
    (config_dir / "remediation_allowlist.json").write_text(
        json.dumps({
            "os_to_package_manager": {
                "ubuntu": "apt",
                "rocky": "dnf",
                "windows": "windows",
            },
            "package_type_to_package_manager": {
                "deb": "apt",
                "windows": "windows",
            },
            "package_type_os_to_package_manager": {
                "rpm": {
                    "rocky": "dnf",
                },
            },
        }),
        encoding="utf-8",
    )


def _engine_for_vuln(tmp_path: Path, vuln: dict) -> RemediationEngine:
    config_dir = tmp_path / "config"
    _write_config(config_dir)
    snapshot_path = tmp_path / "latest.json"
    snapshot_path.write_text(
        json.dumps({"vulnerabilities": [vuln]}),
        encoding="utf-8",
    )
    return RemediationEngine(
        config_dir=config_dir,
        snapshot_path=snapshot_path,
        templates_path=TEMPLATES_PATH,
    )


def test_snap_package_type_fails_closed_even_on_ubuntu_with_fixed_version(tmp_path):
    vuln = {
        "cve": "CVE-2026-00001",
        "agent_id": "003",
        "agent_name": "linux-server-asc-linux-02",
        "package": "lxd",
        "version": "5.0.0",
        "package_type": "snap",
        "severity": "High",
        "operating_system": "ubuntu",
        "os_version": "22.04.5",
        "scanner_condition": "Package less than 5.21.3",
    }
    engine = _engine_for_vuln(tmp_path, vuln)
    finding_id = _generate_vulnerability_key("CVE-2026-00001", "003", "lxd", "High")

    guidance = engine.generate_guidance(finding_id)

    assert guidance.status == "no_guidance"
    assert guidance.fixed_version == "5.21.3"
    assert guidance.package_manager == ""
    assert guidance.command is None
    assert guidance.verification_command is None
    assert "apt-get" not in (guidance.command or "")
    assert any("package.type 'snap'" in warning for warning in guidance.warnings)


def test_legacy_missing_package_type_still_falls_back_to_os_temporarily(tmp_path):
    vuln = {
        "cve": "CVE-2026-00002",
        "agent_id": "003",
        "agent_name": "linux-server-asc-linux-02",
        "package": "openssl",
        "version": "1.1.1k-1ubuntu1",
        "severity": "High",
        "operating_system": "ubuntu",
        "os_version": "22.04.5",
        "scanner_condition": "Package less than 1.1.1l-1ubuntu1",
    }
    engine = _engine_for_vuln(tmp_path, vuln)
    finding_id = _generate_vulnerability_key("CVE-2026-00002", "003", "openssl", "High")

    guidance = engine.generate_guidance(finding_id)

    assert guidance.status == "success"
    assert guidance.package_manager == "apt"
    assert guidance.command == "sudo apt-get install --only-upgrade openssl"
    assert any("fallback temporário por OS" in assumption for assumption in guidance.assumptions)


def test_rocky_rpm_kernel_devel_regression_keeps_validated_dnf_command(tmp_path):
    vuln = {
        "cve": "CVE-2026-53071",
        "agent_id": "005",
        "agent_name": "linux-siemapps",
        "package": "kernel-devel",
        "version": "5.14.0-611.30.1.el9_7",
        "package_type": "rpm",
        "severity": "High",
        "operating_system": "rocky",
        "os_version": "9.7",
        "scanner_condition": "Package less than 0:5.14.0-687.29.1.el9_8",
    }
    engine = _engine_for_vuln(tmp_path, vuln)
    finding_id = _generate_vulnerability_key(
        "CVE-2026-53071",
        "005",
        "kernel-devel",
        "High",
    )

    guidance = engine.generate_guidance(finding_id)

    assert guidance.status == "success"
    assert guidance.package_manager == "dnf"
    assert guidance.fixed_version == "0:5.14.0-687.29.1.el9_8"
    assert guidance.command == "sudo dnf update kernel-devel-0:5.14.0-687.29.1.el9_8"
    assert guidance.verification_command == "rpm -q kernel-devel"


def test_apt_template_does_not_pin_fixed_version(tmp_path):
    vuln = {
        "cve": "CVE-2026-9669",
        "agent_id": "004",
        "agent_name": "linux-server-asc-linux-01",
        "package": "libpython3.13",
        "version": "3.13.5-2",
        "package_type": "deb",
        "severity": "High",
        "operating_system": "debian",
        "os_version": "13",
        "scanner_condition": "Package less than 3.13.5-2+deb13u3",
    }
    engine = _engine_for_vuln(tmp_path, vuln)
    finding_id = _generate_vulnerability_key("CVE-2026-9669", "004", "libpython3.13", "High")

    guidance = engine.generate_guidance(finding_id)

    assert guidance.status == "success"
    assert guidance.fixed_version == "3.13.5-2+deb13u3"
    assert guidance.command == "sudo apt-get install --only-upgrade libpython3.13"
    assert "=3.13.5-2+deb13u3" not in guidance.command
    assert guidance.verification_command == "dpkg-query -W libpython3.13"


def test_apt_groups_same_cve_agent_packages_in_command(tmp_path):
    vulns = [
        {
            "cve": "CVE-2026-40393",
            "agent_id": "004",
            "agent_name": "linux-server-asc-linux-01",
            "package": package,
            "version": "25.0.7-1",
            "package_type": "deb",
            "severity": "High",
            "operating_system": "debian",
            "os_version": "13",
            "scanner_condition": "Package less than 25.0.7-2",
        }
        for package in ("mesa-vulkan-drivers", "libgbm1", "mesa-libgallium")
    ]
    config_dir = tmp_path / "config"
    _write_config(config_dir)
    snapshot_path = tmp_path / "latest.json"
    snapshot_path.write_text(json.dumps({"vulnerabilities": vulns}), encoding="utf-8")
    engine = RemediationEngine(
        config_dir=config_dir,
        snapshot_path=snapshot_path,
        templates_path=TEMPLATES_PATH,
    )
    finding_id = _generate_vulnerability_key(
        "CVE-2026-40393",
        "004",
        "mesa-vulkan-drivers",
        "High",
    )

    guidance = engine.generate_guidance(finding_id)

    assert guidance.status == "success"
    assert guidance.command == (
        "sudo apt-get install --only-upgrade mesa-vulkan-drivers libgbm1 mesa-libgallium"
    )
    assert guidance.verification_command == "dpkg-query -W mesa-vulkan-drivers"
    assert any("Comando agrupado" in assumption for assumption in guidance.assumptions)


def test_apt_single_package_keeps_single_package_command(tmp_path):
    vuln = {
        "cve": "CVE-2026-11111",
        "agent_id": "004",
        "agent_name": "linux-server-asc-linux-01",
        "package": "openssl",
        "version": "3.0.0-1",
        "package_type": "deb",
        "severity": "High",
        "operating_system": "debian",
        "os_version": "13",
        "scanner_condition": "Package less than 3.0.0-2",
    }
    engine = _engine_for_vuln(tmp_path, vuln)
    finding_id = _generate_vulnerability_key("CVE-2026-11111", "004", "openssl", "High")

    guidance = engine.generate_guidance(finding_id)

    assert guidance.status == "success"
    assert guidance.command == "sudo apt-get install --only-upgrade openssl"
    assert not any("Comando agrupado" in assumption for assumption in guidance.assumptions)


def test_apt_grouping_is_limited_and_warns(tmp_path):
    packages = ["target-package"] + [f"related-lib{i}" for i in range(1, 11)]
    vulns = [
        {
            "cve": "CVE-2026-22222",
            "agent_id": "004",
            "agent_name": "linux-server-asc-linux-01",
            "package": package,
            "version": "1.0",
            "package_type": "deb",
            "severity": "High",
            "operating_system": "debian",
            "os_version": "13",
            "scanner_condition": "Package less than 1.1",
        }
        for package in packages
    ]
    config_dir = tmp_path / "config"
    _write_config(config_dir)
    snapshot_path = tmp_path / "latest.json"
    snapshot_path.write_text(json.dumps({"vulnerabilities": vulns}), encoding="utf-8")
    engine = RemediationEngine(
        config_dir=config_dir,
        snapshot_path=snapshot_path,
        templates_path=TEMPLATES_PATH,
    )
    finding_id = _generate_vulnerability_key("CVE-2026-22222", "004", "target-package", "High")

    guidance = engine.generate_guidance(finding_id)

    grouped_packages = guidance.command.split()[4:]
    assert guidance.status == "success"
    assert len(grouped_packages) == 10
    assert grouped_packages[0] == "target-package"
    assert "related-lib10" not in grouped_packages
    assert any("Encontrados 11 pacotes" in warning for warning in guidance.warnings)
    assert any("primeiros 10" in warning for warning in guidance.warnings)


def test_template_grouping_skips_invalid_package_name_without_dropping_group(tmp_path):
    vuln = {
        "cve": "CVE-2026-33333",
        "agent_id": "004",
        "agent_name": "linux-server-asc-linux-01",
        "package": "valid-package",
        "version": "1.0",
        "package_type": "deb",
        "severity": "High",
        "operating_system": "debian",
        "os_version": "13",
        "scanner_condition": "Package less than 1.1",
    }
    engine = _engine_for_vuln(tmp_path, vuln)

    rendered = engine._template_repo.render_command(
        package_manager="apt",
        package_name="valid-package",
        installed_version="1.0",
        fixed_version="1.1",
        package_names=["valid-package", "bad;package"],
    )

    assert rendered is not None
    assert rendered.remediation == "sudo apt-get install --only-upgrade valid-package"
    assert "bad;package" not in rendered.remediation
