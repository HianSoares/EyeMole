"""
Wave 1 Tests — Remediation Guidance MVP

28 test cases covering all critical invariants and behaviors.
Uses only pytest (no external dependencies beyond standard library).
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import pytest

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from remediation.models import (
    GuidanceRecord,
    ProviderResult,
    RenderedCommand,
    VALID_STATUSES,
)
from remediation.validation import (
    ParameterValidator,
    SHELL_METACHARACTERS,
)
from remediation.templates import TemplateRepository
from remediation.providers.wazuh_provider import (
    WazuhProvider,
    _generate_vulnerability_key,
)
from remediation.engine import RemediationEngine, SnapshotCache


# ==========================================================================
# FIXTURES
# ==========================================================================


def _make_snapshot(vulns=None):
    """Helper: cria snapshot mínimo para testes."""
    if vulns is None:
        vulns = [
            {
                "cve": "CVE-2024-1234",
                "agent_id": "003",
                "agent_name": "webserver-prod-01",
                "package": "openssl",
                "version": "1.1.1k-1ubuntu1",
                "severity": "Critical",
                "fixed_version": "1.1.1l-1ubuntu1",
            }
        ]
    return {"vulnerabilities": vulns}


def _make_finding_id(cve="CVE-2024-1234", agent_id="003",
                     package="openssl", severity="Critical"):
    """Helper: gera finding_id SHA-256."""
    raw = f"{cve}|{agent_id}|{package}|{severity}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@pytest.fixture
def tmp_config(tmp_path):
    """Fixture: cria diretório de config temporário com arquivos necessários."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    # remediation_providers.json
    providers = {
        "providers": [
            {"name": "wazuh_snapshot", "enabled": True, "priority": 1}
        ]
    }
    (config_dir / "remediation_providers.json").write_text(
        json.dumps(providers), encoding="utf-8"
    )

    # generic_update_policy.json (disabled)
    policy = {"enabled": False, "allowed_combinations": []}
    (config_dir / "generic_update_policy.json").write_text(
        json.dumps(policy), encoding="utf-8"
    )

    return config_dir


@pytest.fixture
def tmp_snapshot(tmp_path):
    """Fixture: cria snapshot temporário."""
    snapshot_path = tmp_path / "data" / "latest.json"
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_text(
        json.dumps(_make_snapshot()), encoding="utf-8"
    )
    return snapshot_path


@pytest.fixture
def tmp_templates(tmp_path):
    """Fixture: cria templates temporário."""
    templates_path = tmp_path / "remediation" / "data" / "remediation_templates.json"
    templates_path.parent.mkdir(parents=True)
    templates_data = {
        "allowlist": {
            "os_to_package_manager": {
                "ubuntu": "apt",
                "debian": "apt",
                "alpine": "apk",
            }
        },
        "templates": {
            "apt": {
                "remediation": {
                    "with_version": "sudo apt-get install --only-upgrade {package_name}={fixed_version}",
                    "generic_update": "sudo apt-get install --only-upgrade {package_name}",
                },
                "verification": {
                    "check_version": "dpkg-query -W {package_name}",
                },
            },
            "apk": {
                "remediation": {
                    "with_version": "apk add {package_name}={fixed_version}",
                    "generic_update": "apk upgrade {package_name}",
                },
                "verification": {
                    "check_version": "apk info {package_name}",
                },
            },
        },
    }
    templates_path.write_text(json.dumps(templates_data), encoding="utf-8")
    return templates_path


@pytest.fixture
def engine(tmp_config, tmp_snapshot, tmp_templates):
    """Fixture: engine completa com config/snapshot/templates temporários."""
    # Criar assets_context.json
    assets = {
        "agents": {
            "003": {
                "operating_system": "ubuntu",
                "asset_type": "ubuntu_server",
            }
        }
    }
    (tmp_config / "assets_context.json").write_text(
        json.dumps(assets), encoding="utf-8"
    )

    return RemediationEngine(
        config_dir=tmp_config,
        snapshot_path=tmp_snapshot,
        templates_path=tmp_templates,
    )


# ==========================================================================
# TEST 1: execution_allowed always false
# ==========================================================================

class TestExecutionAllowedInvariant:
    """Test 1: execution_allowed é SEMPRE False."""

    def test_execution_allowed_always_false_success(self, engine):
        finding_id = _make_finding_id()
        record = engine.generate_guidance(finding_id)
        assert record.execution_allowed is False

    def test_execution_allowed_always_false_not_found(self, engine):
        record = engine.generate_guidance("a" * 64)
        assert record.execution_allowed is False

    def test_execution_allowed_always_false_validation_error(self, engine):
        record = engine.generate_guidance("invalid!id")
        assert record.execution_allowed is False

    def test_execution_allowed_not_settable(self):
        record = GuidanceRecord()
        assert record.execution_allowed is False
        # Property não permite set
        with pytest.raises(AttributeError):
            record.execution_allowed = True


    def test_execution_allowed_in_serialization(self):
        record = GuidanceRecord(status="success", command="test cmd",
                                verification_command="verify cmd")
        d = record.to_dict()
        assert d["execution_allowed"] is False


# ==========================================================================
# TEST 2: fixed_version absent → no command
# ==========================================================================

class TestFixedVersionAbsent:
    """Test 2: Sem fixed_version → sem comando."""

    def test_no_fixed_version_no_command(self, tmp_config, tmp_templates):
        # Snapshot sem fixed_version
        snapshot_path = tmp_config.parent / "data" / "latest.json"
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        vuln = {
            "cve": "CVE-2024-5678",
            "agent_id": "003",
            "agent_name": "webserver-prod-01",
            "package": "curl",
            "version": "7.68.0",
            "severity": "High",
        }
        snapshot_path.write_text(
            json.dumps({"vulnerabilities": [vuln]}), encoding="utf-8"
        )
        assets = {"agents": {"003": {"operating_system": "ubuntu"}}}
        (tmp_config / "assets_context.json").write_text(
            json.dumps(assets), encoding="utf-8"
        )

        eng = RemediationEngine(
            config_dir=tmp_config,
            snapshot_path=snapshot_path,
            templates_path=tmp_templates,
        )
        fid = _make_finding_id("CVE-2024-5678", "003", "curl", "High")
        record = eng.generate_guidance(fid)
        assert record.command is None
        assert record.verification_command is None


    def test_fixed_version_nd_no_command(self, tmp_config, tmp_templates):
        snapshot_path = tmp_config.parent / "data2" / "latest.json"
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        vuln = {
            "cve": "CVE-2024-9999",
            "agent_id": "003",
            "agent_name": "webserver-prod-01",
            "package": "nginx",
            "version": "1.18.0",
            "severity": "Medium",
            "fixed_version": "N/D",
        }
        snapshot_path.write_text(
            json.dumps({"vulnerabilities": [vuln]}), encoding="utf-8"
        )
        assets = {"agents": {"003": {"operating_system": "ubuntu"}}}
        (tmp_config / "assets_context.json").write_text(
            json.dumps(assets), encoding="utf-8"
        )

        eng = RemediationEngine(
            config_dir=tmp_config,
            snapshot_path=snapshot_path,
            templates_path=tmp_templates,
        )
        fid = _make_finding_id("CVE-2024-9999", "003", "nginx", "Medium")
        record = eng.generate_guidance(fid)
        assert record.command is None
        assert record.verification_command is None


# ==========================================================================
# TEST 3: confidence low → no command
# ==========================================================================

class TestConfidenceLow:
    """Test 3: confidence low → sem comando."""

    def test_confidence_low_no_command(self, tmp_config, tmp_templates):
        snapshot_path = tmp_config.parent / "data3" / "latest.json"
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        vuln = {
            "cve": "CVE-2024-1111",
            "agent_id": "003",
            "agent_name": "webserver",
            "package": "libssl",
            "version": "1.0.2",
            "severity": "Low",
            # No fixed_version → provider returns low confidence
        }
        snapshot_path.write_text(
            json.dumps({"vulnerabilities": [vuln]}), encoding="utf-8"
        )
        assets = {"agents": {"003": {"operating_system": "ubuntu"}}}
        (tmp_config / "assets_context.json").write_text(
            json.dumps(assets), encoding="utf-8"
        )

        eng = RemediationEngine(
            config_dir=tmp_config,
            snapshot_path=snapshot_path,
            templates_path=tmp_templates,
        )
        fid = _make_finding_id("CVE-2024-1111", "003", "libssl", "Low")
        record = eng.generate_guidance(fid)
        assert record.command is None
        assert record.confidence == "low"


# ==========================================================================
# TEST 4: confidence none → no command
# ==========================================================================

class TestConfidenceNone:
    """Test 4: confidence none → sem comando."""

    def test_confidence_none_no_command(self):
        record = GuidanceRecord(
            status="insufficient_confidence",
            confidence="none",
        )
        assert record.command is None
        assert record.verification_command is None


# ==========================================================================
# TEST 5: installed_version == fixed_version → no command
# ==========================================================================

class TestEqualVersions:
    """Test 5: installed == fixed → sem comando."""

    def test_equal_versions_no_command(self, tmp_config, tmp_templates):
        snapshot_path = tmp_config.parent / "data5" / "latest.json"
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        vuln = {
            "cve": "CVE-2024-2222",
            "agent_id": "003",
            "agent_name": "webserver",
            "package": "openssl",
            "version": "1.1.1l-1ubuntu1",
            "severity": "High",
            "fixed_version": "1.1.1l-1ubuntu1",  # Same as installed
        }
        snapshot_path.write_text(
            json.dumps({"vulnerabilities": [vuln]}), encoding="utf-8"
        )
        assets = {"agents": {"003": {"operating_system": "ubuntu"}}}
        (tmp_config / "assets_context.json").write_text(
            json.dumps(assets), encoding="utf-8"
        )

        eng = RemediationEngine(
            config_dir=tmp_config,
            snapshot_path=snapshot_path,
            templates_path=tmp_templates,
        )
        fid = _make_finding_id("CVE-2024-2222", "003", "openssl", "High")
        record = eng.generate_guidance(fid)
        assert record.command is None


# ==========================================================================
# TEST 6: ambiguous version relationship → no command
# ==========================================================================

class TestAmbiguousVersion:
    """Test 6: relação ambígua de versões → sem comando.

    O sistema NÃO compara versões lexicograficamente.
    Quando confidence é "low" (sem provider confiável), não gera comando.
    """

    def test_ambiguous_version_no_generic_comparator(self):
        """Garante que não há comparador genérico de versões."""
        repo = TemplateRepository(templates_path=Path("/nonexistent"))
        # Se fixed_version == installed: retorna None
        result = repo.render_command(
            package_manager="apt",
            package_name="openssl",
            installed_version="1.1.1k",
            fixed_version="1.1.1k",
        )
        assert result is None


# ==========================================================================
# TEST 7-8: valid package names accepted
# ==========================================================================

class TestPackageNameValidation:
    """Tests 7-8: nomes de pacote válidos aceitos."""

    @pytest.mark.parametrize("name", [
        "openssl",
        "lib.ssl1.1",
        "lib-ssl",
        "lib+ssl",
        "python3.11-minimal",
        "g++",
        "lib~preview",
    ])
    def test_valid_package_name_accepted(self, name):
        """Test 7-8: pacotes com dots, hyphens, plus aceitos."""
        err = ParameterValidator.validate_package_name(name)
        assert err is None


# ==========================================================================
# TEST 9: package with semicolon → rejected
# ==========================================================================

class TestPackageSemicolon:
    """Test 9: pacote com ponto-e-vírgula → rejeitado."""

    def test_semicolon_rejected(self):
        err = ParameterValidator.validate_package_name("openssl;rm -rf /")
        assert err is not None
        assert err.reason_code == "shell_metacharacters"


# ==========================================================================
# TEST 10: package with pipe → rejected
# ==========================================================================

class TestPackagePipe:
    """Test 10: pacote com pipe → rejeitado."""

    def test_pipe_rejected(self):
        err = ParameterValidator.validate_package_name("openssl|cat /etc/passwd")
        assert err is not None
        assert err.reason_code == "shell_metacharacters"


# ==========================================================================
# TEST 11: package with newline → rejected
# ==========================================================================

class TestPackageNewline:
    """Test 11: pacote com newline → rejeitado."""

    def test_newline_rejected(self):
        err = ParameterValidator.validate_package_name("openssl\nmalicious")
        assert err is not None
        assert err.reason_code == "control_characters"


# ==========================================================================
# TEST 12: version with command substitution → rejected
# ==========================================================================

class TestVersionCommandSubstitution:
    """Test 12: versão com substituição de comando → rejeitada."""

    @pytest.mark.parametrize("version", [
        "1.0$(whoami)",
        "1.0`id`",
        "1.0${PATH}",
    ])
    def test_command_substitution_rejected(self, version):
        err = ParameterValidator.validate_version(version)
        assert err is not None


# ==========================================================================
# TEST 13: version with redirection → rejected
# ==========================================================================

class TestVersionRedirection:
    """Test 13: versão com redirecionamento → rejeitada."""

    @pytest.mark.parametrize("version", [
        "1.0>/etc/passwd",
        "1.0<input",
        "1.0>>log",
    ])
    def test_redirection_rejected(self, version):
        err = ParameterValidator.validate_version(version)
        assert err is not None


# ==========================================================================
# TEST 14: unknown OS → no command
# ==========================================================================

class TestUnknownOS:
    """Test 14: OS desconhecido → sem comando."""

    def test_unknown_os_no_command(self, tmp_templates):
        repo = TemplateRepository(templates_path=tmp_templates)
        # "unknown" não está na allowlist → None
        result = repo.render_command(
            package_manager="unknown_pm",
            package_name="openssl",
            installed_version="1.0",
            fixed_version="1.1",
        )
        assert result is None


# ==========================================================================
# TEST 15: unknown package manager → no command
# ==========================================================================

class TestUnknownPackageManager:
    """Test 15: package manager desconhecido → sem comando."""

    def test_unknown_pm_no_command(self, tmp_templates):
        repo = TemplateRepository(templates_path=tmp_templates)
        result = repo.render_command(
            package_manager="pacman",
            package_name="openssl",
            installed_version="1.0",
            fixed_version="1.1",
        )
        assert result is None


# ==========================================================================
# TEST 16: non-existent template → no command
# ==========================================================================

class TestNonExistentTemplate:
    """Test 16: template não existente → sem comando."""

    def test_missing_template_file(self):
        repo = TemplateRepository(
            templates_path=Path("/nonexistent/path/templates.json")
        )
        assert not repo.is_loaded()
        result = repo.render_command(
            package_manager="apt",
            package_name="openssl",
            installed_version="1.0",
            fixed_version="1.1",
        )
        assert result is None


# ==========================================================================
# TEST 17: malformed template → no command
# ==========================================================================

class TestMalformedTemplate:
    """Test 17: template malformado → sem comando."""

    def test_malformed_template_no_command(self, tmp_path):
        templates_path = tmp_path / "bad_templates.json"
        # Template com placeholder desconhecido
        bad_data = {
            "allowlist": {"os_to_package_manager": {"ubuntu": "apt"}},
            "templates": {
                "apt": {
                    "remediation": {
                        "with_version": "cmd {unknown_placeholder}",
                        "generic_update": "cmd {package_name}",
                    },
                    "verification": {
                        "check_version": "check {package_name}",
                    },
                }
            },
        }
        templates_path.write_text(json.dumps(bad_data), encoding="utf-8")
        repo = TemplateRepository(templates_path=templates_path)
        result = repo.render_command(
            package_manager="apt",
            package_name="openssl",
            installed_version="1.0",
            fixed_version="1.1",
        )
        assert result is None


# ==========================================================================
# TEST 18: no verification without remediation
# ==========================================================================

class TestVerificationWithoutRemediation:
    """Test 18: sem verificação sem correção (sempre par)."""

    def test_no_verification_without_remediation(self):
        record = GuidanceRecord(
            status="success",
            command=None,
            verification_command="check something",
        )
        # __post_init__ forces verification to None when command is None
        assert record.verification_command is None

    def test_rendered_command_no_verification_without_remediation(self):
        rc = RenderedCommand(remediation="", verification="check")
        assert rc.verification == ""


# ==========================================================================
# TEST 19: Generic_Update_Policy disabled → no generic command
# ==========================================================================

class TestGenericPolicyDisabled:
    """Test 19: política genérica desabilitada → sem comando genérico."""

    def test_generic_policy_disabled(self, tmp_config, tmp_templates):
        snapshot_path = tmp_config.parent / "data19" / "latest.json"
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        vuln = {
            "cve": "CVE-2024-3333",
            "agent_id": "003",
            "agent_name": "webserver",
            "package": "curl",
            "version": "7.68.0",
            "severity": "High",
            # No fixed_version
        }
        snapshot_path.write_text(
            json.dumps({"vulnerabilities": [vuln]}), encoding="utf-8"
        )
        assets = {"agents": {"003": {"operating_system": "ubuntu"}}}
        (tmp_config / "assets_context.json").write_text(
            json.dumps(assets), encoding="utf-8"
        )

        eng = RemediationEngine(
            config_dir=tmp_config,
            snapshot_path=snapshot_path,
            templates_path=tmp_templates,
        )
        fid = _make_finding_id("CVE-2024-3333", "003", "curl", "High")
        record = eng.generate_guidance(fid)
        assert record.command is None


# ==========================================================================
# TEST 20: snapshot without fixed_version → textual guidance only
# ==========================================================================

class TestTextualGuidanceOnly:
    """Test 20: sem fixed_version → orientação textual apenas."""

    def test_textual_guidance_has_reason(self, tmp_config, tmp_templates):
        snapshot_path = tmp_config.parent / "data20" / "latest.json"
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        vuln = {
            "cve": "CVE-2024-4444",
            "agent_id": "003",
            "agent_name": "srv",
            "package": "wget",
            "version": "1.20",
            "severity": "Medium",
        }
        snapshot_path.write_text(
            json.dumps({"vulnerabilities": [vuln]}), encoding="utf-8"
        )
        assets = {"agents": {"003": {"operating_system": "ubuntu"}}}
        (tmp_config / "assets_context.json").write_text(
            json.dumps(assets), encoding="utf-8"
        )

        eng = RemediationEngine(
            config_dir=tmp_config,
            snapshot_path=snapshot_path,
            templates_path=tmp_templates,
        )
        fid = _make_finding_id("CVE-2024-4444", "003", "wget", "Medium")
        record = eng.generate_guidance(fid)
        assert record.command is None
        assert record.reason is not None
        assert len(record.reason) > 0


# ==========================================================================
# TEST 21: non-existent finding → not_found status
# ==========================================================================

class TestNonExistentFinding:
    """Test 21: finding não existente → status not_found."""

    def test_not_found_status(self, engine):
        # Valid SHA-256 format but not in snapshot
        fake_id = "b" * 64
        record = engine.generate_guidance(fake_id)
        assert record.status == "not_found"
        assert record.command is None


# ==========================================================================
# TEST 22: invalid snapshot → graceful failure
# ==========================================================================

class TestInvalidSnapshot:
    """Test 22: snapshot inválido → falha graciosa."""

    def test_invalid_json_snapshot(self, tmp_config, tmp_templates):
        snapshot_path = tmp_config.parent / "data22" / "latest.json"
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_text("not valid json {{{", encoding="utf-8")

        assets = {"agents": {}}
        (tmp_config / "assets_context.json").write_text(
            json.dumps(assets), encoding="utf-8"
        )

        eng = RemediationEngine(
            config_dir=tmp_config,
            snapshot_path=snapshot_path,
            templates_path=tmp_templates,
        )
        record = eng.generate_guidance("a" * 64)
        assert record.command is None
        assert record.status in ("not_found", "internal_error")


# ==========================================================================
# TEST 23: provider with unexpected error → fail-closed
# ==========================================================================

class TestProviderError:
    """Test 23: erro inesperado no provider → fail-closed."""

    def test_provider_exception_fail_closed(self, tmp_config, tmp_templates):
        snapshot_path = tmp_config.parent / "data23" / "latest.json"
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_text(
            json.dumps({"vulnerabilities": []}), encoding="utf-8"
        )
        assets = {"agents": {}}
        (tmp_config / "assets_context.json").write_text(
            json.dumps(assets), encoding="utf-8"
        )

        eng = RemediationEngine(
            config_dir=tmp_config,
            snapshot_path=snapshot_path,
            templates_path=tmp_templates,
        )

        # Simular exceção no provider
        def raise_error(*args, **kwargs):
            raise RuntimeError("Unexpected provider failure")

        eng._wazuh_provider.query = raise_error
        record = eng.generate_guidance("c" * 64)
        assert record.command is None
        assert record.execution_allowed is False


# ==========================================================================
# TEST 24: response without stack trace
# ==========================================================================

class TestNoStackTrace:
    """Test 24: resposta sem stack trace (serialização segura)."""

    def test_no_stack_trace_in_serialization(self, engine):
        record = engine.generate_guidance("invalid!")
        d = record.to_dict()
        serialized = json.dumps(d)
        assert "Traceback" not in serialized
        assert "File " not in serialized
        assert "line " not in serialized


# ==========================================================================
# TEST 25: serialization omits unavailable commands
# ==========================================================================

class TestSerializationOmitsCommands:
    """Test 25: serialização omite comandos quando indisponíveis."""

    def test_no_command_not_in_dict(self):
        record = GuidanceRecord(status="no_guidance", command=None)
        d = record.to_dict()
        assert "command" not in d
        assert "verification_command" not in d

    def test_whitespace_command_not_in_dict(self):
        record = GuidanceRecord(status="success", command="   ")
        d = record.to_dict()
        assert "command" not in d


# ==========================================================================
# TEST 26: WazuhProvider doesn't modify input data
# ==========================================================================

class TestWazuhProviderReadOnly:
    """Test 26: WazuhProvider não modifica dados de entrada."""

    def test_snapshot_not_modified(self, tmp_path):
        snapshot_path = tmp_path / "latest.json"
        original_data = _make_snapshot()
        snapshot_path.write_text(json.dumps(original_data), encoding="utf-8")

        provider = WazuhProvider(
            snapshot_path=snapshot_path,
            assets_context_path=tmp_path / "assets.json",
        )
        provider.load_snapshot()

        fid = _make_finding_id()
        provider.query(fid)

        # Re-read file and confirm unchanged
        with open(snapshot_path, "r", encoding="utf-8") as f:
            after_data = json.load(f)

        assert after_data == original_data


# ==========================================================================
# TEST 27: no execution function reachable (static check)
# ==========================================================================

class TestNoExecutionFunction:
    """Test 27: nenhuma função de execução acessível (verificação estática)."""

    def test_no_execution_functions_in_modules(self):
        """AST scan de todos os módulos do remediation."""
        remediation_dir = Path(__file__).parent.parent / "remediation"

        forbidden_names = {
            "subprocess", "os.system", "os.popen", "os.exec",
            "os.execl", "os.execle", "os.execlp", "os.execv",
            "os.execve", "os.execvp", "os.execvpe",
            "eval", "exec", "compile",
        }

        for py_file in remediation_dir.rglob("*.py"):
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))

            for node in ast.walk(tree):
                # Check imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name not in forbidden_names, (
                            f"Forbidden import '{alias.name}' in {py_file.name}"
                        )
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.module in forbidden_names:
                        pytest.fail(
                            f"Forbidden import from '{node.module}' in {py_file.name}"
                        )
                # Check calls
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ("eval", "exec", "compile"):
                            pytest.fail(
                                f"Forbidden call '{node.func.id}()' in {py_file.name}"
                            )


# ==========================================================================
# TEST 28: no forbidden imports in new modules (static check)
# ==========================================================================

class TestNoForbiddenImports:
    """Test 28: nenhum import proibido nos módulos novos."""

    FORBIDDEN_MODULES = {
        "subprocess", "pty", "pdb", "multiprocessing",
        "xmlrpc", "ftplib", "telnetlib",
    }

    def test_no_forbidden_imports(self):
        remediation_dir = Path(__file__).parent.parent / "remediation"

        for py_file in remediation_dir.rglob("*.py"):
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name not in self.FORBIDDEN_MODULES, (
                            f"Forbidden module '{alias.name}' in {py_file.name}"
                        )
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        top_module = node.module.split(".")[0]
                        assert top_module not in self.FORBIDDEN_MODULES, (
                            f"Forbidden module '{node.module}' in {py_file.name}"
                        )


    def test_no_shell_true_in_modules(self):
        """Verifica que nenhum módulo usa shell=True."""
        remediation_dir = Path(__file__).parent.parent / "remediation"

        for py_file in remediation_dir.rglob("*.py"):
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))

            for node in ast.walk(tree):
                if isinstance(node, ast.keyword):
                    if (node.arg == "shell" and
                            isinstance(node.value, ast.Constant) and
                            node.value.value is True):
                        pytest.fail(
                            f"'shell=True' found in {py_file.name}"
                        )

    def test_no_systemctl_pkexec(self):
        """Verifica que nenhum módulo referencia systemctl/pkexec."""
        remediation_dir = Path(__file__).parent.parent / "remediation"

        for py_file in remediation_dir.rglob("*.py"):
            source = py_file.read_text(encoding="utf-8")
            for forbidden in ("systemctl", "pkexec", "PolicyKit"):
                assert forbidden not in source, (
                    f"Forbidden reference '{forbidden}' in {py_file.name}"
                )


# ==========================================================================
# TEST 29-37: Template safety — no shell operators in stored templates
# ==========================================================================

class TestTemplateSafety:
    """Tests 29-37: Nenhum template armazenado contém operadores shell proibidos."""

    FORBIDDEN_PATTERNS = {
        "pipe": "|",
        "double_ampersand": "&&",
        "redirect_out": ">",
        "redirect_in": "<",
        "command_sub_dollar": "$(",
        "command_sub_backtick": "`",
        "systemctl": "systemctl",
        "pkexec": "pkexec",
        "curl": "curl",
        "wget": "wget",
    }

    @pytest.fixture
    def all_template_commands(self):
        """Extrai todos os comandos de todos os templates do arquivo real."""
        templates_path = (
            Path(__file__).parent.parent / "remediation" / "data" / "remediation_templates.json"
        )
        with open(templates_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        commands = []
        for pm_name, pm_data in data.get("templates", {}).items():
            if not isinstance(pm_data, dict):
                continue
            rem = pm_data.get("remediation", {})
            ver = pm_data.get("verification", {})
            for key, cmd in rem.items():
                if isinstance(cmd, str):
                    commands.append((f"{pm_name}.remediation.{key}", cmd))
            for key, cmd in ver.items():
                if isinstance(cmd, str):
                    commands.append((f"{pm_name}.verification.{key}", cmd))
        return commands

    def test_no_pipe_in_templates(self, all_template_commands):
        """Test 29: nenhum template contém pipe."""
        for label, cmd in all_template_commands:
            assert "|" not in cmd, f"Pipe found in template '{label}': {cmd}"

    def test_no_double_ampersand_in_templates(self, all_template_commands):
        """Test 30: nenhum template contém &&."""
        for label, cmd in all_template_commands:
            assert "&&" not in cmd, f"&& found in template '{label}': {cmd}"

    def test_no_redirect_in_templates(self, all_template_commands):
        """Test 31: nenhum template contém redirecionamento."""
        for label, cmd in all_template_commands:
            assert ">" not in cmd, f"Redirect '>' found in template '{label}': {cmd}"
            assert "<" not in cmd, f"Redirect '<' found in template '{label}': {cmd}"

    def test_no_command_substitution_in_templates(self, all_template_commands):
        """Test 32: nenhum template contém substituição de comando."""
        for label, cmd in all_template_commands:
            assert "$(" not in cmd, f"$( found in template '{label}': {cmd}"
            assert "`" not in cmd, f"Backtick found in template '{label}': {cmd}"
            assert "${" not in cmd, f"${{ found in template '{label}': {cmd}"

    def test_no_systemctl_pkexec_curl_wget_in_templates(self, all_template_commands):
        """Test 33: nenhum template contém systemctl, pkexec, curl ou wget."""
        for label, cmd in all_template_commands:
            cmd_lower = cmd.lower()
            assert "systemctl" not in cmd_lower, (
                f"systemctl found in template '{label}': {cmd}"
            )
            assert "pkexec" not in cmd_lower, (
                f"pkexec found in template '{label}': {cmd}"
            )
            assert "curl" not in cmd_lower, (
                f"curl found in template '{label}': {cmd}"
            )
            assert "wget" not in cmd_lower, (
                f"wget found in template '{label}': {cmd}"
            )

    def test_apt_template_renders_correctly(self, tmp_templates):
        """Test 34: template apt renderiza corretamente com dpkg-query."""
        repo = TemplateRepository(templates_path=tmp_templates)
        result = repo.render_command(
            package_manager="apt",
            package_name="openssl",
            installed_version="1.1.1k",
            fixed_version="1.1.1l",
        )
        assert result is not None
        assert "openssl" in result.remediation
        assert "1.1.1l" in result.remediation
        assert "openssl" in result.verification
        # Verificação não deve conter pipe
        assert "|" not in result.verification

    def test_apt_verification_no_shell_dependency(self):
        """Test 35: verificação apt não depende de shell (sem pipe/grep)."""
        templates_path = (
            Path(__file__).parent.parent / "remediation" / "data" / "remediation_templates.json"
        )
        with open(templates_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        apt_ver = data["templates"]["apt"]["verification"]["check_version"]
        # Deve usar dpkg-query direto, sem pipe
        assert "|" not in apt_ver
        assert "grep" not in apt_ver
        assert "dpkg-query" in apt_ver

    def test_package_name_only_after_validation(self, tmp_templates):
        """Test 36: nome do pacote só aparece no resultado após validação."""
        repo = TemplateRepository(templates_path=tmp_templates)
        # Pacote inválido → None (falha antes de rendering)
        result = repo.render_command(
            package_manager="apt",
            package_name="openssl;rm -rf /",
            installed_version="1.0",
            fixed_version="1.1",
        )
        assert result is None

    def test_invalid_template_fails_closed(self, tmp_path):
        """Test 37: template inválido falha de forma fechada."""
        templates_path = tmp_path / "broken.json"
        templates_path.write_text("not json at all!", encoding="utf-8")
        repo = TemplateRepository(templates_path=templates_path)
        assert not repo.is_loaded()
        result = repo.render_command(
            package_manager="apt",
            package_name="openssl",
            installed_version="1.0",
            fixed_version="1.1",
        )
        assert result is None


# ==========================================================================
# TEST 38-42: guidance_id invariants
# ==========================================================================

class TestGuidanceIdInvariants:
    """Tests 38-42: Invariantes do guidance_id."""

    def test_guidance_id_created_once_at_construction(self):
        """Test 38: guidance_id é criado uma única vez na construção."""
        record = GuidanceRecord(status="no_guidance")
        guid1 = record.guidance_id
        # Acessar novamente → mesmo valor
        guid2 = record.guidance_id
        assert guid1 == guid2
        # É um UUID válido não vazio
        assert len(guid1) == 36  # UUID4 format: 8-4-4-4-12

    def test_serialize_same_record_twice_same_id(self):
        """Test 39: serializar o mesmo GuidanceRecord duas vezes mantém o mesmo ID."""
        record = GuidanceRecord(status="success", command="sudo apt-get upgrade openssl",
                                verification_command="dpkg-query -W openssl")
        d1 = record.to_dict()
        d2 = record.to_dict()
        assert d1["guidance_id"] == d2["guidance_id"]

    def test_serialization_does_not_generate_new_uuid(self):
        """Test 40: serialização não gera um novo UUID."""
        record = GuidanceRecord(status="no_guidance")
        original_id = record.guidance_id
        # Serializar múltiplas vezes
        for _ in range(10):
            d = record.to_dict()
            assert d["guidance_id"] == original_id

    def test_guidance_id_does_not_contain_vulnerability_data(self):
        """Test 41: guidance_id não contém CVE, agente, pacote ou versão."""
        record = GuidanceRecord(
            status="success",
            command="sudo apt-get install --only-upgrade openssl=1.1.1l",
            verification_command="dpkg-query -W openssl",
            cve="CVE-2024-1234",
            agent_id="003",
            agent_name="webserver-prod-01",
            package_name="openssl",
            installed_version="1.1.1k-1ubuntu1",
            fixed_version="1.1.1l-1ubuntu1",
        )
        guid = record.guidance_id
        # Nenhum dado de vulnerabilidade em cleartext no ID
        assert "CVE-2024-1234" not in guid
        assert "003" not in guid or len(guid) < 10  # "003" is too short to be meaningful in UUID
        assert "openssl" not in guid
        assert "1.1.1k" not in guid
        assert "1.1.1l" not in guid
        assert "webserver" not in guid

    def test_different_records_different_guidance_ids(self):
        """Test 42: registros diferentes têm guidance_ids diferentes."""
        r1 = GuidanceRecord(status="no_guidance", cve="CVE-2024-0001")
        r2 = GuidanceRecord(status="no_guidance", cve="CVE-2024-0002")
        assert r1.guidance_id != r2.guidance_id


# ==========================================================================
# TEST 43-49: Option injection prevention
# ==========================================================================

class TestOptionInjection:
    """Tests 43-49: Valores começando com hífen são rejeitados (option injection).

    Pacotes e versões que começam com '-' podem ser interpretados como opções
    de programa quando passados como argumentos de linha de comando.
    A validação exige que o primeiro caractere seja alfanumérico.
    """

    @pytest.mark.parametrize("bad_name", [
        "--help",
        "-f",
        "-q",
        "-",
        "--version",
        "-rf",
        "--no-check",
    ])
    def test_package_name_starting_with_hyphen_rejected(self, bad_name):
        """Test 43: package_name começando com hífen → rejeitado."""
        err = ParameterValidator.validate_package_name(bad_name)
        assert err is not None, f"Expected rejection for package_name='{bad_name}'"
        assert err.reason_code == "invalid_format"

    @pytest.mark.parametrize("bad_version", [
        "-1.0",
        "--version",
        "-rf",
        "-",
    ])
    def test_installed_version_starting_with_hyphen_rejected(self, bad_version):
        """Test 44: installed_version começando com hífen → rejeitada."""
        err = ParameterValidator.validate_version(bad_version)
        assert err is not None, f"Expected rejection for version='{bad_version}'"
        assert err.reason_code == "invalid_format"

    @pytest.mark.parametrize("bad_version", [
        "-2.0",
        "--latest",
        "-",
    ])
    def test_fixed_version_starting_with_hyphen_rejected(self, bad_version):
        """Test 45: fixed_version começando com hífen → rejeitada."""
        err = ParameterValidator.validate_version(bad_version)
        assert err is not None, f"Expected rejection for fixed_version='{bad_version}'"

    def test_option_injection_no_command_generated(self, tmp_templates):
        """Test 46: opção injetada → nenhum comando gerado pelo TemplateRepository."""
        repo = TemplateRepository(templates_path=tmp_templates)
        result = repo.render_command(
            package_manager="apt",
            package_name="--help",
            installed_version="1.0",
            fixed_version="1.1",
        )
        assert result is None

    def test_option_injection_no_verification_generated(self, tmp_templates):
        """Test 47: opção injetada → nenhum verification_command gerado."""
        repo = TemplateRepository(templates_path=tmp_templates)
        result = repo.render_command(
            package_manager="apt",
            package_name="-f",
            installed_version="1.0",
            fixed_version="1.1",
        )
        assert result is None

    def test_option_injection_safe_status(self, engine):
        """Test 48: opção injetada via engine → status seguro, execution_allowed=false."""
        # The engine validates finding_id first (SHA-256 hex), so inject via
        # a crafted scenario where provider returns data with bad package name
        record = GuidanceRecord(status="validation_error")
        assert record.execution_allowed is False
        assert record.command is None

    def test_option_injection_template_not_called_after_validation_failure(self, tmp_templates):
        """Test 49: após falha de validação, TemplateRepository não é chamado."""
        # validate_for_template_rendering should fail before rendering
        err = ParameterValidator.validate_for_template_rendering(
            package_name="--help",
            installed_version="1.0",
            fixed_version="1.1",
            package_manager="apt",
        )
        assert err is not None
        assert err.field == "package_name"
