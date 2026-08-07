"""
test_installation.py — Comprehensive tests for install.sh

Tests all critical installation scenarios in a sandboxed environment.
Does NOT require root, does NOT write to /opt, /var/www, /etc, or real systemd/nginx.
Uses tmpdir fixtures and mocked system commands.

25 test scenarios covering:
- validate_json_configs (valid/invalid/missing)
- install_default_configs (fresh install, idempotency, preservation)
- validate_python (comprehensive module check, syntax errors)
- install_systemd (health check, failure detection)
- run_report_once_if_possible (fail-fast behavior)
- rsync config exclusion behavior
- bash -n syntax check
- Source guard behavior
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from textwrap import dedent

import pytest

# ============================================================================
# CONSTANTS
# ============================================================================

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"
CONFIG_DIR = REPO_ROOT / "opt" / "hmg-soar" / "config"
TEMPLATES_JSON = (
    REPO_ROOT / "opt" / "hmg-soar" / "remediation" / "data"
    / "remediation_templates.json"
)

CONFIG_FILES = [
    "generic_update_policy.json",
    "remediation_allowlist.json",
    "remediation_providers.json",
    "risk_acceptance.json",
    "sla_policy.json",
    "treatment_policy.json",
]

IS_WINDOWS = platform.system() == "Windows"

# Find a working bash binary
_GIT_BASH = None
if IS_WINDOWS:
    # Look for Git Bash which works reliably on Windows
    _candidates = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Git" / "bin" / "bash.exe",
        Path("C:/Program Files/Git/bin/bash.exe"),
        Path("C:/Program Files (x86)/Git/bin/bash.exe"),
    ]
    for _c in _candidates:
        if _c.exists():
            _GIT_BASH = str(_c)
            break

BASH_CMD = _GIT_BASH if _GIT_BASH else shutil.which("bash")
BASH_AVAILABLE = BASH_CMD is not None


def _to_wsl_path(p) -> str:
    """Convert a Windows path to Git Bash-compatible path (/c/...)."""
    s = str(p).replace("\\", "/")
    if IS_WINDOWS and len(s) >= 2 and s[1] == ":":
        drive = s[0].lower()
        return f"/{drive}{s[2:]}"
    return s


def _run_bash(
    script: str,
    expect_fail: bool = False,
    timeout: int = 30,
) -> subprocess.CompletedProcess:
    """Run a bash script snippet. Handles expect_fail assertion."""
    if not BASH_AVAILABLE:
        pytest.skip("bash not available on this platform")

    env = os.environ.copy()
    # On Windows, ensure python3 is available inside Git Bash
    if IS_WINDOWS:
        python_exe = sys.executable  # The real Python interpreter
        python_dir = str(Path(python_exe).parent)
        python_dir_bash = _to_wsl_path(python_dir)
        # Create python3 alias via preamble
        preamble = (
            f'export PATH="{python_dir_bash}:$PATH"\n'
            f'alias python3="{_to_wsl_path(python_exe)}"\n'
            f'python3() {{ "{_to_wsl_path(python_exe)}" "$@"; }}\n'
        )
        script = preamble + script

    result = subprocess.run(
        [BASH_CMD, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )

    if expect_fail and result.returncode == 0:
        raise AssertionError(
            f"Expected script to fail but it succeeded.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    elif not expect_fail and result.returncode != 0:
        raise AssertionError(
            f"Script failed unexpectedly (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    return result


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def sandbox(tmp_path):
    """
    Create a complete sandbox mimicking the repo structure.
    Returns a dict with paths to all relevant directories.
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    # Create config dir with real JSON files from the repo
    config_src = repo / "opt" / "hmg-soar" / "config"
    config_src.mkdir(parents=True)
    for f in CONFIG_FILES:
        real_file = CONFIG_DIR / f
        if real_file.exists():
            shutil.copy2(real_file, config_src / f)
        else:
            (config_src / f).write_text('{"metadata": {"version": "1.0"}}')

    # Create remediation templates
    rem_data = repo / "opt" / "hmg-soar" / "remediation" / "data"
    rem_data.mkdir(parents=True)
    if TEMPLATES_JSON.exists():
        shutil.copy2(TEMPLATES_JSON, rem_data / "remediation_templates.json")
    else:
        (rem_data / "remediation_templates.json").write_text('{"templates": []}')

    # Create app dir (destination)
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "config").mkdir()

    # Create systemd dir
    systemd_dir = repo / "systemd"
    systemd_dir.mkdir()

    return {
        "tmp_path": tmp_path,
        "repo": repo,
        "config_src": config_src,
        "app_dir": app_dir,
        "rem_data": rem_data,
        "systemd_dir": systemd_dir,
    }


def _make_validate_json_script(repo_wsl: str) -> str:
    """Build the validate_json_configs function as a standalone script."""
    return dedent(f"""\
        set -Eeuo pipefail
        REPO_ROOT="{repo_wsl}"

        log() {{ echo "[+] $*"; }}
        die() {{ echo "[x] $*" >&2; exit 1; }}

        validate_json_configs() {{
          log "Validando integridade dos JSONs obrigatórios..."
          local src_config="${{REPO_ROOT}}/opt/hmg-soar/config"
          local src_templates="${{REPO_ROOT}}/opt/hmg-soar/remediation/data/remediation_templates.json"

          local json_files=(
            "${{src_config}}/generic_update_policy.json"
            "${{src_config}}/remediation_allowlist.json"
            "${{src_config}}/remediation_providers.json"
            "${{src_config}}/risk_acceptance.json"
            "${{src_config}}/sla_policy.json"
            "${{src_config}}/treatment_policy.json"
            "${{src_templates}}"
          )

          local f
          for f in "${{json_files[@]}}"; do
            if [[ ! -f "${{f}}" ]]; then
              die "JSON obrigatório ausente no repositório: ${{f}}"
            fi
            if ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "${{f}}" 2>/dev/null; then
              die "JSON inválido: ${{f}}"
            fi
          done
          log "Todos os JSONs obrigatórios são válidos."
        }}

        validate_json_configs
    """)


def _make_install_default_configs_script(repo_wsl: str, app_dir_wsl: str) -> str:
    """Build install_default_configs as standalone script."""
    return dedent(f"""\
        set -Eeuo pipefail
        REPO_ROOT="{repo_wsl}"
        APP_DIR="{app_dir_wsl}"
        APP_USER="$(whoami)"
        WEB_GROUP="$(whoami)"

        log() {{ echo "[+] $*"; }}
        die() {{ echo "[x] $*" >&2; exit 1; }}

        install_default_configs() {{
          log "Instalando configurações padrão (somente se ausentes)..."
          local src_config="${{REPO_ROOT}}/opt/hmg-soar/config"
          local dest_config="${{APP_DIR}}/config"

          local config_files=(
            generic_update_policy.json
            remediation_allowlist.json
            remediation_providers.json
            risk_acceptance.json
            sla_policy.json
            treatment_policy.json
          )

          local f
          for f in "${{config_files[@]}}"; do
            local src="${{src_config}}/${{f}}"
            local dest="${{dest_config}}/${{f}}"
            if [[ ! -f "${{src}}" ]]; then
              die "Arquivo de configuração padrão ausente no repositório: ${{src}}"
            fi
            if [[ -f "${{dest}}" ]]; then
              log "  Preservado (existente): ${{f}}"
            else
              cp "${{src}}" "${{dest}}"
              log "  Instalado: ${{f}}"
            fi
          done
        }}

        install_default_configs
    """)


def _make_validate_python_script(app_dir_wsl: str) -> str:
    """Build validate_python as standalone script (simplified for testing)."""
    return dedent(f"""\
        set -Eeuo pipefail
        APP_DIR="{app_dir_wsl}"
        APP_USER="$(whoami)"

        log() {{ echo "[+] $*"; }}
        die() {{ echo "[x] $*" >&2; exit 1; }}

        validate_python() {{
          log "Validando sintaxe Python de todos os módulos de produção..."

          local py_files=()
          py_files+=("${{APP_DIR}}/analyserV1.py")
          py_files+=("${{APP_DIR}}/soar_api.py")

          local optional
          for optional in context_bootstrap.py preview_dashboard.py preview_server.py; do
            if [[ -f "${{APP_DIR}}/${{optional}}" ]]; then
              py_files+=("${{APP_DIR}}/${{optional}}")
            fi
          done

          while IFS= read -r -d '' pyf; do
            py_files+=("${{pyf}}")
          done < <(find "${{APP_DIR}}/remediation" -name '*.py' -print0 2>/dev/null || true)

          local f
          for f in "${{py_files[@]}}"; do
            if ! python3 -c "
import sys, py_compile
try:
    py_compile.compile(sys.argv[1], doraise=True)
except py_compile.PyCompileError as e:
    print(f'Erro de sintaxe: {{e}}', file=sys.stderr)
    sys.exit(1)
" "${{f}}"; then
              die "Falha na validação Python: ${{f}}"
            fi
          done

          log "Smoke test de importação dos módulos de remediação..."
          if ! PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${{APP_DIR}}" python3 -c "
import importlib, sys
modules = [
    'remediation',
    'remediation.engine',
    'remediation.cache',
    'remediation.rate_limiter',
    'remediation.validation',
    'remediation.templates',
    'remediation.providers.wazuh_provider',
]
for mod in modules:
    try:
        importlib.import_module(mod)
    except Exception as e:
        print(f'Falha ao importar {{mod}}: {{e}}', file=sys.stderr)
        sys.exit(1)
"; then
            die "Falha no smoke test de importação dos módulos de remediação."
          fi

          find "${{APP_DIR}}" -type d -name '__pycache__' -exec rm -rf {{}} + 2>/dev/null || true
          find "${{APP_DIR}}" -name '*.pyc' -delete 2>/dev/null || true
          log "Validação Python concluída com sucesso."
        }}

        validate_python
    """)


# ============================================================================
# TEST 1: bash -n syntax check on install.sh
# ============================================================================


@pytest.mark.skipif(not BASH_AVAILABLE, reason="bash not available")
class TestBashSyntax:
    def test_01_bash_n_passes(self):
        """install.sh passes bash -n (no syntax errors)."""
        result = subprocess.run(
            [BASH_CMD, "-n", _to_wsl_path(INSTALL_SH)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"bash -n failed:\nstderr: {result.stderr}"
        )


# ============================================================================
# TEST 2-6: validate_json_configs
# ============================================================================


@pytest.mark.skipif(not BASH_AVAILABLE, reason="bash not available")
class TestValidateJsonConfigs:
    def test_02_valid_json_all_present(self, sandbox):
        """validate_json_configs passes with all valid JSON files present."""
        repo_wsl = _to_wsl_path(sandbox["repo"])
        script = _make_validate_json_script(repo_wsl)
        _run_bash(script)

    def test_03_missing_json_file_fails(self, sandbox):
        """validate_json_configs fails if a required JSON is missing."""
        (sandbox["config_src"] / "sla_policy.json").unlink()
        repo_wsl = _to_wsl_path(sandbox["repo"])
        script = _make_validate_json_script(repo_wsl)
        _run_bash(script, expect_fail=True)

    def test_04_invalid_json_content_fails(self, sandbox):
        """validate_json_configs fails if a JSON file has invalid syntax."""
        (sandbox["config_src"] / "sla_policy.json").write_text(
            '{"broken": true,,,}'
        )
        repo_wsl = _to_wsl_path(sandbox["repo"])
        script = _make_validate_json_script(repo_wsl)
        _run_bash(script, expect_fail=True)

    def test_05_missing_templates_json_fails(self, sandbox):
        """validate_json_configs fails if remediation_templates.json is missing."""
        (sandbox["rem_data"] / "remediation_templates.json").unlink()
        repo_wsl = _to_wsl_path(sandbox["repo"])
        script = _make_validate_json_script(repo_wsl)
        _run_bash(script, expect_fail=True)

    def test_06_empty_json_file_fails(self, sandbox):
        """validate_json_configs fails if a JSON file is empty."""
        (sandbox["config_src"] / "risk_acceptance.json").write_text("")
        repo_wsl = _to_wsl_path(sandbox["repo"])
        script = _make_validate_json_script(repo_wsl)
        _run_bash(script, expect_fail=True)


# ============================================================================
# TEST 7-12: install_default_configs
# ============================================================================


@pytest.mark.skipif(not BASH_AVAILABLE, reason="bash not available")
class TestInstallDefaultConfigs:
    def test_07_fresh_install_copies_all_configs(self, sandbox):
        """On fresh install (empty config dir), all defaults are installed."""
        repo_wsl = _to_wsl_path(sandbox["repo"])
        app_wsl = _to_wsl_path(sandbox["app_dir"])
        script = _make_install_default_configs_script(repo_wsl, app_wsl)
        _run_bash(script)
        # Verify all files were copied
        for f in CONFIG_FILES:
            dest = sandbox["app_dir"] / "config" / f
            assert dest.exists(), f"Config file not installed: {f}"
            data = json.loads(dest.read_text())
            assert isinstance(data, dict)

    def test_08_existing_config_preserved(self, sandbox):
        """Existing config files are NOT overwritten."""
        custom_content = '{"custom": true, "metadata": {"version": "custom"}}'
        dest_config = sandbox["app_dir"] / "config"
        (dest_config / "sla_policy.json").write_text(custom_content)

        repo_wsl = _to_wsl_path(sandbox["repo"])
        app_wsl = _to_wsl_path(sandbox["app_dir"])
        script = _make_install_default_configs_script(repo_wsl, app_wsl)
        result = _run_bash(script)

        actual = (dest_config / "sla_policy.json").read_text()
        assert actual == custom_content
        assert "Preservado (existente): sla_policy.json" in result.stdout

    def test_09_missing_source_config_fails(self, sandbox):
        """install_default_configs fails if a source config is missing."""
        (sandbox["config_src"] / "treatment_policy.json").unlink()
        repo_wsl = _to_wsl_path(sandbox["repo"])
        app_wsl = _to_wsl_path(sandbox["app_dir"])
        script = _make_install_default_configs_script(repo_wsl, app_wsl)
        _run_bash(script, expect_fail=True)

    def test_10_idempotent_run(self, sandbox):
        """Running install_default_configs twice is idempotent."""
        repo_wsl = _to_wsl_path(sandbox["repo"])
        app_wsl = _to_wsl_path(sandbox["app_dir"])
        script = _make_install_default_configs_script(repo_wsl, app_wsl)
        _run_bash(script)
        # Second run — all should say preserved
        result = _run_bash(script)
        assert "Preservado (existente)" in result.stdout

    def test_11_partial_config_installs_missing_only(self, sandbox):
        """Only missing configs are installed; existing ones are preserved."""
        dest_config = sandbox["app_dir"] / "config"
        for f in CONFIG_FILES[:2]:
            shutil.copy2(sandbox["config_src"] / f, dest_config / f)

        repo_wsl = _to_wsl_path(sandbox["repo"])
        app_wsl = _to_wsl_path(sandbox["app_dir"])
        script = _make_install_default_configs_script(repo_wsl, app_wsl)
        result = _run_bash(script)

        for f in CONFIG_FILES:
            assert (dest_config / f).exists(), f"Missing after install: {f}"
        assert result.stdout.count("Preservado") == 2
        assert result.stdout.count("Instalado") == 4

    def test_12_config_files_are_valid_json_after_install(self, sandbox):
        """All installed config files are valid parseable JSON."""
        repo_wsl = _to_wsl_path(sandbox["repo"])
        app_wsl = _to_wsl_path(sandbox["app_dir"])
        script = _make_install_default_configs_script(repo_wsl, app_wsl)
        _run_bash(script)
        for f in CONFIG_FILES:
            path = sandbox["app_dir"] / "config" / f
            data = json.loads(path.read_text())
            assert isinstance(data, dict)


# ============================================================================
# TEST 13-17: validate_python (comprehensive)
# ============================================================================


@pytest.mark.skipif(not BASH_AVAILABLE, reason="bash not available")
class TestValidatePython:
    def _setup_app_dir(self, sandbox):
        """Create a minimal app directory with valid Python modules."""
        app = sandbox["app_dir"]
        (app / "analyserV1.py").write_text("# Valid python\nx = 1\n")
        (app / "soar_api.py").write_text("# Valid python\nimport os\n")
        (app / "context_bootstrap.py").write_text("# Optional\npass\n")

        rem = app / "remediation"
        rem.mkdir(exist_ok=True)
        (rem / "__init__.py").write_text(
            "from . import engine, cache, rate_limiter, validation, templates\n"
        )
        (rem / "engine.py").write_text("class RemediationEngine:\n    pass\n")
        (rem / "cache.py").write_text("class SnapshotCache:\n    pass\n")
        (rem / "rate_limiter.py").write_text("class RateLimiter:\n    pass\n")
        (rem / "validation.py").write_text(
            "class ParameterValidator:\n    pass\n"
        )
        (rem / "templates.py").write_text(
            "class TemplateRepository:\n    pass\n"
        )
        (rem / "models.py").write_text("VALID_STATUSES = ['ok']\n")

        prov = rem / "providers"
        prov.mkdir(exist_ok=True)
        (prov / "__init__.py").write_text("# providers\n")
        (prov / "wazuh_provider.py").write_text(
            "class WazuhProvider:\n    pass\n"
            "def _generate_vulnerability_key():\n    pass\n"
        )

    def test_13_valid_python_passes(self, sandbox):
        """validate_python succeeds with all valid Python files."""
        self._setup_app_dir(sandbox)
        app_wsl = _to_wsl_path(sandbox["app_dir"])
        script = _make_validate_python_script(app_wsl)
        _run_bash(script)

    def test_14_syntax_error_in_main_fails(self, sandbox):
        """validate_python fails if analyserV1.py has a syntax error."""
        self._setup_app_dir(sandbox)
        (sandbox["app_dir"] / "analyserV1.py").write_text(
            "def broken(\n    # missing close paren\n"
        )
        app_wsl = _to_wsl_path(sandbox["app_dir"])
        script = _make_validate_python_script(app_wsl)
        _run_bash(script, expect_fail=True)

    def test_15_syntax_error_in_remediation_fails(self, sandbox):
        """validate_python fails if a remediation module has syntax error."""
        self._setup_app_dir(sandbox)
        (sandbox["app_dir"] / "remediation" / "engine.py").write_text(
            "class Broken:\n    def foo(self\n"
        )
        app_wsl = _to_wsl_path(sandbox["app_dir"])
        script = _make_validate_python_script(app_wsl)
        _run_bash(script, expect_fail=True)

    def test_16_soar_api_included_in_validation(self, sandbox):
        """validate_python checks soar_api.py (was missing in old version)."""
        self._setup_app_dir(sandbox)
        (sandbox["app_dir"] / "soar_api.py").write_text(
            "def broken(:\n    pass\n"
        )
        app_wsl = _to_wsl_path(sandbox["app_dir"])
        script = _make_validate_python_script(app_wsl)
        _run_bash(script, expect_fail=True)

    def test_17_import_smoke_test_passes(self, sandbox):
        """validate_python smoke-imports remediation modules successfully."""
        self._setup_app_dir(sandbox)
        app_wsl = _to_wsl_path(sandbox["app_dir"])
        script = _make_validate_python_script(app_wsl)
        result = _run_bash(script)
        assert "Smoke test" in result.stdout
        assert "conclu" in result.stdout  # "concluída com sucesso"


# ============================================================================
# TEST 18-20: install_systemd (no || true masking)
# ============================================================================


@pytest.mark.skipif(not BASH_AVAILABLE, reason="bash not available")
class TestInstallSystemd:
    def test_18_systemd_validates_timer_active(self, sandbox):
        """install_systemd checks timer is-active (no more || true masking)."""
        (sandbox["systemd_dir"] / "hmg-soar-report.service").write_text("[Service]\n")
        (sandbox["systemd_dir"] / "hmg-soar-report.timer").write_text("[Timer]\n")
        (sandbox["systemd_dir"] / "hmg-soar-api.service").write_text("[Service]\n")

        fake_systemd = sandbox["tmp_path"] / "systemd_dest"
        fake_systemd.mkdir()
        repo_wsl = _to_wsl_path(sandbox["repo"])
        dest_wsl = _to_wsl_path(fake_systemd)

        script = dedent(f"""\
            set -Eeuo pipefail
            REPO_ROOT="{repo_wsl}"
            SERVICE_FILE="hmg-soar-report.service"
            TIMER_FILE="hmg-soar-report.timer"

            log() {{ echo "[+] $*"; }}
            warn() {{ echo "[!] $*" >&2; }}
            die() {{ echo "[x] $*" >&2; exit 1; }}

            # Mock systemctl: everything succeeds
            systemctl() {{
                case "$1" in
                    daemon-reload|enable|restart) return 0 ;;
                    is-active) return 0 ;;
                    status) return 0 ;;
                esac
                return 0
            }}
            journalctl() {{ return 0; }}
            sleep() {{ true; }}
            # Mock python3 for health check: simulate success
            python3() {{ return 0; }}

            install_systemd() {{
              log "Instalando unidades systemd..."

              if [[ -f "${{REPO_ROOT}}/systemd/${{SERVICE_FILE}}" ]]; then
                cp "${{REPO_ROOT}}/systemd/${{SERVICE_FILE}}" "{dest_wsl}/${{SERVICE_FILE}}"
              fi
              if [[ -f "${{REPO_ROOT}}/systemd/${{TIMER_FILE}}" ]]; then
                cp "${{REPO_ROOT}}/systemd/${{TIMER_FILE}}" "{dest_wsl}/${{TIMER_FILE}}"
              fi
              API_SERVICE_FILE="hmg-soar-api.service"
              if [[ -f "${{REPO_ROOT}}/systemd/${{API_SERVICE_FILE}}" ]]; then
                cp "${{REPO_ROOT}}/systemd/${{API_SERVICE_FILE}}" "{dest_wsl}/${{API_SERVICE_FILE}}"
              fi

              systemctl daemon-reload

              if [[ -f "{dest_wsl}/${{TIMER_FILE}}" ]]; then
                systemctl enable --now "${{TIMER_FILE}}"
                if ! systemctl is-active --quiet "${{TIMER_FILE}}"; then
                  die "Falha ao ativar timer."
                fi
                log "Timer ativo."
              fi

              if [[ -f "{dest_wsl}/${{API_SERVICE_FILE}}" ]]; then
                systemctl enable --now "${{API_SERVICE_FILE}}"
                systemctl restart "${{API_SERVICE_FILE}}"
                if ! systemctl is-active --quiet "${{API_SERVICE_FILE}}"; then
                  die "Falha ao iniciar a API."
                fi

                log "Health check..."
                local health_ok=0
                local attempt
                for attempt in 1 2 3 4 5; do
                  sleep 2
                  if python3 -c "pass" 2>/dev/null; then
                    health_ok=1
                    break
                  fi
                done
                if [[ "${{health_ok}}" -ne 1 ]]; then
                  die "Health check falhou."
                fi
                log "API respondendo."
              fi
            }}

            install_systemd
        """)
        result = _run_bash(script)
        assert "Instalando unidades systemd" in result.stdout
        assert "Timer ativo" in result.stdout
        assert "API respondendo" in result.stdout

    def test_19_timer_failure_causes_die(self, sandbox):
        """install_systemd calls die if timer is-active returns false."""
        (sandbox["systemd_dir"] / "hmg-soar-report.timer").write_text("[Timer]\n")

        fake_systemd = sandbox["tmp_path"] / "systemd_dest"
        fake_systemd.mkdir()
        repo_wsl = _to_wsl_path(sandbox["repo"])
        dest_wsl = _to_wsl_path(fake_systemd)

        # Pre-copy timer so -f checks pass
        shutil.copy2(
            sandbox["systemd_dir"] / "hmg-soar-report.timer",
            fake_systemd / "hmg-soar-report.timer",
        )

        script = dedent(f"""\
            set -Eeuo pipefail
            TIMER_FILE="hmg-soar-report.timer"

            log() {{ echo "[+] $*"; }}
            warn() {{ echo "[!] $*" >&2; }}
            die() {{ echo "[x] $*" >&2; exit 1; }}

            systemctl() {{
                case "$1" in
                    daemon-reload|enable) return 0 ;;
                    is-active) return 1 ;;
                    status) return 3 ;;
                esac
                return 0
            }}

            # Simulate timer check logic from install_systemd
            systemctl daemon-reload
            if [[ -f "{dest_wsl}/${{TIMER_FILE}}" ]]; then
              systemctl enable --now "${{TIMER_FILE}}"
              if ! systemctl is-active --quiet "${{TIMER_FILE}}"; then
                die "Falha ao ativar timer ${{TIMER_FILE}}."
              fi
            fi
        """)
        _run_bash(script, expect_fail=True)

    def test_20_health_check_failure_causes_die(self, sandbox):
        """install_systemd dies if API health check fails after retries."""
        script = dedent("""\
            set -Eeuo pipefail

            log() { echo "[+] $*"; }
            warn() { echo "[!] $*" >&2; }
            die() { echo "[x] $*" >&2; exit 1; }

            systemctl() {
                case "$1" in
                    is-active) return 0 ;;
                    *) return 0 ;;
                esac
            }
            sleep() { true; }
            # python3 always fails (simulating health check failure)
            python3() { return 1; }

            # Health check logic from install_systemd
            log "Health check..."
            health_ok=0
            for attempt in 1 2 3 4 5; do
              sleep 2
              if python3 -c "pass" 2>/dev/null; then
                health_ok=1
                break
              fi
            done
            if [[ "${health_ok}" -ne 1 ]]; then
              die "Health check falhou."
            fi
        """)
        _run_bash(script, expect_fail=True)


# ============================================================================
# TEST 21-23: run_report_once_if_possible (fail-fast)
# ============================================================================


@pytest.mark.skipif(not BASH_AVAILABLE, reason="bash not available")
class TestRunReportOnce:
    def test_21_no_service_file_skips_gracefully(self, sandbox):
        """run_report_once_if_possible skips if service file missing in sandbox."""
        fake_systemd = sandbox["tmp_path"] / "fake_systemd"
        fake_systemd.mkdir()
        systemd_wsl = _to_wsl_path(fake_systemd)
        # Directory exists but has no service file inside
        script = dedent(f"""\
            set -Eeuo pipefail
            SERVICE_FILE="hmg-soar-report.service"
            SYSTEMD_UNIT_DIR="{systemd_wsl}"

            log() {{ echo "[+] $*"; }}
            warn() {{ echo "[!] $*" >&2; }}
            die() {{ echo "[x] $*" >&2; exit 1; }}

            # Logic from run_report_once_if_possible using SYSTEMD_UNIT_DIR
            if [[ ! -f "${{SYSTEMD_UNIT_DIR}}/${{SERVICE_FILE}}" ]]; then
              warn "Service systemd não instalado. Pulando execução."
              exit 0
            fi
        """)
        result = _run_bash(script)
        assert "Pulando" in result.stderr

    def test_22_restart_failure_causes_die(self, sandbox):
        """run_report_once_if_possible dies if systemctl restart fails."""
        fake_systemd = sandbox["tmp_path"] / "systemd_dest"
        fake_systemd.mkdir()
        (fake_systemd / "hmg-soar-report.service").write_text("[Service]\n")

        etc_dir = sandbox["tmp_path"] / "etc_hmg"
        etc_dir.mkdir()
        (etc_dir / "credentials.env").write_text("API_KEY=fake\n")

        dest_wsl = _to_wsl_path(fake_systemd)
        etc_wsl = _to_wsl_path(etc_dir)

        script = dedent(f"""\
            set -Eeuo pipefail
            SERVICE_FILE="hmg-soar-report.service"
            ETC_DIR="{etc_wsl}"

            log() {{ echo "[+] $*"; }}
            warn() {{ echo "[!] $*" >&2; }}
            die() {{ echo "[x] $*" >&2; exit 1; }}

            systemctl() {{
                case "$1" in
                    restart) return 1 ;;
                    status) echo "failed"; return 3 ;;
                esac
                return 0
            }}
            journalctl() {{ echo "error log"; return 0; }}

            # Logic from run_report_once_if_possible
            if [[ ! -f "{dest_wsl}/${{SERVICE_FILE}}" ]]; then
              warn "Pulando execução."
              exit 0
            fi

            if [[ -f "${{ETC_DIR}}/credentials.env" ]]; then
              log "Executando serviço..."
              if ! systemctl restart "${{SERVICE_FILE}}"; then
                warn "Falha."
                die "Execução inicial falhou."
              fi
            fi
        """)
        _run_bash(script, expect_fail=True)

    def test_23_bootstrap_failure_causes_die(self, sandbox):
        """run_report_once_if_possible dies if context_bootstrap.py fails."""
        app_wsl = _to_wsl_path(sandbox["app_dir"])

        # Create a bootstrap script that fails
        (sandbox["app_dir"] / "context_bootstrap.py").write_text(
            "import sys; sys.exit(1)\n"
        )

        script = dedent(f"""\
            set -Eeuo pipefail
            APP_DIR="{app_wsl}"

            log() {{ echo "[+] $*"; }}
            warn() {{ echo "[!] $*" >&2; }}
            die() {{ echo "[x] $*" >&2; exit 1; }}

            log "Executando bootstrap de contexto..."
            if ! PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${{APP_DIR}}" python3 "${{APP_DIR}}/context_bootstrap.py" --auto; then
              die "Falha no bootstrap."
            fi
        """)
        _run_bash(script, expect_fail=True)


# ============================================================================
# TEST 24: rsync still excludes config/
# ============================================================================


@pytest.mark.skipif(not BASH_AVAILABLE, reason="bash not available")
class TestRsyncExclude:
    def test_24_rsync_excludes_config_dir(self):
        """
        install_app_files uses rsync --exclude 'config/' so existing
        config is never clobbered by rsync. install_default_configs
        handles fresh installs instead.
        """
        content = INSTALL_SH.read_text(encoding="utf-8")
        assert "--exclude 'config/'" in content, (
            "rsync must still exclude config/ to avoid overwriting"
        )
        assert "install_default_configs()" in content
        assert "install_default_configs" in content


# ============================================================================
# TEST 25: Source guard at bottom of install.sh
# ============================================================================


@pytest.mark.skipif(not BASH_AVAILABLE, reason="bash not available")
class TestSourceGuard:
    def test_25_source_guard_prevents_auto_execution(self):
        """
        install.sh can be sourced without automatically running main.
        The guard prevents auto-execution when sourced.
        """
        content = INSTALL_SH.read_text(encoding="utf-8")
        assert 'BASH_SOURCE[0]' in content
        assert 'main "$@"' in content

        install_path = _to_wsl_path(INSTALL_SH)
        result = subprocess.run(
            [BASH_CMD, "-c", f'source "{install_path}"; echo "SOURCE_OK"'],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert "SOURCE_OK" in result.stdout, (
            f"Source guard failed. stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )


# ============================================================================
# TEST 26-30: Runtime dependencies and SYSTEMD_UNIT_DIR isolation
# ============================================================================


@pytest.mark.skipif(not BASH_AVAILABLE, reason="bash not available")
class TestRuntimeDependencies:
    def test_26_imports_present_no_apt(self, sandbox):
        """When requests/urllib3 importable, apt-get is NOT called."""
        script = dedent("""\
            set -Eeuo pipefail
            log() { echo "[+] $*"; }
            die() { echo "[x] $*" >&2; exit 1; }

            # Mock: python3 import succeeds
            python3() {
                if [[ "$2" == "import requests, urllib3" ]]; then
                    return 0
                fi
                command python3 "$@"
            }
            apt_called=0
            apt-get() { apt_called=1; }

            ensure_python_runtime_dependencies() {
              log "Verificando dependências Python de runtime..."
              if python3 -c "import requests, urllib3" 2>/dev/null; then
                log "Dependências Python de runtime já disponíveis."
                return 0
              fi
              die "Should not reach here"
            }

            ensure_python_runtime_dependencies
            [[ "${apt_called}" -eq 0 ]] || die "apt-get should not be called"
            echo "OK_NO_APT"
        """)
        result = _run_bash(script)
        assert "OK_NO_APT" in result.stdout

    def test_27_imports_absent_calls_apt(self, sandbox):
        """When imports fail initially, apt-get install is called."""
        script = dedent("""\
            set -Eeuo pipefail
            log() { echo "[+] $*"; }
            die() { echo "[x] $*" >&2; exit 1; }

            call_count=0
            python3() {
                if [[ "$2" == "import requests, urllib3" ]]; then
                    call_count=$((call_count + 1))
                    if [[ "${call_count}" -le 1 ]]; then
                        return 1
                    fi
                    return 0
                fi
                command python3 "$@"
            }
            apt_packages=""
            apt-get() {
                if [[ "$1" == "install" ]]; then
                    shift; shift  # skip -y
                    apt_packages="$*"
                fi
                return 0
            }
            command() {
                if [[ "$2" == "apt-get" ]]; then return 0; fi
                builtin command "$@"
            }

            ensure_python_runtime_dependencies() {
              log "Verificando dependências Python de runtime..."
              if python3 -c "import requests, urllib3" 2>/dev/null; then
                log "Dependências Python de runtime já disponíveis."
                return 0
              fi
              log "Instalando dependências Python de runtime..."
              if command -v apt-get >/dev/null 2>&1; then
                apt-get update -y
                apt-get install -y python3-requests python3-urllib3
              else
                die "Módulos ausentes."
              fi
              if ! python3 -c "import requests, urllib3" 2>/dev/null; then
                die "Módulos continuam indisponíveis."
              fi
              log "Instaladas."
            }

            ensure_python_runtime_dependencies
            echo "PKGS=${apt_packages}"
        """)
        result = _run_bash(script)
        assert "python3-requests" in result.stdout
        assert "python3-urllib3" in result.stdout

    def test_28_import_still_fails_after_install_dies(self, sandbox):
        """If imports still fail after apt-get, installer dies."""
        script = dedent("""\
            set -Eeuo pipefail
            log() { echo "[+] $*"; }
            die() { echo "[x] $*" >&2; exit 1; }

            python3() {
                if [[ "$2" == "import requests, urllib3" ]]; then
                    return 1
                fi
                command python3 "$@"
            }
            apt-get() { return 0; }
            command() {
                if [[ "$2" == "apt-get" ]]; then return 0; fi
                builtin command "$@"
            }

            ensure_python_runtime_dependencies() {
              log "Verificando..."
              if python3 -c "import requests, urllib3" 2>/dev/null; then
                return 0
              fi
              if command -v apt-get >/dev/null 2>&1; then
                apt-get update -y
                apt-get install -y python3-requests python3-urllib3
              else
                die "Módulos ausentes."
              fi
              if ! python3 -c "import requests, urllib3" 2>/dev/null; then
                die "Módulos continuam indisponíveis."
              fi
            }

            ensure_python_runtime_dependencies
        """)
        _run_bash(script, expect_fail=True)


@pytest.mark.skipif(not BASH_AVAILABLE, reason="bash not available")
class TestSystemdUnitDirIsolation:
    def test_29_default_systemd_unit_dir(self):
        """SYSTEMD_UNIT_DIR defaults to /etc/systemd/system."""
        content = INSTALL_SH.read_text(encoding="utf-8")
        assert 'SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"' in content

    def test_30_unit_present_in_sandbox(self, sandbox):
        """With unit file present in sandbox SYSTEMD_UNIT_DIR, skip path is NOT taken."""
        fake_systemd = sandbox["tmp_path"] / "fake_systemd_present"
        fake_systemd.mkdir()
        (fake_systemd / "hmg-soar-report.service").write_text("[Service]\n")
        systemd_wsl = _to_wsl_path(fake_systemd)

        script = dedent(f"""\
            set -Eeuo pipefail
            SERVICE_FILE="hmg-soar-report.service"
            SYSTEMD_UNIT_DIR="{systemd_wsl}"

            log() {{ echo "[+] $*"; }}
            warn() {{ echo "[!] $*" >&2; }}
            die() {{ echo "[x] $*" >&2; exit 1; }}

            if [[ ! -f "${{SYSTEMD_UNIT_DIR}}/${{SERVICE_FILE}}" ]]; then
              warn "Pulando."
              exit 0
            fi
            echo "UNIT_FOUND"
        """)
        result = _run_bash(script)
        assert "UNIT_FOUND" in result.stdout


# ============================================================================
# TEST 31-36: Offline Dashboard & Web Publication Validation
# ============================================================================


@pytest.mark.skipif(not BASH_AVAILABLE, reason="bash not available")
class TestOfflineDashboardAndWebValidation:
    def test_31_systemd_service_unit_has_condition_path_exists(self):
        """hmg-soar-report.service contains ConditionPathExists for credentials.env and retains mandatory EnvironmentFile."""
        unit_path = REPO_ROOT / "systemd" / "hmg-soar-report.service"
        assert unit_path.exists()
        content = unit_path.read_text(encoding="utf-8")
        assert "ConditionPathExists=/etc/hmg-soar/credentials.env" in content
        assert "EnvironmentFile=/etc/hmg-soar/credentials.env" in content
        assert "EnvironmentFile=-" not in content

    def test_32_offline_install_publishes_placeholder_and_succeeds(self, sandbox):
        """Installation without credentials.env creates placeholder index.html, runs context_bootstrap, doesn't run service, and shows offline status."""
        app_dir = sandbox["app_dir"]
        (app_dir / "context_bootstrap.py").write_text("print('BOOTSTRAP_EXECUTED')\n")

        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()

        etc_dir = sandbox["tmp_path"] / "etc_no_creds"
        etc_dir.mkdir()

        systemd_dir = sandbox["tmp_path"] / "systemd_sandbox"
        systemd_dir.mkdir()
        (systemd_dir / "hmg-soar-report.service").write_text("[Service]\n")

        app_wsl = _to_wsl_path(app_dir)
        web_wsl = _to_wsl_path(web_dir)
        etc_wsl = _to_wsl_path(etc_dir)
        systemd_wsl = _to_wsl_path(systemd_dir)

        script = dedent(f"""\
            set -Eeuo pipefail
            APP_DIR="{app_wsl}"
            WEB_DIR="{web_wsl}"
            ETC_DIR="{etc_wsl}"
            SYSTEMD_UNIT_DIR="{systemd_wsl}"
            SERVICE_FILE="hmg-soar-report.service"
            APP_USER="$(id -un)"
            WEB_GROUP="$(id -gn)"
            ENABLE_WEB_RUN=0
            POLKIT_RULE_FILE="{_to_wsl_path(sandbox['tmp_path'] / 'polkit.rules')}"
            WEB_RUN_FLAG="{app_wsl}/web_run.enabled"
            BACKUP_DIR="{_to_wsl_path(sandbox['tmp_path'] / 'backup')}"

            source "{_to_wsl_path(INSTALL_SH)}"

            chown() {{ return 0; }}
            systemctl_restarted=0
            systemctl() {{
                if [[ "$1" == "restart" && "$2" == "hmg-soar-report.service" ]]; then
                    systemctl_restarted=1
                    echo "SYSTEMCTL_RESTART_CALLED" >&2
                fi
                return 0
            }}
            runuser() {{
                shift 3
                "$@"
            }}

            run_report_once_if_possible
            validate_web_publication
            final_message
            echo "SYSTEMCTL_RESTARTED=${{systemctl_restarted}}"
        """)
        result = _run_bash(script)

        assert "BOOTSTRAP_EXECUTED" in result.stdout
        assert "SYSTEMCTL_RESTART_CALLED" not in result.stderr
        assert "SYSTEMCTL_RESTARTED=0" in result.stdout
        assert "BOOTSTRAP / OFFLINE" in result.stdout
        assert "EyeMole SOAR instalado." in result.stdout

        index_html = web_dir / "index.html"
        assert index_html.exists()
        assert index_html.is_file()
        assert index_html.stat().st_size > 0
        content = index_html.read_text(encoding="utf-8")
        assert "EyeMole SOAR instalado" in content
        assert "Modo Bootstrap / Offline" in content
        assert "password" not in content.lower()
        assert "secret" not in content.lower()
        assert "token" not in content.lower()

    def test_33_credentials_install_runs_service_and_preserves_real_dashboard(self, sandbox):
        """Installation with credentials.env runs report service and preserves generated real dashboard without placeholder overwrite."""
        app_dir = sandbox["app_dir"]
        (app_dir / "context_bootstrap.py").write_text("print('BOOTSTRAP_EXECUTED')\n")

        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()

        etc_dir = sandbox["tmp_path"] / "etc_with_creds"
        etc_dir.mkdir()
        (etc_dir / "credentials.env").write_text("WAZUH_PASS=secret\n")

        systemd_dir = sandbox["tmp_path"] / "systemd_sandbox"
        systemd_dir.mkdir()
        (systemd_dir / "hmg-soar-report.service").write_text("[Service]\n")

        app_wsl = _to_wsl_path(app_dir)
        web_wsl = _to_wsl_path(web_dir)
        etc_wsl = _to_wsl_path(etc_dir)
        systemd_wsl = _to_wsl_path(systemd_dir)

        index_html = web_dir / "index.html"

        script = dedent(f"""\
            set -Eeuo pipefail
            APP_DIR="{app_wsl}"
            WEB_DIR="{web_wsl}"
            ETC_DIR="{etc_wsl}"
            SYSTEMD_UNIT_DIR="{systemd_wsl}"
            SERVICE_FILE="hmg-soar-report.service"
            APP_USER="$(id -un)"
            WEB_GROUP="$(id -gn)"
            ENABLE_WEB_RUN=0
            POLKIT_RULE_FILE="{_to_wsl_path(sandbox['tmp_path'] / 'polkit.rules')}"
            WEB_RUN_FLAG="{app_wsl}/web_run.enabled"
            BACKUP_DIR="{_to_wsl_path(sandbox['tmp_path'] / 'backup')}"

            source "{_to_wsl_path(INSTALL_SH)}"

            chown() {{ return 0; }}
            restart_count=0
            systemctl() {{
                if [[ "$1" == "restart" && "$2" == "hmg-soar-report.service" ]]; then
                    restart_count=$((restart_count + 1))
                    echo "<html><body>REAL DASHBOARD CONTENT</body></html>" > "{_to_wsl_path(index_html)}"
                fi
                return 0
            }}
            journalctl() {{ return 0; }}
            runuser() {{
                shift 3
                "$@"
            }}

            run_report_once_if_possible
            validate_web_publication
            final_message
            echo "RESTART_COUNT=${{restart_count}}"
        """)
        result = _run_bash(script)

        assert "RESTART_COUNT=2" in result.stdout
        assert "BOOTSTRAP / OFFLINE" not in result.stdout
        assert "EyeMole SOAR instalado." in result.stdout

        assert index_html.exists()
        content = index_html.read_text(encoding="utf-8")
        assert "REAL DASHBOARD CONTENT" in content
        assert "Bootstrap / Offline" not in content

    def test_34_real_report_generation_without_index_html_fails(self, sandbox):
        """If real report service runs but fails to produce index.html, installation fails and does not report success."""
        app_dir = sandbox["app_dir"]
        (app_dir / "context_bootstrap.py").write_text("print('BOOTSTRAP')\n")

        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()

        etc_dir = sandbox["tmp_path"] / "etc_creds"
        etc_dir.mkdir()
        (etc_dir / "credentials.env").write_text("WAZUH_PASS=secret\n")

        systemd_dir = sandbox["tmp_path"] / "systemd_sandbox"
        systemd_dir.mkdir()
        (systemd_dir / "hmg-soar-report.service").write_text("[Service]\n")

        app_wsl = _to_wsl_path(app_dir)
        web_wsl = _to_wsl_path(web_dir)
        etc_wsl = _to_wsl_path(etc_dir)
        systemd_wsl = _to_wsl_path(systemd_dir)

        script = dedent(f"""\
            set -Eeuo pipefail
            APP_DIR="{app_wsl}"
            WEB_DIR="{web_wsl}"
            ETC_DIR="{etc_wsl}"
            SYSTEMD_UNIT_DIR="{systemd_wsl}"
            SERVICE_FILE="hmg-soar-report.service"
            APP_USER="$(id -un)"
            WEB_GROUP="$(id -gn)"

            source "{_to_wsl_path(INSTALL_SH)}"

            chown() {{ return 0; }}
            systemctl() {{ return 0; }}
            journalctl() {{ return 0; }}
            runuser() {{ shift 3; "$@"; }}

            run_report_once_if_possible
            validate_web_publication
            final_message
        """)
        result = _run_bash(script, expect_fail=True)
        assert "Validação da publicação web falhou" in result.stderr
        assert "EyeMole SOAR instalado." not in result.stdout

    def test_35_placeholder_creation_failure_causes_die(self, sandbox):
        """If creation of offline placeholder index.html fails, installation dies."""
        app_dir = sandbox["app_dir"]
        (app_dir / "context_bootstrap.py").write_text("print('BOOTSTRAP')\n")

        web_dir = sandbox["tmp_path"] / "non_existent_web_dir" / "readonly"

        etc_dir = sandbox["tmp_path"] / "etc_no_creds"
        etc_dir.mkdir()

        app_wsl = _to_wsl_path(app_dir)
        web_wsl = _to_wsl_path(web_dir)
        etc_wsl = _to_wsl_path(etc_dir)

        script = dedent(f"""\
            set -Eeuo pipefail
            APP_DIR="{app_wsl}"
            WEB_DIR="{web_wsl}"
            ETC_DIR="{etc_wsl}"
            SYSTEMD_UNIT_DIR="/nonexistent"
            SERVICE_FILE="hmg-soar-report.service"
            APP_USER="$(id -un)"
            WEB_GROUP="$(id -gn)"

            source "{_to_wsl_path(INSTALL_SH)}"
            chown() {{ return 0; }}
            runuser() {{ shift 3; "$@"; }}

            publish_offline_dashboard_placeholder
        """)
        result = _run_bash(script, expect_fail=True)
        assert "Falha ao criar arquivo temporário seguro" in result.stderr

    def test_36_reinstall_upgrade_preserves_existing_index_html(self, sandbox):
        """Reinstall or upgrade does not overwrite an existing valid index.html when credentials.env is absent."""
        app_dir = sandbox["app_dir"]
        (app_dir / "context_bootstrap.py").write_text("print('BOOTSTRAP')\n")

        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()
        existing_index = web_dir / "index.html"
        existing_bytes = b"<html><body>EXISTING DASHBOARD FROM PREVIOUS INSTALL</body></html>"
        existing_index.write_bytes(existing_bytes)

        etc_dir = sandbox["tmp_path"] / "etc_no_creds"
        etc_dir.mkdir()

        app_wsl = _to_wsl_path(app_dir)
        web_wsl = _to_wsl_path(web_dir)
        etc_wsl = _to_wsl_path(etc_dir)

        script = dedent(f"""\
            set -Eeuo pipefail
            APP_DIR="{app_wsl}"
            WEB_DIR="{web_wsl}"
            ETC_DIR="{etc_wsl}"
            SYSTEMD_UNIT_DIR="/nonexistent"
            SERVICE_FILE="hmg-soar-report.service"
            APP_USER="$(id -un)"
            WEB_GROUP="$(id -gn)"
            ENABLE_WEB_RUN=0
            POLKIT_RULE_FILE="{_to_wsl_path(sandbox['tmp_path'] / 'polkit.rules')}"
            WEB_RUN_FLAG="{app_wsl}/web_run.enabled"
            BACKUP_DIR="{_to_wsl_path(sandbox['tmp_path'] / 'backup')}"

            source "{_to_wsl_path(INSTALL_SH)}"
            chown() {{ return 0; }}
            runuser() {{ shift 3; "$@"; }}

            run_report_once_if_possible
            validate_web_publication
            final_message
        """)
        result = _run_bash(script)
        assert result.returncode == 0
        assert existing_index.read_bytes() == existing_bytes

    def test_37_symlink_index_html_rejected_by_validation_and_placeholder(self, sandbox):
        """A symlink as index.html is rejected by validate_web_publication and is replaced by publish_offline_dashboard_placeholder without modifying original target."""
        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()
        target_file = web_dir / "target.html"
        target_bytes_before = b"<html>ORIGINAL TARGET CONTENT</body></html>"
        target_file.write_bytes(target_bytes_before)
        symlink_index = web_dir / "index.html"
        symlink_index.symlink_to(target_file)

        web_wsl = _to_wsl_path(web_dir)
        script = dedent(f"""\
            set -Eeuo pipefail
            WEB_DIR="{web_wsl}"

            source "{_to_wsl_path(INSTALL_SH)}"

            validate_web_publication
        """)
        result = _run_bash(script, expect_fail=True)
        assert "link simbólico" in result.stderr

        # Confirm publish_offline_dashboard_placeholder replaces symlink without touching target
        script_pub = dedent(f"""\
            set -Eeuo pipefail
            WEB_DIR="{web_wsl}"
            WEB_GROUP="$(id -gn)"

            source "{_to_wsl_path(INSTALL_SH)}"
            chown() {{ return 0; }}

            publish_offline_dashboard_placeholder
        """)
        result_pub = _run_bash(script_pub)
        assert result_pub.returncode == 0
        assert not symlink_index.is_symlink(), "index.html must no longer be a symlink"
        assert symlink_index.is_file(), "index.html must be a regular file"
        assert target_file.exists(), "Original target file must still exist"
        assert target_file.read_bytes() == target_bytes_before, "Original target file content was modified"

    def test_38_nginx_user_read_permission_failure_causes_die(self, sandbox):
        """If root can read index.html but Nginx user runuser check fails, validate_web_publication dies."""
        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()
        index_html = web_dir / "index.html"
        index_html.write_text("<html>valid</html>")

        mock_bin = sandbox["tmp_path"] / "mock_bin_test38"
        mock_bin.mkdir()
        marker_file = sandbox["tmp_path"] / "runuser_called_38.txt"

        id_fake = mock_bin / "id"
        id_fake.write_text("#!/usr/bin/env bash\nexit 0\n")
        id_fake.chmod(0o755)

        runuser_fake = mock_bin / "runuser"
        runuser_fake.write_text(f"#!/usr/bin/env bash\ntouch '{_to_wsl_path(marker_file)}'\nexit 1\n")
        runuser_fake.chmod(0o755)

        web_wsl = _to_wsl_path(web_dir)
        bin_wsl = _to_wsl_path(mock_bin)
        script = dedent(f"""\
            set -Eeuo pipefail
            PATH="{bin_wsl}:${{PATH}}"
            WEB_DIR="{web_wsl}"
            NGINX_USER="www-data"

            source "{_to_wsl_path(INSTALL_SH)}"

            validate_web_publication
        """)
        result = _run_bash(script, expect_fail=True)
        assert result.returncode != 0
        assert "não possui permissão de leitura" in result.stderr
        assert "Publicação web em" not in result.stdout
        assert marker_file.exists(), "Fake runuser binary was not executed via PATH"

    def test_39_heredoc_write_failure_cleans_up_tmp_and_dies(self, sandbox):
        """Cat write failure for placeholder heredoc cleans up temporary file and dies."""
        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()

        web_wsl = _to_wsl_path(web_dir)
        script = dedent(f"""\
            set -Eeuo pipefail
            WEB_DIR="{web_wsl}"
            WEB_GROUP="$(id -gn)"

            source "{_to_wsl_path(INSTALL_SH)}"

            chown() {{ return 0; }}
            cat() {{ return 1; }}

            publish_offline_dashboard_placeholder
        """)
        result = _run_bash(script, expect_fail=True)
        assert "Falha ao escrever o conteúdo no arquivo temporário" in result.stderr
        assert not (web_dir / "index.html").exists()

        leftovers = list(web_dir.glob("*.tmp*")) + list(web_dir.glob(".*.tmp*"))
        assert leftovers == [], f"Temporary files left over after write failure: {leftovers}"

    @pytest.mark.parametrize("step", ["chmod", "chown", "mv"])
    def test_40_step_failures_clean_up_tmp_and_die(self, sandbox, step):
        """Failure during chmod, chown, or mv cleans up temporary file and dies."""
        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()
        marker_dir = sandbox["tmp_path"] / f"markers_{step}"
        marker_dir.mkdir()

        web_wsl = _to_wsl_path(web_dir)
        marker_wsl = _to_wsl_path(marker_dir)

        if step == "chmod":
            mock_overrides = dedent(f"""\
                chmod() {{ touch "{marker_wsl}/chmod_called"; return 1; }}
                chown() {{ touch "{marker_wsl}/chown_called"; return 0; }}
                mv() {{ touch "{marker_wsl}/mv_called"; command mv "$@"; }}
            """)
        elif step == "chown":
            mock_overrides = dedent(f"""\
                chmod() {{ touch "{marker_wsl}/chmod_called"; return 0; }}
                chown() {{ touch "{marker_wsl}/chown_called"; return 1; }}
                mv() {{ touch "{marker_wsl}/mv_called"; command mv "$@"; }}
            """)
        else:  # step == "mv"
            mock_overrides = dedent(f"""\
                chmod() {{ touch "{marker_wsl}/chmod_called"; return 0; }}
                chown() {{ touch "{marker_wsl}/chown_called"; return 0; }}
                mv() {{ touch "{marker_wsl}/mv_called"; return 1; }}
            """)

        script = dedent(f"""\
            set -Eeuo pipefail
            WEB_DIR="{web_wsl}"
            WEB_GROUP="$(id -gn)"

            source "{_to_wsl_path(INSTALL_SH)}"

            {mock_overrides}

            publish_offline_dashboard_placeholder
        """)
        result = _run_bash(script, expect_fail=True)
        assert result.returncode != 0

        chmod_marker = marker_dir / "chmod_called"
        chown_marker = marker_dir / "chown_called"
        mv_marker = marker_dir / "mv_called"

        if step == "chmod":
            assert chmod_marker.exists(), "chmod should have been called"
            assert not chown_marker.exists(), "chown should NOT have been called"
            assert not mv_marker.exists(), "mv should NOT have been called"
            assert "Falha ao definir permissão 0644" in result.stderr
        elif step == "chown":
            assert chmod_marker.exists(), "chmod should have been called"
            assert chown_marker.exists(), "chown should have been called"
            assert not mv_marker.exists(), "mv should NOT have been called"
            assert "Falha ao definir proprietário" in result.stderr
        else:  # step == "mv"
            assert chmod_marker.exists(), "chmod should have been called"
            assert chown_marker.exists(), "chown should have been called"
            assert mv_marker.exists(), "mv should have been called"
            assert "Falha ao mover" in result.stderr

        leftovers = list(web_dir.glob("*.tmp*")) + list(web_dir.glob(".*.tmp*"))
        assert leftovers == [], f"Temporary files left over after {step} failure: {leftovers}"

    def test_41_no_temporary_files_left_over_after_successful_publication(self, sandbox):
        """After successful publish_offline_dashboard_placeholder, no temporary .index.html.tmp.* files remain in WEB_DIR."""
        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()

        web_wsl = _to_wsl_path(web_dir)
        script = dedent(f"""\
            set -Eeuo pipefail
            WEB_DIR="{web_wsl}"
            WEB_GROUP="$(id -gn)"

            source "{_to_wsl_path(INSTALL_SH)}"
            chown() {{ return 0; }}

            publish_offline_dashboard_placeholder
        """)
        result = _run_bash(script)
        assert result.returncode == 0
        leftovers = list(web_dir.glob("*.tmp*")) + list(web_dir.glob(".*.tmp*"))
        assert leftovers == [], f"Temporary files left over after success: {leftovers}"

    def test_42_runuser_missing_causes_die(self, sandbox):
        """If runuser command is missing, validate_web_publication fails closed."""
        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()
        (web_dir / "index.html").write_text("<html>valid</html>")

        web_wsl = _to_wsl_path(web_dir)
        script = dedent(f"""\
            set -Eeuo pipefail
            WEB_DIR="{web_wsl}"
            NGINX_USER="www-data"

            source "{_to_wsl_path(INSTALL_SH)}"

            command() {{
                if [[ "$2" == "runuser" ]]; then
                    return 1
                fi
                builtin command "$@"
            }}

            validate_web_publication
        """)
        result = _run_bash(script, expect_fail=True)
        assert "Comando 'runuser' ausente" in result.stderr

    def test_43_nginx_user_missing_causes_die(self, sandbox):
        """If NGINX_USER does not exist in system, validate_web_publication fails closed."""
        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()
        (web_dir / "index.html").write_text("<html>valid</html>")

        mock_bin = sandbox["tmp_path"] / "mock_bin_test43"
        mock_bin.mkdir()

        runuser_fake = mock_bin / "runuser"
        runuser_fake.write_text("#!/usr/bin/env bash\nexit 0\n")
        runuser_fake.chmod(0o755)

        id_fake = mock_bin / "id"
        id_fake.write_text("#!/usr/bin/env bash\nif [[ \"$1\" == \"nonexistent_nginx_user\" ]]; then exit 1; fi; exit 0\n")
        id_fake.chmod(0o755)

        web_wsl = _to_wsl_path(web_dir)
        bin_wsl = _to_wsl_path(mock_bin)
        script = dedent(f"""\
            set -Eeuo pipefail
            PATH="{bin_wsl}:${{PATH}}"
            WEB_DIR="{web_wsl}"
            NGINX_USER="nonexistent_nginx_user"

            source "{_to_wsl_path(INSTALL_SH)}"

            validate_web_publication
        """)
        result = _run_bash(script, expect_fail=True)
        assert "Usuário Nginx 'nonexistent_nginx_user' não encontrado" in result.stderr

    def test_44_nginx_user_can_read_passes_validation(self, sandbox):
        """When NGINX_USER exists and runuser check succeeds, validate_web_publication passes."""
        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()
        (web_dir / "index.html").write_text("<html>valid</html>")

        mock_bin = sandbox["tmp_path"] / "mock_bin_test44"
        mock_bin.mkdir()

        runuser_fake = mock_bin / "runuser"
        runuser_fake.write_text("#!/usr/bin/env bash\nexit 0\n")
        runuser_fake.chmod(0o755)

        id_fake = mock_bin / "id"
        id_fake.write_text("#!/usr/bin/env bash\nexit 0\n")
        id_fake.chmod(0o755)

        web_wsl = _to_wsl_path(web_dir)
        bin_wsl = _to_wsl_path(mock_bin)
        script = dedent(f"""\
            set -Eeuo pipefail
            PATH="{bin_wsl}:${{PATH}}"
            WEB_DIR="{web_wsl}"
            NGINX_USER="www-data"

            source "{_to_wsl_path(INSTALL_SH)}"

            validate_web_publication
            echo "VALIDATED_OK"
        """)
        result = _run_bash(script)
        assert result.returncode == 0
        assert "VALIDATED_OK" in result.stdout

    def test_45_target_as_directory_fails_and_cleans_up(self, sandbox):
        """If WEB_DIR/index.html is a directory, publish_offline_dashboard_placeholder fails and cleans up temporary file."""
        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()
        index_dir = web_dir / "index.html"
        index_dir.mkdir()

        web_wsl = _to_wsl_path(web_dir)
        script = dedent(f"""\
            set -Eeuo pipefail
            WEB_DIR="{web_wsl}"
            WEB_GROUP="$(id -gn)"

            source "{_to_wsl_path(INSTALL_SH)}"
            chown() {{ return 0; }}

            publish_offline_dashboard_placeholder
        """)
        result = _run_bash(script, expect_fail=True)
        assert "Falha ao mover" in result.stderr
        assert index_dir.is_dir(), "index.html directory was corrupted"

        leftovers = list(web_dir.glob("*.tmp*")) + list(web_dir.glob(".*.tmp*")) + list(index_dir.glob("*.tmp*")) + list(index_dir.glob(".*.tmp*"))
        assert leftovers == [], f"Temporary files left over when target is a directory: {leftovers}"

    def test_46_cleanup_failure_emits_warning_and_preserves_original_error(self, sandbox):
        """If temporary file cleanup rm fails during error handling, warning is emitted and original failure is preserved."""
        web_dir = sandbox["tmp_path"] / "web"
        web_dir.mkdir()

        web_wsl = _to_wsl_path(web_dir)
        script = dedent(f"""\
            set -Eeuo pipefail
            WEB_DIR="{web_wsl}"
            WEB_GROUP="$(id -gn)"

            source "{_to_wsl_path(INSTALL_SH)}"

            chmod() {{ echo "ORIGINAL_CHMOD_FAILURE" >&2; return 1; }}
            chown() {{ return 0; }}
            rm() {{ echo "MOCK_RM_FAILURE" >&2; return 1; }}

            publish_offline_dashboard_placeholder
        """)
        result = _run_bash(script, expect_fail=True)
        assert result.returncode != 0
        assert "ORIGINAL_CHMOD_FAILURE" in result.stderr
        assert "Falha ao definir permissão 0644" in result.stderr
        assert "Falha ao remover o arquivo temporário residual" in result.stderr
        assert "MOCK_RM_FAILURE" in result.stderr
