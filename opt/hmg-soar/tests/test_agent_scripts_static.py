from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
AGENT_SCRIPTS = REPO_ROOT / "agent-scripts"


def _script(path: str) -> str:
    return (AGENT_SCRIPTS / path).read_text(encoding="utf-8")


def _all_script_texts():
    for path in AGENT_SCRIPTS.rglob("*"):
        if path.is_file():
            yield path, path.read_text(encoding="utf-8")


def test_agent_scripts_do_not_hardcode_test_environment_hostname():
    forbidden = ("tre-pr.jus.br", "wazuh-manager-hmg")

    for path, text in _all_script_texts():
        for value in forbidden:
            assert value not in text, f"{value!r} is hardcoded in {path}"


def test_agent_scripts_do_not_ship_literal_tokens():
    suspicious_values = (
        "Bearer eyJ",
        "Bearer sk-",
        "TOKEN_DO_AGENT",
        "<TOKEN",
        "token-generated-for-agent",
    )

    for path, text in _all_script_texts():
        for value in suspicious_values:
            assert value not in text, f"suspicious token placeholder {value!r} in {path}"


def test_linux_generator_uses_expected_upload_contract_and_resilience_flags():
    text = _script("linux/generate_and_upload_sbom.sh")

    assert "/soar-api/sbom/" in text
    assert "cyclonedx-json" in text
    assert "/etc/eyemole-agent/token" in text
    assert "CA_CERT_PATH" in text
    assert "--cacert" in text
    assert "--connect-timeout" in text
    assert "--max-time" in text
    assert "--retry" in text
    assert "SBOM_FILE=\"\"" in text
    assert "trap cleanup EXIT" in text


def test_linux_installer_uses_systemd_timer_and_reduced_default_scopes():
    installer = _script("linux/install-agent-script.sh")
    timer = _script("linux/eyemole-sbom.timer")

    assert "systemctl enable --now eyemole-sbom.timer" in installer
    assert "dir:/var/lib/dpkg" in installer
    assert "dir:/var/lib/rpm" in installer
    assert "cron" not in installer.lower()
    assert "OnCalendar=*-*-* 02:15:00" in timer
    assert "Persistent=true" in timer


def test_windows_generator_uses_curl_exe_and_optional_ca_cert():
    text = _script("windows/Generate-And-Upload-Sbom.ps1")

    assert "/soar-api/sbom/" in text
    assert "cyclonedx-json" in text
    assert "curl.exe" in text
    assert "Invoke-RestMethod" not in text
    assert "TokenPath" in text
    assert "CaCertPath" in text
    assert "--cacert" in text
    assert "--connect-timeout" in text
    assert "--max-time" in text
    assert "--retry" in text


def test_windows_installer_uses_scheduled_task_and_reduced_default_scopes():
    text = _script("windows/Install-EyeMoleSbomTask.ps1")

    assert "Register-ScheduledTask" in text
    assert "token.txt" in text
    assert "C:\\Program Files" in text
    assert "C:\\Program Files (x86)" in text
    assert "curl.exe --version" in text
    assert "winget" not in text.lower()
