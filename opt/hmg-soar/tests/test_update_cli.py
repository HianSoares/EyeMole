"""Public version checks and administrator-only updates, without real deployments."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("eyemole_cli", ROOT / "cli/eyemole.py")
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)
A, B = "a" * 40, "b" * 40


def published(resource):
    if resource == "/git/ref/heads/main":
        return {"object": {"sha": B}}
    assert resource == f"/compare/{A}...{B}"
    return {"status": "ahead", "ahead_by": 1}


def test_available_requires_descendant_in_main():
    result = cli.check_update({"installed_commit": A}, published)
    assert result["state"] == "available"
    assert result["update_available"] is True


@pytest.mark.parametrize("comparison", ["behind", "diverged", "identical"])
def test_never_offer_downgrade_or_unrelated_history(comparison):
    result = cli.check_update({"installed_commit": A}, lambda p: (
        {"object": {"sha": B}} if p.startswith("/git/") else {"status": comparison, "ahead_by": 0}))
    assert not result["update_available"]
    assert result["state"] == "different_history"


def test_current_revision_skips_comparison():
    calls = []
    result = cli.check_update({"installed_commit": A}, lambda p: (
        calls.append(p) or {"object": {"sha": A}}))
    assert result["state"] == "up_to_date"
    assert calls == ["/git/ref/heads/main"]


@pytest.mark.parametrize("state", [{}, {"installed_commit": "--evil"},
    {"installed_commit": A, "local_changes": True},
    {"installed_commit": A, "custom_layout": True},
    {"installed_commit": A, "last_update_failed": True}])
def test_unmanaged_and_uncertain_installations_do_not_contact_github(state):
    def no_network(_):
        pytest.fail("unexpected network")
    assert not cli.check_update(state, no_network)["update_available"]


def test_offline_is_unknown_not_current_or_cached_available():
    def offline(_):
        raise OSError("secret proxy credential must not be exposed")
    result = cli.check_update({"installed_commit": A}, offline)
    assert result["state"] == "check_failed"
    assert not result["update_available"]
    assert "secret" not in json.dumps(result)


def test_invalid_remote_revision_is_rejected():
    result = cli.check_update({"installed_commit": A}, lambda _: {"object": {"sha": "x;evil"}})
    assert result["state"] == "check_failed"


def test_credential_reader_never_executes_shell(tmp_path):
    marker = tmp_path / "executed"
    cred = tmp_path / "credentials.env"
    cred.write_text(f'OPENSEARCH_PASS="$(touch {marker})"\nWAZUH_API_PASS=abc\n')
    assert "$(touch" in cli.credentials(cred)["OPENSEARCH_PASS"]
    assert not marker.exists()


def test_tls_checks_both_hosts_as_service_user_without_passwords(tmp_path, monkeypatch):
    cred = tmp_path / "credentials.env"
    cred.write_text('OPENSEARCH_PASS=secret1\nWAZUH_API_PASS=secret2\n'
                    'OPENSEARCH_HOST=indexer.example\nWAZUH_API_HOST=manager.example\n'
                    'HMG_INTERNAL_CA_BUNDLE=/etc/example/ca.pem\n')
    calls = []
    monkeypatch.setattr(cli, "run", lambda argv, **kw: calls.append(argv))
    cli.tls_preflight(cred)
    assert len(calls) == 2
    assert all(c[:5] == ["runuser", "-u", "hmg-soar", "--", "/usr/bin/python3"] for c in calls)
    assert all(c[-1] == "/etc/example/ca.pem" for c in calls)
    assert "secret1" not in str(calls) and "secret2" not in str(calls)


def test_bad_tls_aborts_before_install(tmp_path, monkeypatch):
    state, status = tmp_path / "state", tmp_path / "status"
    cli.atomic_json(state, {"installed_commit": A})
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(cli, "update_lock", contextlib.nullcontext)
    monkeypatch.setattr(cli, "check_update", lambda s: cli.check_update_original(s, published))
    monkeypatch.setattr(cli, "tls_preflight", lambda: (_ for _ in ()).throw(cli.UpdateError("TLS failed")))
    monkeypatch.setattr(cli, "checkout", lambda *a: pytest.fail("must not download or install"))
    with pytest.raises(cli.UpdateError, match="TLS failed"):
        cli.update(state, status)
    assert cli.read_json(state) == {"installed_commit": A}


cli.check_update_original = cli.check_update


def test_update_requires_root_before_any_network(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(cli, "check_update", lambda s: pytest.fail("must not contact GitHub"))
    with pytest.raises(cli.UpdateError, match="sudo eyemole update"):
        cli.update()


@pytest.mark.skipif(os.name != "posix", reason="Linux advisory lock")
def test_update_lock_rejects_concurrent_runs_and_releases(tmp_path):
    path = tmp_path / "lock"
    with cli.update_lock(path):
        with pytest.raises(cli.UpdateError, match="Já existe"):
            with cli.update_lock(path):
                pass
    with cli.update_lock(path):
        pass


@pytest.mark.parametrize("fail", [False, True])
@pytest.mark.parametrize("web_run", [False, True])
def test_update_pins_revision_preserves_mode_and_records_only_success(tmp_path, monkeypatch, fail, web_run):
    state, status = tmp_path / "state", tmp_path / "status"
    cli.atomic_json(state, {"installed_commit": A})
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(cli, "update_lock", contextlib.nullcontext)
    monkeypatch.setattr(cli, "pause_collection_timers", contextlib.nullcontext)
    monkeypatch.setattr(cli, "tls_preflight", lambda: None)
    monkeypatch.setattr(cli, "check_update", lambda s: cli.check_update_original(s, published))
    monkeypatch.setattr(cli, "UPDATE_ROOT", tmp_path / "updates")
    monkeypatch.setattr(cli, "BACKUP_ROOT", tmp_path / "backups")
    monkeypatch.setattr(cli, "MAINTENANCE_FLAG", tmp_path / "maintenance")
    monkeypatch.setattr(cli, "RECOVERY_REQUIRED", tmp_path / "recovery-required")
    class FakeSnapshot:
        def __init__(self, path):
            pass
        def create(self):
            pass
        def check_restore_space(self):
            pass
        def mark(self, status):
            pass
        def remember_services(self, states):
            pass
        def restore(self):
            cli.atomic_json(state, {"installed_commit": A})
    admin = SimpleNamespace(preflight=lambda: None, RecoveryError=RuntimeError,
                            policy=lambda: {"backup_root": str(tmp_path / "backups")},
                            secure_directory=lambda p: p.mkdir(parents=True), Snapshot=FakeSnapshot,
                            pause_application=lambda run: contextlib.nullcontext(), cleanup=lambda *a, **k: None,
                            service_states=lambda run: {})
    monkeypatch.setattr(cli, "administration", lambda: admin)
    flag = tmp_path / "web_run.enabled"
    monkeypatch.setattr(cli, "WEB_RUN_FLAG", flag)
    if web_run:
        flag.touch()
    downloaded = []
    def download(target, repo):
        downloaded.append(target)
        repo.mkdir()
        (repo / "install.sh").write_text("#!/bin/bash\n")
    monkeypatch.setattr(cli, "checkout", download)
    monkeypatch.setattr(cli, "validate_checkout", lambda r: None)
    calls = []
    def install(args, **kw):
        if args[0] != "bash":
            return SimpleNamespace(stdout="inactive\n")
        calls.append((args, kw))
        if fail:
            raise cli.UpdateError("installer failed")
        cli.atomic_json(state, {"installed_commit": B})
    monkeypatch.setattr(cli, "run", install)
    if fail:
        with pytest.raises(cli.UpdateError, match="instalação anterior restaurada"):
            cli.update(state, status)
        assert cli.read_json(state)["installed_commit"] == A
        assert not cli.read_json(state).get("last_update_failed")
    else:
        assert cli.update(state, status) == 0
        assert cli.read_json(state)["installed_commit"] == B
        assert cli.read_json(status)["state"] == "up_to_date"
    assert downloaded == [B]
    assert ("--enable-web-run" in calls[0][0]) is web_run
    env = calls[0][1]["env"]
    assert env["EYEMOLE_DEFER_COLLECTION_TIMERS"] == "1"
    assert "OPENSEARCH_PASS" not in env


def test_timers_resume_even_when_collection_is_busy(monkeypatch):
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if args[1] == "show":
            return SimpleNamespace(stdout="active\n")
        return SimpleNamespace(stdout="")
    monkeypatch.setattr(cli, "run", run)
    with pytest.raises(cli.UpdateError, match="Coleta em execução"):
        with cli.pause_collection_timers():
            pytest.fail("must not deploy during collection")
    starts = [a[2] for a in calls if a[1] == "start"]
    assert starts == ["hmg-soar-report.timer", "hmg-soar-grype.timer", "eyemole-update-check.timer"]


def test_record_install_tracks_exact_git_revision_and_dirty_tree(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    git("init")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "Test")
    (repo / "app").write_text("initial")
    git("add", "app")
    git("commit", "-m", "initial")
    expected = git("rev-parse", "HEAD").stdout.strip()
    state, status = tmp_path / "state", tmp_path / "status"
    cli.record_install(repo, state, status)
    assert cli.read_json(state)["installed_commit"] == expected
    assert cli.read_json(state)["local_changes"] is False
    (repo / "app").write_text("modified")
    cli.record_install(repo, state, status)
    assert cli.read_json(state)["local_changes"] is True


def test_bad_download_syntax_is_rejected_without_execution(tmp_path):
    (tmp_path / "opt/hmg-soar").mkdir(parents=True)
    (tmp_path / "cli").mkdir()
    (tmp_path / "install.sh").write_text("#!/bin/bash\n")
    (tmp_path / "cli/eyemole.py").touch()
    (tmp_path / "opt/hmg-soar/app.py").write_text("this is invalid syntax !!!")
    with pytest.raises(SyntaxError):
        cli.validate_checkout(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="Linux installer backup paths")
def test_installer_keeps_credentials_out_of_application_backup(tmp_path):
    app, etc = tmp_path / "opt/hmg-soar", tmp_path / "etc/hmg-soar"
    app.mkdir(parents=True)
    etc.mkdir(parents=True)
    (app / "app.py").write_text("code")
    (etc / "credentials.env").write_text("OPENSEARCH_PASS=fake-test-value")
    backup = tmp_path / "backup"
    env = dict(os.environ, ETC_DIR=str(etc), EYEMOLE_BACKUP_DIR=str(backup), APP_DIR=str(app))
    subprocess.run(["bash", "-c", 'source "$1"; backup_path "$APP_DIR"; backup_credentials',
                    "bash", str(ROOT / "install.sh")], env=env, check=True, capture_output=True)
    assert (backup / "hmg-soar/app.py").read_text() == "code"
    assert (backup / "credentials/credentials.env").is_file()
    assert not list((backup / "hmg-soar").rglob("credentials.env"))
