"""Real compressed snapshots and signed execution, entirely in isolated fixtures."""
import base64
import importlib.util
import json
import os
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from operations.worker import signed_argument

ROOT = Path(__file__).resolve().parents[3]


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


admin = module(ROOT / "cli/administration.py", "recovery")
receiver = module(ROOT / "agents/eyemole-remediate.py", "receiver")


@pytest.mark.skipif(os.name != "posix", reason="GNU tar and POSIX ownership")
def test_real_snapshot_recovers_code_credentials_database_and_new_absent_file(tmp_path):
    root = tmp_path / "root"
    app = root / "opt/hmg-soar"
    cred = root / "etc/hmg-soar"
    app.mkdir(parents=True)
    cred.mkdir(parents=True)
    (app / "code.py").write_text("old code")
    (cred / "credentials.env").write_text("test-value-only")
    absent = root / "etc/worker.service"
    snapshot = admin.Snapshot(tmp_path / "backup", [app, cred, absent], root).create()
    (app / "code.py").write_text("new broken code")
    (app / "new.py").write_text("new file")
    absent.write_text("new worker")
    (cred / "credentials.env").write_text("changed")
    snapshot.restore()
    assert (app / "code.py").read_text() == "old code"
    assert (cred / "credentials.env").read_text() == "test-value-only"
    assert not (app / "new.py").exists() and not absent.exists()
    assert snapshot.verify()["status"] == "restored"
    assert snapshot.archive.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != "posix", reason="GNU tar")
def test_tampered_archive_is_rejected_before_restoration(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "app"
    target.mkdir()
    (target / "x").write_text("old")
    snapshot = admin.Snapshot(tmp_path / "backup", [target], root).create()
    (target / "x").write_text("new")
    with snapshot.archive.open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(admin.RecoveryError):
        snapshot.restore()
    assert (target / "x").read_text() == "new"


@pytest.mark.skipif(os.name != "posix", reason="GNU tar")
def test_external_symlink_is_rejected_before_deployment(tmp_path):
    root = tmp_path / "root"
    target = root / "app"
    target.mkdir(parents=True)
    (target / "secret-link").symlink_to("/etc/shadow")
    with pytest.raises(admin.RecoveryError):
        admin.Snapshot(tmp_path / "backup", [target], root).create()


def test_no_space_fails_preflight_before_backup(tmp_path, monkeypatch):
    target = tmp_path / "app"
    target.write_bytes(b"x" * 8192)
    monkeypatch.setattr(admin.shutil, "disk_usage", lambda p: SimpleNamespace(free=0))
    with pytest.raises(admin.RecoveryError, match="Espaço insuficiente"):
        admin.preflight({"backup_root": str(tmp_path / "backup"), "minimum_free_bytes": 4096}, [target])
    assert not (tmp_path / "backup").exists()


@pytest.fixture
def packet():
    payload = {"id": "a" * 32, "agent_id": "001", "package": "openssl", "package_manager": "apt", "installed_version": "1.0",
               "fixed_version": "2.0", "issued_at": 1000, "expires_at": 1200}
    policy = {"enabled": True, "agent_id": "001", "hmac_key": "test-key-" * 8, "packages": ["openssl"], "package_managers": ["apt"]}
    return payload, policy


def test_signed_plan_is_checked_by_agent_and_uses_argv_without_shell(packet):
    payload, policy = packet
    decoded = receiver.decode(signed_argument(payload, policy["hmac_key"]), policy, current=1100)
    argv = receiver.action(decoded, query=lambda *a, **k: "1.0")
    assert argv == ["/usr/bin/apt-get", "-y", "--only-upgrade", "install", "--", "openssl=2.0"]


@pytest.mark.parametrize("change", [{"package": "--evil"}, {"package": "openssl;touch"}, {"agent_id": "002"}, {"expires_at": 900},
                                    {"package_manager": "powershell"}, {"fixed_version": "$(evil)"}])
def test_receiver_rejects_unsafe_or_inapplicable_signed_parameters(packet, change):
    payload, policy = packet
    payload.update(change)
    with pytest.raises(ValueError):
        receiver.decode(signed_argument(payload, policy["hmac_key"]), policy, current=1100)


def test_receiver_rejects_signature_tampering_and_changed_installation(packet):
    payload, policy = packet
    encoded = signed_argument(payload, policy["hmac_key"])
    decoded = json.loads(base64.urlsafe_b64decode(encoded))
    decoded["payload"]["package"] = "different"
    tampered = base64.urlsafe_b64encode(json.dumps(decoded).encode()).decode()
    with pytest.raises(ValueError, match="signature"):
        receiver.decode(tampered, policy, current=1100)
    with pytest.raises(ValueError, match="installed_version_changed"):
        receiver.action(payload, query=lambda *a, **k: "1.1")


@pytest.mark.skipif(os.name != 'posix', reason='GNU tar and xattrs')
def test_restore_preserves_extended_attributes_and_rejects_full_disk_before_changes(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    target = root / 'app'
    target.mkdir(parents=True)
    file = target / 'code.py'
    file.write_text('old')
    os.setxattr(file, 'user.eyemole-test', b'original attribute')
    snapshot = admin.Snapshot(tmp_path / 'backup', [target], root).create()
    file.write_text('new')
    os.setxattr(file, 'user.eyemole-test', b'changed attribute')
    original = admin.shutil.disk_usage
    monkeypatch.setattr(admin.shutil, 'disk_usage', lambda p: SimpleNamespace(free=0))
    with pytest.raises(admin.RecoveryError, match='Espaço insuficiente'):
        snapshot.restore()
    assert file.read_text() == 'new'
    monkeypatch.setattr(admin.shutil, 'disk_usage', original)
    snapshot.restore()
    assert file.read_text() == 'old'
    assert os.getxattr(file, 'user.eyemole-test') == b'original attribute'
