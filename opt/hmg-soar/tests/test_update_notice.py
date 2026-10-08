"""Read-only local API and dashboard update notice contracts."""
import datetime as dt
import json
from pathlib import Path
import subprocess
import shutil
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import soar_api
import analyserV1

A, B = "a" * 40, "b" * 40


@pytest.mark.parametrize("state,age,available", [
    ("available", 0, True), ("up_to_date", 0, False),
    ("check_failed", 0, False), ("available", 49 * 3600, False),
    ("available", -3600, False), ("install_failed", 0, False),
])
def test_notice_only_uses_fresh_local_result(tmp_path, monkeypatch, state, age, available):
    path = tmp_path / "status.json"
    monkeypatch.setattr(soar_api, "UPDATE_STATUS_JSON", path)
    stamp = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=age)
    path.write_text(json.dumps({"state": state, "checked_at": stamp.isoformat(),
                                "installed_commit": A, "latest_commit": B}))
    assert soar_api._read_update_status()["update_available"] is available


@pytest.mark.parametrize("content", ["not-json", "[]", '{"state": []}', "x" * 5000,
    '{"state": "available", "checked_at": "invalid"}'])
def test_invalid_local_result_degrades_without_server_error(tmp_path, monkeypatch, content):
    path = tmp_path / "status.json"
    monkeypatch.setattr(soar_api, "UPDATE_STATUS_JSON", path)
    path.write_text(content)
    assert soar_api._read_update_status()["update_available"] is False


def test_missing_status_file_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(soar_api, "UPDATE_STATUS_JSON", tmp_path / "missing.json")
    assert soar_api._read_update_status()["state"] == "unknown"


def test_api_endpoint_does_not_execute_commands(monkeypatch):
    handler = soar_api.SoarAPIHandler.__new__(soar_api.SoarAPIHandler)
    handler.path = "/update-status"
    captured = []
    monkeypatch.setattr(handler, "_send_json", lambda code, data: captured.append((code, data)))
    monkeypatch.setattr(soar_api.subprocess, "run", lambda *a, **k: pytest.fail("no subprocess permitted"))
    handler.do_GET()
    assert captured[0][0] == 200
    assert "update_available" in captured[0][1]


def test_dashboard_notice_shows_command_and_hides_when_current():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    template = analyserV1.HTML_TEMPLATE
    start = template.index("async function refreshEyeMoleUpdateNotice()")
    end = template.index("document.addEventListener('DOMContentLoaded'", start)
    js = template[start:end]
    script = """
const elements = {
  'eyemole-installed-version': {}, 'eyemole-update-notice': {hidden: true},
  'eyemole-latest-version': {}
};
global.document = { getElementById: id => elements[id] };
let state = {state:'available', update_available:true, installed_commit:'a'.repeat(40), latest_commit:'b'.repeat(40)};
global.fetch = async () => ({ok: true, json: async () => state});
""" + js + """
(async () => {
  await refreshEyeMoleUpdateNotice();
  if (elements['eyemole-update-notice'].hidden) throw Error('missing notice');
  if (elements['eyemole-latest-version'].textContent !== 'bbbbbbb') throw Error('bad revision');
  state.state = 'up_to_date'; state.update_available = false;
  await refreshEyeMoleUpdateNotice();
  if (!elements['eyemole-update-notice'].hidden) throw Error('stale notice');
})().catch(e => {console.error(e); process.exit(1);});
"""
    subprocess.run([node, "-e", script], check=True, timeout=15)
    assert "sudo eyemole update" in template
