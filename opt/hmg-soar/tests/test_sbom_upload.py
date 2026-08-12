from __future__ import annotations

import hashlib
import io
import json
import shutil
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import soar_api
from remediation.rate_limiter import SlidingWindowLog


@pytest.fixture
def workdir():
    root = Path(__file__).resolve().parent.parent / ".test-tmp-sbom-upload" / uuid.uuid4().hex
    root.mkdir(parents=True, exist_ok=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)
        try:
            root.parent.rmdir()
        except OSError:
            pass


class _Headers:
    def __init__(self, values: dict[str, str]):
        self._values = values

    def get(self, key: str, default=None):
        return self._values.get(key, default)


class MockHandler:
    def __init__(self, headers: dict[str, str], body: bytes):
        self._headers = _Headers(headers)
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.client_address = ("127.0.0.1", 12345)
        self.response_code = None
        self.response_headers = {}

    @property
    def headers(self):
        return self._headers

    def send_response(self, code):
        self.response_code = code

    def send_header(self, key, value):
        self.response_headers[key] = value

    def end_headers(self):
        pass

    def _get_client_ip(self):
        return "127.0.0.1"

    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def get_response_json(self):
        return json.loads(self.wfile.getvalue().decode("utf-8"))


def _write_assets(path: Path, agent_id: str = "003", token: str = "secret-token",
                  enabled: bool = True) -> None:
    data = {
        "metadata": {"version": "1.0"},
        "defaults": {},
        "agents": {
            agent_id: {
                "id": agent_id,
                "asset_name": "agent-003",
                "hostname": "agent-003",
                "criticality": "unknown",
                "technical_owner": "unknown",
                "business_owner": "unknown",
                "environment": "hmg",
                "classification_status": "pending",
                "sbom_token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
                "sbom_upload_enabled": enabled,
                "token_rotated_at": "2026-08-11T00:00:00+00:00",
            }
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _sbom() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"name": "lodash", "version": "4.17.15"}],
    }


def _call_upload(workdir: Path, agent_id: str = "003", token: str = "secret-token",
                 payload=None, headers: dict[str, str] | None = None):
    body = json.dumps(_sbom() if payload is None else payload).encode("utf-8")
    request_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }
    if headers:
        request_headers.update(headers)

    handler = MockHandler(request_headers, body)
    with patch.object(soar_api, "ASSETS_CONTEXT_JSON", workdir / "config" / "assets_context.json"), \
         patch.object(soar_api, "ASSETS_CONTEXT_LOCK", workdir / "config" / ".assets_context.lock"), \
         patch.object(soar_api, "SBOM_PENDING_DIR", workdir / "sbom" / "pending"), \
         patch.object(soar_api, "CONTEXT_AUDIT_DIR", workdir / "audit"), \
         patch.object(soar_api, "CONTEXT_AUDIT_LOG", workdir / "audit" / "audit_actions.jsonl"), \
         patch.object(soar_api, "_sbom_rate_limiter", SlidingWindowLog(max_tokens=30)):
        _write_assets(soar_api.ASSETS_CONTEXT_JSON)
        soar_api.SoarAPIHandler._handle_upload_sbom(handler, agent_id)
    return handler, workdir / "sbom" / "pending" / f"{agent_id}.json"


def test_valid_token_accepts_and_writes_sbom(workdir):
    handler, target = _call_upload(workdir)

    assert handler.response_code == 202
    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"


def test_invalid_token_rejected_with_401(workdir):
    handler, target = _call_upload(workdir, token="wrong-token")

    assert handler.response_code == 401
    assert not target.exists()


def test_unknown_agent_id_rejected(workdir):
    handler, target = _call_upload(workdir, agent_id="999")

    assert handler.response_code == 401
    assert not target.exists()


def test_non_json_payload_rejected(workdir):
    body = b"not-json"
    handler = MockHandler({
        "Authorization": "Bearer secret-token",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }, body)

    with patch.object(soar_api, "ASSETS_CONTEXT_JSON", workdir / "config" / "assets_context.json"), \
         patch.object(soar_api, "ASSETS_CONTEXT_LOCK", workdir / "config" / ".assets_context.lock"), \
         patch.object(soar_api, "SBOM_PENDING_DIR", workdir / "sbom" / "pending"), \
         patch.object(soar_api, "CONTEXT_AUDIT_DIR", workdir / "audit"), \
         patch.object(soar_api, "CONTEXT_AUDIT_LOG", workdir / "audit" / "audit_actions.jsonl"), \
         patch.object(soar_api, "_sbom_rate_limiter", SlidingWindowLog(max_tokens=30)):
        _write_assets(soar_api.ASSETS_CONTEXT_JSON)
        soar_api.SoarAPIHandler._handle_upload_sbom(handler, "003")

    assert handler.response_code == 400


def test_json_that_is_not_cyclonedx_sbom_rejected(workdir):
    handler, target = _call_upload(workdir, payload={"hello": "world"})

    assert handler.response_code == 422
    assert not target.exists()


def test_rate_limit_rejects_before_write(workdir):
    limiter = SlidingWindowLog(max_tokens=1, window_seconds=60)
    limiter.is_allowed("sbom:003:127.0.0.1")
    body = json.dumps(_sbom()).encode("utf-8")
    handler = MockHandler({
        "Authorization": "Bearer secret-token",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }, body)

    with patch.object(soar_api, "ASSETS_CONTEXT_JSON", workdir / "config" / "assets_context.json"), \
         patch.object(soar_api, "ASSETS_CONTEXT_LOCK", workdir / "config" / ".assets_context.lock"), \
         patch.object(soar_api, "SBOM_PENDING_DIR", workdir / "sbom" / "pending"), \
         patch.object(soar_api, "_sbom_rate_limiter", limiter):
        _write_assets(soar_api.ASSETS_CONTEXT_JSON)
        soar_api.SoarAPIHandler._handle_upload_sbom(handler, "003")

    assert handler.response_code == 429
    assert not (workdir / "sbom" / "pending" / "003.json").exists()


def test_atomic_write_does_not_corrupt_existing_file_on_replace_failure(workdir):
    target = workdir / "003.json"
    target.write_text('{"bomFormat": "CycloneDX", "components": []}', encoding="utf-8")

    with patch.object(soar_api.os, "replace", side_effect=OSError("boom")):
        with pytest.raises(OSError):
            soar_api._atomic_write_json_file(target, {"bomFormat": "CycloneDX", "components": [{"name": "x"}]})

    assert json.loads(target.read_text(encoding="utf-8")) == {
        "bomFormat": "CycloneDX",
        "components": [],
    }


def test_token_generation_uses_existing_agent_id_re_and_file_lock(workdir):
    assets_path = workdir / "config" / "assets_context.json"
    _write_assets(assets_path)

    with patch.object(soar_api, "ASSETS_CONTEXT_JSON", assets_path), \
         patch.object(soar_api, "ASSETS_CONTEXT_LOCK", workdir / "config" / ".assets_context.lock"):
        soar_api.set_agent_sbom_token("003", "new-secret-token")

    data = json.loads(assets_path.read_text(encoding="utf-8"))
    agent = data["agents"]["003"]
    assert agent["sbom_upload_enabled"] is True
    assert agent["token_rotated_at"]
    assert agent["sbom_token_sha256"] == hashlib.sha256(b"new-secret-token").hexdigest()
    assert (workdir / "config" / ".assets_context.lock").exists()


def test_token_compare_uses_hmac_compare_digest():
    agent = {
        "sbom_upload_enabled": True,
        "sbom_token_sha256": hashlib.sha256(b"secret-token").hexdigest(),
    }

    with patch.object(soar_api.hmac, "compare_digest", return_value=True) as mocked:
        assert soar_api._agent_token_is_valid(agent, "secret-token") is True

    mocked.assert_called_once()
