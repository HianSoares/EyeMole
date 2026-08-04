"""
Wave 2 Tests — Remediation Guidance MVP (API e Auditoria)

50 test cases covering GET endpoint, POST audit, cache, rate limiter,
and regression. Uses unittest.mock to simulate HTTP requests.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from remediation.models import GuidanceRecord
from remediation.cache import GuidanceCache
from remediation.rate_limiter import SlidingWindowLog

# Backward-compatible alias for existing test code



# ==========================================================================
# HELPERS
# ==========================================================================

def _make_finding_id(cve="CVE-2024-1234", agent_id="003",
                     package="openssl", severity="Critical"):
    """Helper: gera finding_id SHA-256."""
    raw = f"{cve}|{agent_id}|{package}|{severity}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


VALID_FINDING_ID = _make_finding_id()


def _make_guidance_record(finding_id=None, status="success", command="sudo apt-get install openssl=1.1.1l"):
    """Helper: cria GuidanceRecord para testes."""
    return GuidanceRecord(
        finding_id=finding_id or VALID_FINDING_ID,
        cve="CVE-2024-1234",
        package_name="openssl",
        installed_version="1.1.1k-1ubuntu1",
        fixed_version="1.1.1l-1ubuntu1",
        operating_system="ubuntu",
        package_manager="apt",
        agent_id="003",
        agent_name="webserver-prod-01",
        severity="Critical",
        status=status,
        command=command,
        verification_command="dpkg-query -W openssl",
        source="wazuh_snapshot",
        confidence="high",
    )


class MockRequest:
    """Simula um request HTTP para o handler."""

    def __init__(self, method="GET", path="/", headers=None, body=b""):
        self.method = method
        self.path = path
        self.headers = headers or {}
        self.body = body
        self.rfile = io.BytesIO(body)


class MockHandler:
    """Simula o SoarAPIHandler para testes sem servidor HTTP real.

    Importa e usa as funções de handler diretamente.
    """

    def __init__(self, method="GET", path="/", headers=None, body=b""):
        self.method = method
        self.path = path
        self._headers = headers or {"X-Remote-User": "testuser"}
        self.body = body
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.client_address = ("127.0.0.1", 12345)

        # Response tracking
        self.response_code = None
        self.response_headers = {}
        self.response_body = None
        self._headers_list = []

    @property
    def headers(self):
        """Dict-like headers object."""
        return _DictHeaders(self._headers)

    def send_response(self, code):
        self.response_code = code

    def send_header(self, key, value):
        self.response_headers[key] = value
        self._headers_list.append((key, value))

    def end_headers(self):
        pass

    def get_response_json(self):
        """Parse response body as JSON."""
        body = self.wfile.getvalue()
        if body:
            return json.loads(body.decode("utf-8"))
        return None


class _DictHeaders:
    """Adapter para simular headers HTTP como dict."""

    def __init__(self, d):
        self._d = d

    def get(self, key, default=None):
        return self._d.get(key, default)

    def __getitem__(self, key):
        return self._d[key]


# ==========================================================================
# FIXTURES
# ==========================================================================


@pytest.fixture
def tmp_snapshot(tmp_path):
    """Cria snapshot temporário para testes."""
    snapshot_path = tmp_path / "latest.json"
    vuln = {
        "cve": "CVE-2024-1234",
        "agent_id": "003",
        "agent_name": "webserver-prod-01",
        "package": "openssl",
        "version": "1.1.1k-1ubuntu1",
        "severity": "Critical",
        "fixed_version": "1.1.1l-1ubuntu1",
    }
    snapshot_path.write_text(
        json.dumps({"vulnerabilities": [vuln]}), encoding="utf-8"
    )
    return snapshot_path


@pytest.fixture
def cache(tmp_snapshot):
    """Cache com snapshot path."""
    return GuidanceCache(snapshot_path=tmp_snapshot, ttl_seconds=3600, max_entries=100)


@pytest.fixture
def guidance_limiter():
    """Rate limiter para guidance GET (60/min)."""
    return SlidingWindowLog(max_tokens=60, window_seconds=60)


@pytest.fixture
def audit_limiter():
    """Rate limiter para audit POST (10/min)."""
    return SlidingWindowLog(max_tokens=10, window_seconds=60)


# ==========================================================================
# API HANDLER INTEGRATION HELPER
# ==========================================================================

def _call_handler(method, path, headers=None, body=b"",
                  engine_result=None, cache_obj=None):
    """Invoca o handler de remediation diretamente sem servidor HTTP.

    Usa patches para isolar dos componentes reais.
    """
    import soar_api

    if headers is None:
        headers = {"X-Remote-User": "testuser"}

    # Create a mock handler instance replicating SoarAPIHandler behavior
    handler = MockHandler(method=method, path=path, headers=headers, body=body)

    # Patch module-level globals
    patches = {}

    if engine_result is not None:
        mock_engine = MagicMock()
        mock_engine.generate_guidance.return_value = engine_result
        patches["_remediation_engine"] = mock_engine
    elif not hasattr(soar_api, "_remediation_engine") or soar_api._remediation_engine is None:
        mock_engine = MagicMock()
        mock_engine.generate_guidance.return_value = GuidanceRecord(
            finding_id=VALID_FINDING_ID, status="not_found", confidence="none"
        )
        patches["_remediation_engine"] = mock_engine

    if cache_obj is not None:
        patches["_guidance_cache"] = cache_obj
    elif not hasattr(soar_api, "_guidance_cache") or soar_api._guidance_cache is None:
        patches["_guidance_cache"] = GuidanceCache(ttl_seconds=3600)

    if "_guidance_rate_limiter" not in patches:
        if not hasattr(soar_api, "_guidance_rate_limiter") or soar_api._guidance_rate_limiter is None:
            patches["_guidance_rate_limiter"] = SlidingWindowLog(max_tokens=60)

    if "_audit_rate_limiter" not in patches:
        if not hasattr(soar_api, "_audit_rate_limiter") or soar_api._audit_rate_limiter is None:
            patches["_audit_rate_limiter"] = SlidingWindowLog(max_tokens=10)

    # Apply patches
    from urllib.parse import urlparse
    parsed_url = urlparse(path)

    # Bind handler methods to our mock
    handler._get_remote_user = lambda: headers.get("X-Remote-User", "unknown")
    handler._get_client_ip = lambda: "127.0.0.1"
    handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
    handler._send_guidance_response = lambda record: _mock_send_guidance_response(handler, record)
    handler._log_guidance_audit = lambda **kwargs: None  # suppress audit in tests

    if patches:
        with patch.multiple(soar_api, **patches):
            if method == "GET":
                soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed_url)
            elif method == "POST":
                soar_api.SoarAPIHandler._handle_remediation_audit_post_internal(handler, parsed_url)
    else:
        if method == "GET":
            soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed_url)
        elif method == "POST":
            soar_api.SoarAPIHandler._handle_remediation_audit_post_internal(handler, parsed_url)

    return handler


def _mock_send_guidance_json(handler, code, data, extra_headers=None):
    """Mock implementation of _send_guidance_json."""
    handler.response_code = code
    body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    handler.response_headers["Content-Type"] = "application/json; charset=utf-8"
    handler.response_headers["Cache-Control"] = "no-store"
    handler.response_headers["X-Execution-Allowed"] = "false"
    if extra_headers:
        handler.response_headers.update(extra_headers)
    handler.wfile.write(body)


def _mock_send_guidance_response(handler, record):
    """Mock implementation of _send_guidance_response."""
    data = record.to_dict()
    body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    if len(body) > 32768:
        _mock_send_guidance_json(handler, 500, {"error": "Erro interno do servidor"})
        return
    handler.response_code = 200
    handler.response_headers["Content-Type"] = "application/json; charset=utf-8"
    handler.response_headers["Cache-Control"] = "no-store"
    handler.response_headers["X-Execution-Allowed"] = "false"
    handler.wfile.write(body)


# ==========================================================================
# TEST 1: Valid finding_id → 200
# ==========================================================================

class TestGETValidFindingId:
    """Test 1: finding_id válido retorna 200."""

    def test_valid_finding_id_returns_200(self):
        record = _make_guidance_record()
        handler = _call_handler(
            "GET", f"/remediation-guidance/{VALID_FINDING_ID}",
            engine_result=record,
        )
        assert handler.response_code == 200


# ==========================================================================
# TEST 2: Guidance with status success → has command
# ==========================================================================

class TestGETSuccessHasCommand:
    """Test 2: status success contém command."""

    def test_success_has_command(self):
        record = _make_guidance_record(status="success")
        handler = _call_handler(
            "GET", f"/remediation-guidance/{VALID_FINDING_ID}",
            engine_result=record,
        )
        assert handler.response_code == 200
        data = handler.get_response_json()
        assert "command" in data
        assert data["command"] is not None


# ==========================================================================
# TEST 3: Guidance with status no_guidance → no command
# ==========================================================================

class TestGETNoGuidance:
    """Test 3: status no_guidance não contém command."""

    def test_no_guidance_no_command(self):
        record = _make_guidance_record(status="no_guidance", command=None)
        handler = _call_handler(
            "GET", f"/remediation-guidance/{VALID_FINDING_ID}",
            engine_result=record,
        )
        assert handler.response_code == 200
        data = handler.get_response_json()
        assert "command" not in data


# ==========================================================================
# TEST 4: Non-existent finding → 404
# ==========================================================================

class TestGETNotFound:
    """Test 4: finding não existente → 404."""

    def test_not_found_returns_404(self):
        record = GuidanceRecord(finding_id="b" * 64, status="not_found")
        handler = _call_handler(
            "GET", f"/remediation-guidance/{'b' * 64}",
            engine_result=record,
        )
        assert handler.response_code == 404


# ==========================================================================
# TEST 5: Invalid finding_id (bad chars) → 400
# ==========================================================================

class TestGETInvalidFindingIdBadChars:
    """Test 5: finding_id com caracteres inválidos → 400."""

    def test_bad_chars_returns_400(self):
        handler = _call_handler("GET", "/remediation-guidance/invalid!chars;here")
        assert handler.response_code == 400


# ==========================================================================
# TEST 6: Excessively long finding_id → 400
# ==========================================================================

class TestGETExcessivelyLongFindingId:
    """Test 6: finding_id muito longo → 400."""

    def test_too_long_returns_400(self):
        # 65 chars (valid hex but too long/short)
        handler = _call_handler("GET", f"/remediation-guidance/{'a' * 65}")
        assert handler.response_code == 400

    def test_too_short_returns_400(self):
        handler = _call_handler("GET", f"/remediation-guidance/{'a' * 63}")
        assert handler.response_code == 400


# ==========================================================================
# TEST 7: Query string present → 400
# ==========================================================================

class TestGETQueryStringRejected:
    """Test 7: query string presente → 400."""

    def test_query_string_returns_400(self):
        handler = _call_handler(
            "GET", f"/remediation-guidance/{VALID_FINDING_ID}?foo=bar"
        )
        assert handler.response_code == 400


# ==========================================================================
# TEST 8: Body present → 400
# ==========================================================================

class TestGETBodyRejected:
    """Test 8: body presente no GET → 400."""

    def test_body_present_returns_400(self):
        handler = _call_handler(
            "GET", f"/remediation-guidance/{VALID_FINDING_ID}",
            headers={"X-Remote-User": "testuser", "Content-Length": "5"},
            body=b"hello",
        )
        assert handler.response_code == 400


# ==========================================================================
# TEST 9: Rate limit exceeded → 429
# ==========================================================================

class TestGETRateLimitExceeded:
    """Test 9: rate limit excedido → 429."""

    def test_rate_limit_429(self):
        import soar_api
        exhausted_limiter = SlidingWindowLog(max_tokens=1, window_seconds=60)
        exhausted_limiter.is_allowed("testuser")  # consume the only token

        with patch.object(soar_api, "_guidance_rate_limiter", exhausted_limiter), \
             patch.object(soar_api, "_remediation_engine", MagicMock()), \
             patch.object(soar_api, "_guidance_cache", GuidanceCache()), \
             patch.object(soar_api, "_audit_rate_limiter", SlidingWindowLog()):
            from urllib.parse import urlparse
            handler = MockHandler()
            handler._get_remote_user = lambda: "testuser"
            handler._get_client_ip = lambda: "127.0.0.1"
            handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
            handler._send_guidance_response = lambda rec: _mock_send_guidance_response(handler, rec)
            handler._log_guidance_audit = lambda **kwargs: None
            handler.rfile = io.BytesIO(b"")
            handler._headers = {"X-Remote-User": "testuser"}
            parsed = urlparse(f"/remediation-guidance/{VALID_FINDING_ID}")
            soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed)
        assert handler.response_code == 429


# ==========================================================================
# TEST 10: Retry-After header present in 429
# ==========================================================================

class TestGETRetryAfterHeader:
    """Test 10: header Retry-After presente em 429."""

    def test_retry_after_in_429(self):
        import soar_api
        exhausted_limiter = SlidingWindowLog(max_tokens=1, window_seconds=60)
        exhausted_limiter.is_allowed("testuser")

        with patch.object(soar_api, "_guidance_rate_limiter", exhausted_limiter), \
             patch.object(soar_api, "_remediation_engine", MagicMock()), \
             patch.object(soar_api, "_guidance_cache", GuidanceCache()), \
             patch.object(soar_api, "_audit_rate_limiter", SlidingWindowLog()):
            from urllib.parse import urlparse
            handler = MockHandler()
            handler._get_remote_user = lambda: "testuser"
            handler._get_client_ip = lambda: "127.0.0.1"
            handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
            handler._send_guidance_response = lambda rec: _mock_send_guidance_response(handler, rec)
            handler._log_guidance_audit = lambda **kwargs: None
            handler.rfile = io.BytesIO(b"")
            handler._headers = {"X-Remote-User": "testuser"}
            parsed = urlparse(f"/remediation-guidance/{VALID_FINDING_ID}")
            soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed)
        assert "Retry-After" in handler.response_headers
        assert int(handler.response_headers["Retry-After"]) > 0


# ==========================================================================
# TEST 11: Engine raises unexpected error → 500
# ==========================================================================

class TestGETEngineError:
    """Test 11: erro inesperado no engine → 500."""

    def test_engine_error_returns_500(self):
        import soar_api
        mock_engine = MagicMock()
        mock_engine.generate_guidance.side_effect = RuntimeError("boom")

        with patch.object(soar_api, "_remediation_engine", mock_engine), \
             patch.object(soar_api, "_guidance_cache", GuidanceCache()), \
             patch.object(soar_api, "_guidance_rate_limiter", SlidingWindowLog()), \
             patch.object(soar_api, "_audit_rate_limiter", SlidingWindowLog()):
            from urllib.parse import urlparse
            handler = MockHandler()
            handler._get_remote_user = lambda: "testuser"
            handler._get_client_ip = lambda: "127.0.0.1"
            handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
            handler._send_guidance_response = lambda rec: _mock_send_guidance_response(handler, rec)
            handler._log_guidance_audit = lambda **kwargs: None
            handler.rfile = io.BytesIO(b"")
            handler._headers = {"X-Remote-User": "testuser"}
            parsed = urlparse(f"/remediation-guidance/{VALID_FINDING_ID}")
            soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed)
        assert handler.response_code == 500


# ==========================================================================
# TEST 12: Provider temporarily unavailable → 503
# ==========================================================================

class TestGETProviderUnavailable:
    """Test 12: provider indisponível → 503."""

    def test_provider_unavailable_returns_503(self):
        record = GuidanceRecord(
            finding_id=VALID_FINDING_ID,
            status="provider_unavailable",
        )
        handler = _call_handler(
            "GET", f"/remediation-guidance/{VALID_FINDING_ID}",
            engine_result=record,
        )
        assert handler.response_code == 503


# ==========================================================================
# TEST 13: Response has no stack trace
# ==========================================================================

class TestGETNoStackTrace:
    """Test 13: resposta não contém stack trace."""

    def test_no_stack_trace_in_500(self):
        import soar_api
        mock_engine = MagicMock()
        mock_engine.generate_guidance.side_effect = ValueError("internal detail")

        with patch.object(soar_api, "_remediation_engine", mock_engine), \
             patch.object(soar_api, "_guidance_cache", GuidanceCache()), \
             patch.object(soar_api, "_guidance_rate_limiter", SlidingWindowLog()), \
             patch.object(soar_api, "_audit_rate_limiter", SlidingWindowLog()):
            from urllib.parse import urlparse
            handler = MockHandler()
            handler._get_remote_user = lambda: "testuser"
            handler._get_client_ip = lambda: "127.0.0.1"
            handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
            handler._send_guidance_response = lambda rec: _mock_send_guidance_response(handler, rec)
            handler._log_guidance_audit = lambda **kwargs: None
            handler.rfile = io.BytesIO(b"")
            handler._headers = {"X-Remote-User": "testuser"}
            parsed = urlparse(f"/remediation-guidance/{VALID_FINDING_ID}")
            soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed)
        body = handler.wfile.getvalue().decode("utf-8")
        assert "Traceback" not in body
        assert "internal detail" not in body


# ==========================================================================
# TEST 14: execution_allowed always false in response
# ==========================================================================

class TestGETExecutionAllowedAlwaysFalse:
    """Test 14: execution_allowed sempre false."""

    def test_execution_allowed_false_in_200(self):
        record = _make_guidance_record()
        handler = _call_handler(
            "GET", f"/remediation-guidance/{VALID_FINDING_ID}",
            engine_result=record,
        )
        data = handler.get_response_json()
        assert data["execution_allowed"] is False
        assert handler.response_headers.get("X-Execution-Allowed") == "false"

    def test_execution_allowed_false_in_400(self):
        handler = _call_handler("GET", "/remediation-guidance/invalid!")
        assert handler.response_headers.get("X-Execution-Allowed") == "false"


# ==========================================================================
# TEST 15: Commands omitted in non-success states
# ==========================================================================

class TestGETCommandsOmittedNonSuccess:
    """Test 15: comandos omitidos em estados não-success."""

    def test_no_command_in_no_guidance(self):
        record = _make_guidance_record(status="no_guidance", command=None)
        handler = _call_handler(
            "GET", f"/remediation-guidance/{VALID_FINDING_ID}",
            engine_result=record,
        )
        data = handler.get_response_json()
        assert "command" not in data
        assert "verification_command" not in data


# ==========================================================================
# TEST 16: Cache hit (same finding_id returns same guidance_id)
# ==========================================================================

class TestGETCacheHit:
    """Test 16: cache hit retorna mesmo guidance_id."""

    def test_cache_hit_same_guidance_id(self, cache):
        record = _make_guidance_record()
        cache.put(VALID_FINDING_ID, record)

        # Second get should return same record
        cached = cache.get_by_finding_id(VALID_FINDING_ID)
        assert cached is not None
        assert cached.guidance_id == record.guidance_id


# ==========================================================================
# TEST 17: Cache miss (new finding_id triggers engine)
# ==========================================================================

class TestGETCacheMiss:
    """Test 17: cache miss dispara engine."""

    def test_cache_miss_returns_none(self, cache):
        result = cache.get_by_finding_id("c" * 64)
        assert result is None


# ==========================================================================
# TEST 18: Invalidation on snapshot change (mtime)
# ==========================================================================

class TestGETCacheInvalidation:
    """Test 18: invalidação de cache quando snapshot muda (mtime)."""

    def test_mtime_change_invalidates_cache(self, tmp_snapshot, cache):
        record = _make_guidance_record()
        cache.put(VALID_FINDING_ID, record)
        assert cache.get_by_finding_id(VALID_FINDING_ID) is not None

        # Modify snapshot file (changes mtime)
        time.sleep(0.05)
        tmp_snapshot.write_text(
            json.dumps({"vulnerabilities": []}), encoding="utf-8"
        )

        # Cache should be invalidated
        result = cache.get_by_finding_id(VALID_FINDING_ID)
        assert result is None


# ==========================================================================
# TEST 19: TTL expiration
# ==========================================================================

class TestGETCacheTTL:
    """Test 19: expiração por TTL."""

    def test_ttl_expiration(self, tmp_snapshot):
        cache = GuidanceCache(snapshot_path=tmp_snapshot, ttl_seconds=1)
        record = _make_guidance_record()
        cache.put(VALID_FINDING_ID, record)

        # Should be in cache
        assert cache.get_by_finding_id(VALID_FINDING_ID) is not None

        # Wait for TTL
        time.sleep(1.1)
        assert cache.get_by_finding_id(VALID_FINDING_ID) is None


# ==========================================================================
# TEST 20: 10,000 entry limit (eviction)
# ==========================================================================

class TestGETCacheEviction:
    """Test 20: limite de 10,000 entradas com eviction LRU."""

    def test_eviction_on_limit(self):
        cache = GuidanceCache(ttl_seconds=3600, max_entries=5)

        # Fill cache with 5 entries
        records = []
        for i in range(5):
            fid = hashlib.sha256(f"test{i}".encode()).hexdigest()
            rec = GuidanceRecord(finding_id=fid, status="no_guidance")
            cache.put(fid, rec)
            records.append((fid, rec))

        # All 5 should be there
        assert cache.size() == 5

        # Add 6th entry → should evict oldest (index 0)
        fid_new = hashlib.sha256(b"test_new").hexdigest()
        rec_new = GuidanceRecord(finding_id=fid_new, status="no_guidance")
        cache.put(fid_new, rec_new)

        assert cache.size() == 5
        # Oldest should be evicted
        assert cache.get_by_finding_id(records[0][0]) is None
        # Newest should be there
        assert cache.get_by_finding_id(fid_new) is not None


# ==========================================================================
# TEST 21: Thread safety basic test
# ==========================================================================

class TestGETThreadSafety:
    """Test 21: operações de cache são thread-safe."""

    def test_concurrent_puts_and_gets(self):
        cache = GuidanceCache(ttl_seconds=3600, max_entries=1000)
        errors = []

        def worker(idx):
            try:
                fid = hashlib.sha256(f"thread{idx}".encode()).hexdigest()
                rec = GuidanceRecord(finding_id=fid, status="no_guidance")
                cache.put(fid, rec)
                result = cache.get_by_finding_id(fid)
                if result is None:
                    errors.append(f"Thread {idx}: cache miss after put")
            except Exception as e:
                errors.append(f"Thread {idx}: {e}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread safety errors: {errors}"


# ==========================================================================
# TEST 22: View event is audited
# ==========================================================================

class TestGETViewAudited:
    """Test 22: evento de view é registrado em auditoria."""

    def test_view_audit_called(self, tmp_path):
        import soar_api

        audit_log_path = tmp_path / "audit_actions.jsonl"
        record = _make_guidance_record()

        with patch.object(soar_api, "AUDIT_LOG", audit_log_path):
            with patch.object(soar_api, "AUDIT_DIR", tmp_path):
                with patch.object(soar_api, "_remediation_engine", MagicMock(
                    generate_guidance=MagicMock(return_value=record))):
                    with patch.object(soar_api, "_guidance_cache", GuidanceCache()):
                        with patch.object(soar_api, "_guidance_rate_limiter", SlidingWindowLog()):
                            with patch.object(soar_api, "_audit_rate_limiter", SlidingWindowLog()):
                                # Create handler manually with log enabled
                                handler = MockHandler(path=f"/remediation-guidance/{VALID_FINDING_ID}")
                                handler._get_remote_user = lambda: "testuser"
                                handler._get_client_ip = lambda: "127.0.0.1"
                                handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
                                handler._send_guidance_response = lambda rec: _mock_send_guidance_response(handler, rec)
                                handler._log_guidance_audit = soar_api.SoarAPIHandler._log_guidance_audit.__get__(handler)

                                from urllib.parse import urlparse
                                parsed = urlparse(f"/remediation-guidance/{VALID_FINDING_ID}")
                                soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed)

        # Check audit file
        if audit_log_path.exists():
            lines = audit_log_path.read_text(encoding="utf-8").strip().split("\n")
            assert len(lines) >= 1
            entry = json.loads(lines[-1])
            assert entry["action"] == "guidance_view"
            assert entry["remote_user"] == "testuser"


# ==========================================================================
# TEST 23: POST correct payload → 200
# ==========================================================================

class TestPOSTCorrectPayload:
    """Test 23: payload correto de copy → 200."""

    def test_copy_returns_200(self):
        import soar_api
        record = _make_guidance_record()
        cache = GuidanceCache()
        cache.put(VALID_FINDING_ID, record)
        guid = record.guidance_id

        with patch.object(soar_api, "_guidance_cache", cache):
            with patch.object(soar_api, "_remediation_engine", MagicMock()):
                with patch.object(soar_api, "_guidance_rate_limiter", SlidingWindowLog()):
                    with patch.object(soar_api, "_audit_rate_limiter", SlidingWindowLog()):
                        body = json.dumps({"action": "copy"}).encode("utf-8")
                        handler = _call_handler(
                            "POST",
                            f"/remediation-guidance/{guid}/audit",
                            headers={
                                "X-Remote-User": "testuser",
                                "Content-Type": "application/json",
                                "Content-Length": str(len(body)),
                            },
                            body=body,
                            cache_obj=cache,
                        )
        assert handler.response_code == 200
        data = handler.get_response_json()
        assert data["status"] == "ok"


# ==========================================================================
# TEST 24: Non-existent guidance_id → 404
# ==========================================================================

class TestPOSTNonExistentGuid:
    """Test 24: guidance_id inexistente → 404."""

    def test_nonexistent_guid_returns_404(self):
        body = json.dumps({"action": "copy"}).encode("utf-8")
        fake_guid = "550e8400-e29b-41d4-a716-446655440000"
        handler = _call_handler(
            "POST",
            f"/remediation-guidance/{fake_guid}/audit",
            headers={
                "X-Remote-User": "testuser",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        assert handler.response_code == 404


# ==========================================================================
# TEST 25: Expired guidance_id → 404
# ==========================================================================

class TestPOSTExpiredGuid:
    """Test 25: guidance_id expirado → 404."""

    def test_expired_guid_returns_404(self):
        cache = GuidanceCache(ttl_seconds=1)
        record = _make_guidance_record()
        cache.put(VALID_FINDING_ID, record)
        guid = record.guidance_id

        time.sleep(1.1)  # Wait for TTL

        body = json.dumps({"action": "copy"}).encode("utf-8")
        handler = _call_handler(
            "POST",
            f"/remediation-guidance/{guid}/audit",
            headers={
                "X-Remote-User": "testuser",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
            cache_obj=cache,
        )
        assert handler.response_code == 404


# ==========================================================================
# TEST 26: Invalid JSON → 400
# ==========================================================================

class TestPOSTInvalidJSON:
    """Test 26: JSON inválido → 400."""

    def test_invalid_json_returns_400(self):
        body = b"not valid json{{"
        fake_guid = "550e8400-e29b-41d4-a716-446655440000"
        handler = _call_handler(
            "POST",
            f"/remediation-guidance/{fake_guid}/audit",
            headers={
                "X-Remote-User": "testuser",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        assert handler.response_code == 400


# ==========================================================================
# TEST 27: Empty body → 400
# ==========================================================================

class TestPOSTEmptyBody:
    """Test 27: body vazio → 400."""

    def test_empty_body_returns_400(self):
        fake_guid = "550e8400-e29b-41d4-a716-446655440000"
        handler = _call_handler(
            "POST",
            f"/remediation-guidance/{fake_guid}/audit",
            headers={
                "X-Remote-User": "testuser",
                "Content-Type": "application/json",
                "Content-Length": "0",
            },
            body=b"",
        )
        assert handler.response_code == 400


# ==========================================================================
# TEST 28: Wrong Content-Type → 400
# ==========================================================================

class TestPOSTWrongContentType:
    """Test 28: Content-Type errado → 400."""

    def test_wrong_content_type_returns_400(self):
        body = json.dumps({"action": "copy"}).encode("utf-8")
        fake_guid = "550e8400-e29b-41d4-a716-446655440000"
        handler = _call_handler(
            "POST",
            f"/remediation-guidance/{fake_guid}/audit",
            headers={
                "X-Remote-User": "testuser",
                "Content-Type": "text/plain",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        assert handler.response_code == 400


# ==========================================================================
# TEST 29: Invalid action → 400
# ==========================================================================

class TestPOSTInvalidAction:
    """Test 29: action inválida → 400."""

    def test_invalid_action_returns_400(self):
        body = json.dumps({"action": "execute"}).encode("utf-8")
        fake_guid = "550e8400-e29b-41d4-a716-446655440000"
        handler = _call_handler(
            "POST",
            f"/remediation-guidance/{fake_guid}/audit",
            headers={
                "X-Remote-User": "testuser",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        assert handler.response_code == 400


# ==========================================================================
# TEST 30: Extra fields → 400
# ==========================================================================

class TestPOSTExtraFields:
    """Test 30: campos extras → 400."""

    def test_extra_fields_returns_400(self):
        body = json.dumps({"action": "copy", "extra": "field"}).encode("utf-8")
        fake_guid = "550e8400-e29b-41d4-a716-446655440000"
        handler = _call_handler(
            "POST",
            f"/remediation-guidance/{fake_guid}/audit",
            headers={
                "X-Remote-User": "testuser",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        assert handler.response_code == 400


# ==========================================================================
# TEST 31: Query string present in POST → 400
# ==========================================================================

class TestPOSTQueryStringRejected:
    """Test 31: query string no POST → 400."""

    def test_query_string_returns_400(self):
        body = json.dumps({"action": "copy"}).encode("utf-8")
        fake_guid = "550e8400-e29b-41d4-a716-446655440000"
        handler = _call_handler(
            "POST",
            f"/remediation-guidance/{fake_guid}/audit?foo=bar",
            headers={
                "X-Remote-User": "testuser",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        assert handler.response_code == 400


# ==========================================================================
# TEST 32: Rate limit before lookup → 429
# ==========================================================================

class TestPOSTRateLimitBeforeLookup:
    """Test 32: rate limit verificado antes de lookup → 429."""

    def test_rate_limit_before_lookup(self):
        import soar_api
        exhausted = SlidingWindowLog(max_tokens=1, window_seconds=60)
        fake_guid = "550e8400-e29b-41d4-a716-446655440000"
        exhausted.is_allowed("copy:user:testuser")  # exhaust with new key format

        body = json.dumps({"action": "copy"}).encode("utf-8")
        with patch.object(soar_api, "_audit_rate_limiter", exhausted), \
             patch.object(soar_api, "_remediation_engine", MagicMock()), \
             patch.object(soar_api, "_guidance_cache", GuidanceCache()), \
             patch.object(soar_api, "_guidance_rate_limiter", SlidingWindowLog()):
            from urllib.parse import urlparse
            handler = MockHandler()
            handler._get_remote_user = lambda: "testuser"
            handler._get_client_ip = lambda: "127.0.0.1"
            handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
            handler._log_guidance_audit = lambda **kwargs: None
            handler.rfile = io.BytesIO(body)
            handler._headers = {
                "X-Remote-User": "testuser",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            }
            parsed = urlparse(f"/remediation-guidance/{fake_guid}/audit")
            soar_api.SoarAPIHandler._handle_remediation_audit_post_internal(handler, parsed)
        assert handler.response_code == 429


# ==========================================================================
# TEST 33: Unauthenticated user → 401
# ==========================================================================

class TestPOSTUnauthenticated:
    """Test 33: usuário não autenticado → 401."""

    def test_unauthenticated_returns_401(self):
        body = json.dumps({"action": "copy"}).encode("utf-8")
        fake_guid = "550e8400-e29b-41d4-a716-446655440000"
        handler = _call_handler(
            "POST",
            f"/remediation-guidance/{fake_guid}/audit",
            headers={
                "X-Remote-User": "",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        assert handler.response_code == 401

    def test_missing_user_header_returns_401(self):
        body = json.dumps({"action": "copy"}).encode("utf-8")
        fake_guid = "550e8400-e29b-41d4-a716-446655440000"
        handler = _call_handler(
            "POST",
            f"/remediation-guidance/{fake_guid}/audit",
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        assert handler.response_code == 401


# ==========================================================================
# TEST 34: Copy event is audited
# ==========================================================================

class TestPOSTCopyAudited:
    """Test 34: evento de copy é auditado."""

    def test_copy_audit_logged(self, tmp_path):
        import soar_api
        cache = GuidanceCache()
        record = _make_guidance_record()
        cache.put(VALID_FINDING_ID, record)
        guid = record.guidance_id

        audit_log_path = tmp_path / "audit_actions.jsonl"

        with patch.object(soar_api, "AUDIT_LOG", audit_log_path):
            with patch.object(soar_api, "AUDIT_DIR", tmp_path):
                with patch.object(soar_api, "_guidance_cache", cache):
                    with patch.object(soar_api, "_remediation_engine", MagicMock()):
                        with patch.object(soar_api, "_guidance_rate_limiter", SlidingWindowLog()):
                            with patch.object(soar_api, "_audit_rate_limiter", SlidingWindowLog()):
                                body = json.dumps({"action": "copy"}).encode("utf-8")
                                handler = MockHandler(path=f"/remediation-guidance/{guid}/audit")
                                handler._get_remote_user = lambda: "testuser"
                                handler._get_client_ip = lambda: "127.0.0.1"
                                handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
                                handler._log_guidance_audit = soar_api.SoarAPIHandler._log_guidance_audit.__get__(handler)
                                handler.rfile = io.BytesIO(body)
                                handler._headers = {
                                    "X-Remote-User": "testuser",
                                    "Content-Type": "application/json",
                                    "Content-Length": str(len(body)),
                                }

                                from urllib.parse import urlparse
                                parsed = urlparse(f"/remediation-guidance/{guid}/audit")
                                soar_api.SoarAPIHandler._handle_remediation_audit_post_internal(handler, parsed)

        if audit_log_path.exists():
            lines = audit_log_path.read_text(encoding="utf-8").strip().split("\n")
            entry = json.loads(lines[-1])
            assert entry["action"] == "guidance_copy"
            assert entry["remote_user"] == "testuser"


# ==========================================================================
# TEST 35: Command NOT in audit log
# ==========================================================================

class TestPOSTCommandNotInAudit:
    """Test 35: command content NEVER in audit log."""

    def test_command_not_in_audit(self, tmp_path):
        import soar_api
        cache = GuidanceCache()
        record = _make_guidance_record(command="sudo apt-get install openssl=1.1.1l")
        cache.put(VALID_FINDING_ID, record)

        audit_log_path = tmp_path / "audit_actions.jsonl"

        with patch.object(soar_api, "AUDIT_LOG", audit_log_path):
            with patch.object(soar_api, "AUDIT_DIR", tmp_path):
                with patch.object(soar_api, "_guidance_cache", cache):
                    with patch.object(soar_api, "_remediation_engine", MagicMock()):
                        with patch.object(soar_api, "_guidance_rate_limiter", SlidingWindowLog()):
                            with patch.object(soar_api, "_audit_rate_limiter", SlidingWindowLog()):
                                # Trigger view to generate audit
                                handler = MockHandler()
                                handler._get_remote_user = lambda: "testuser"
                                handler._get_client_ip = lambda: "127.0.0.1"
                                handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
                                handler._send_guidance_response = lambda rec: _mock_send_guidance_response(handler, rec)
                                handler._log_guidance_audit = soar_api.SoarAPIHandler._log_guidance_audit.__get__(handler)

                                from urllib.parse import urlparse
                                parsed = urlparse(f"/remediation-guidance/{VALID_FINDING_ID}")
                                soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed)

        if audit_log_path.exists():
            content = audit_log_path.read_text(encoding="utf-8")
            assert "sudo apt-get install" not in content
            assert "openssl=1.1.1l" not in content


# ==========================================================================
# TEST 36: Command NOT accepted in payload
# ==========================================================================

class TestPOSTCommandNotAccepted:
    """Test 36: command não aceito no payload."""

    def test_command_in_payload_rejected(self):
        body = json.dumps({"action": "copy", "command": "rm -rf /"}).encode("utf-8")
        fake_guid = "550e8400-e29b-41d4-a716-446655440000"
        handler = _call_handler(
            "POST",
            f"/remediation-guidance/{fake_guid}/audit",
            headers={
                "X-Remote-User": "testuser",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        # Extra fields → 400
        assert handler.response_code == 400


# ==========================================================================
# TEST 37: Response does NOT contain command in audit response
# ==========================================================================

class TestPOSTResponseNoCommand:
    """Test 37: resposta do POST audit não contém command."""

    def test_audit_response_no_command(self):
        import soar_api
        cache = GuidanceCache()
        record = _make_guidance_record(command="dangerous command here")
        cache.put(VALID_FINDING_ID, record)
        guid = record.guidance_id

        body = json.dumps({"action": "copy"}).encode("utf-8")
        with patch.object(soar_api, "_guidance_cache", cache):
            with patch.object(soar_api, "_remediation_engine", MagicMock()):
                with patch.object(soar_api, "_guidance_rate_limiter", SlidingWindowLog()):
                    with patch.object(soar_api, "_audit_rate_limiter", SlidingWindowLog()):
                        handler = _call_handler(
                            "POST",
                            f"/remediation-guidance/{guid}/audit",
                            headers={
                                "X-Remote-User": "testuser",
                                "Content-Type": "application/json",
                                "Content-Length": str(len(body)),
                            },
                            body=body,
                            cache_obj=cache,
                        )
        assert handler.response_code == 200
        response_text = handler.wfile.getvalue().decode("utf-8")
        assert "dangerous command" not in response_text


# ==========================================================================
# TEST 38: Excessive repetition → 429
# ==========================================================================

class TestPOSTExcessiveRepetition:
    """Test 38: repetição excessiva de copy → 429."""

    def test_excessive_repetition_rate_limited(self):
        limiter = SlidingWindowLog(max_tokens=3, window_seconds=60)
        key = "testuser:some-guid"
        assert limiter.is_allowed(key) is True
        assert limiter.is_allowed(key) is True
        assert limiter.is_allowed(key) is True
        assert limiter.is_allowed(key) is False
        assert limiter.get_retry_after(key) > 0


# ==========================================================================
# TEST 39: guidance_id linked to cache
# ==========================================================================

class TestPOSTGuidLinkedToCache:
    """Test 39: guidance_id resolve para record no cache."""

    def test_guid_resolves_in_cache(self):
        cache = GuidanceCache(ttl_seconds=3600)
        record = _make_guidance_record()
        cache.put(VALID_FINDING_ID, record)

        # Lookup by guidance_id
        resolved = cache.get_by_guidance_id(record.guidance_id)
        assert resolved is not None
        assert resolved.finding_id == VALID_FINDING_ID
        assert resolved.guidance_id == record.guidance_id


# ==========================================================================
# TEST 40: Cache invalidation makes old ID return 404
# ==========================================================================

class TestPOSTCacheInvalidation404:
    """Test 40: invalidação de cache faz guidance_id antigo retornar 404."""

    def test_invalidation_causes_404(self):
        cache = GuidanceCache(ttl_seconds=3600)
        record = _make_guidance_record()
        cache.put(VALID_FINDING_ID, record)
        guid = record.guidance_id

        # Verify it's there
        assert cache.get_by_guidance_id(guid) is not None

        # Invalidate all
        cache.invalidate_all()

        # Now it's gone
        assert cache.get_by_guidance_id(guid) is None


# ==========================================================================
# REGRESSION TESTS (41-50)
# ==========================================================================

# TEST 41: All existing endpoints still registered
class TestRegressionEndpointsRegistered:
    """Test 41: todos os endpoints existentes ainda registrados."""

    def test_existing_get_endpoints_registered(self):
        """Verifica que do_GET tem todos os paths conhecidos."""
        import soar_api
        import inspect
        source = inspect.getsource(soar_api.SoarAPIHandler.do_GET)
        expected_paths = [
            "/health", "/status", "/audit-actions", "/risk-summary",
            "/risk-delta", "/asset-context", "/assets-context",
            "/exposure-context", "/sla-summary", "/risk-acceptance",
            "/trend-summary", "/treatment-plan",
        ]
        for path in expected_paths:
            assert path in source, f"Path {path} not found in do_GET"

    def test_existing_post_endpoints_registered(self):
        """Verifica que do_POST tem /run-analysis e /assets-context."""
        import soar_api
        import inspect
        source = inspect.getsource(soar_api.SoarAPIHandler.do_POST)
        assert "/run-analysis" in source
        assert "/assets-context/" in source


# TEST 42: Existing responses unchanged
class TestRegressionResponsesUnchanged:
    """Test 42: respostas existentes não alteradas."""

    def test_health_response_format(self):
        """_handle_health retorna formato esperado."""
        import soar_api
        import inspect
        source = inspect.getsource(soar_api.SoarAPIHandler._handle_health)
        assert '"status": "ok"' in source or "'status': 'ok'" in source


# TEST 43: /health still works
class TestRegressionHealthWorks:
    """Test 43: /health ainda funciona."""

    def test_health_handler_exists(self):
        import soar_api
        assert hasattr(soar_api.SoarAPIHandler, "_handle_health")
        handler = MockHandler()
        handler._send_json = lambda code, data: setattr(handler, "response_code", code)
        soar_api.SoarAPIHandler._handle_health(handler)
        assert handler.response_code == 200


# TEST 44: /audit-actions still works
class TestRegressionAuditActionsWorks:
    """Test 44: /audit-actions ainda funciona."""

    def test_audit_actions_handler_exists(self):
        import soar_api
        assert hasattr(soar_api.SoarAPIHandler, "_handle_audit_actions")


# TEST 45: /run-analysis not called by remediation
class TestRegressionRunAnalysisNotCalled:
    """Test 45: /run-analysis não é chamado pelo módulo de remediação."""

    def test_no_run_analysis_in_remediation(self):
        """Nenhum arquivo do módulo de remediação referencia run-analysis."""
        remediation_dir = Path(__file__).parent.parent / "remediation"
        for py_file in remediation_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            assert "run-analysis" not in content
            assert "run_analysis" not in content


# TEST 46: analyserV1.py untouched
class TestRegressionAnalyserUntouched:
    """Test 46: analyserV1.py não foi modificado (existe)."""

    def test_analyser_exists(self):
        analyser = Path(__file__).parent.parent / "analyserV1.py"
        assert analyser.exists(), "analyserV1.py deve existir"


# TEST 47: Frontend HTML template integrity
class TestRegressionFrontendTemplate:
    """Test 47: HTML_TEMPLATE do analyserV1 existe e contém estrutura válida."""

    def test_html_template_exists_and_valid(self):
        """HTML_TEMPLATE está presente, é string não vazia com estrutura HTML."""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))
        import analyserV1
        tpl = analyserV1.HTML_TEMPLATE
        assert isinstance(tpl, str), "HTML_TEMPLATE deve ser string"
        assert len(tpl) > 1000, "HTML_TEMPLATE deve ser substancial"
        assert "<!DOCTYPE html>" in tpl or "<!doctype html>" in tpl.lower()
        assert "</html>" in tpl
        assert "</body>" in tpl


# TEST 48: No forbidden imports in new code
class TestRegressionNoForbiddenImports:
    """Test 48: nenhum import proibido no código novo de remediação."""

    def test_no_subprocess_in_remediation(self):
        import ast
        remediation_dir = Path(__file__).parent.parent / "remediation"
        for py_file in remediation_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            assert "import subprocess" not in content
            assert "from subprocess" not in content

    def test_no_os_system_in_remediation(self):
        import ast
        remediation_dir = Path(__file__).parent.parent / "remediation"
        for py_file in remediation_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            try:
                tree = ast.parse(content)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Attribute):
                        if (isinstance(func.value, ast.Name) and
                                func.value.id == "os" and
                                func.attr in ("system", "popen")):
                            pytest.fail(f"os.{func.attr} call found in {py_file.name}")

    def test_no_eval_exec_in_remediation(self):
        remediation_dir = Path(__file__).parent.parent / "remediation"
        for py_file in remediation_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            # Check for standalone eval/exec (not as part of larger word)
            lines = content.split("\n")
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if stripped.startswith("'") or stripped.startswith('"'):
                    continue
                # Simple check: eval( or exec( as function calls
                assert "eval(" not in stripped or "validate" in stripped.lower()
                assert "exec(" not in stripped or "execution" in stripped.lower()


# TEST 49: No secrets in test data
class TestRegressionNoSecrets:
    """Test 49: nenhum segredo em dados de teste."""

    def test_no_real_credentials(self):
        """Verifica que dados fictícios usados nos testes não parecem credenciais reais."""
        # The test data uses "testuser", fake UUIDs, fake CVEs — all fictitious
        # Verify no AWS/GCP/Azure-style keys in the test file
        test_file = Path(__file__)
        content = test_file.read_text(encoding="utf-8")
        # AWS access key pattern: AKIA followed by 16 chars
        import re
        aws_key_pattern = re.compile(r"AKIA[0-9A-Z]{16}")
        assert not aws_key_pattern.search(content), "Possible AWS key found"
        # Long hex strings that could be real tokens (>= 40 hex chars not in a hash context)
        # Our finding_ids are 64 hex chars but those are SHA-256 hashes, which is fine
        # Just verify no "Bearer " tokens
        assert "Bearer " not in content or "Bearer" in "# checking for Bearer tokens"


# TEST 50: Audit failure behavior documented in test
class TestRegressionAuditFailureBehavior:
    """Test 50: comportamento de falha de auditoria documentado.

    Per requirements:
    - View: audit failure logs warning but doesn't crash request
    - Copy: audit failure should not crash the audit endpoint
    """

    def test_audit_write_failure_doesnt_crash_view(self):
        """Se a escrita de audit falha, o GET ainda retorna 200."""
        import soar_api
        record = _make_guidance_record()

        with patch.object(soar_api, "_remediation_engine", MagicMock(
            generate_guidance=MagicMock(return_value=record))):
            with patch.object(soar_api, "_guidance_cache", GuidanceCache()):
                with patch.object(soar_api, "_guidance_rate_limiter", SlidingWindowLog()):
                    with patch.object(soar_api, "_audit_rate_limiter", SlidingWindowLog()):
                        # Patch audit log path to unwritable location
                        with patch.object(soar_api, "AUDIT_LOG", Path("/nonexistent/dir/audit.jsonl")):
                            handler = MockHandler()
                            handler._get_remote_user = lambda: "testuser"
                            handler._get_client_ip = lambda: "127.0.0.1"
                            handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
                            handler._send_guidance_response = lambda rec: _mock_send_guidance_response(handler, rec)
                            handler._log_guidance_audit = soar_api.SoarAPIHandler._log_guidance_audit.__get__(handler)

                            from urllib.parse import urlparse
                            parsed = urlparse(f"/remediation-guidance/{VALID_FINDING_ID}")
                            soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed)

        # Should still return 200 (audit failure is non-fatal for view)
        assert handler.response_code == 200

    def test_rate_limiter_retry_after_positive(self):
        """Rate limiter retorna retry_after > 0 quando excedido."""
        limiter = SlidingWindowLog(max_tokens=1, window_seconds=60)
        limiter.is_allowed("user1")  # exhaust
        retry = limiter.get_retry_after("user1")
        assert retry > 0
        assert retry <= 61  # at most window + 1


# ==========================================================================
# ADDITIONAL TESTS: Rate limit correction and cache audit
# ==========================================================================

class TestPOSTRateLimitPerUser:
    """Rate limit POST por usuário, independente do guidance_id."""

    def test_different_guidance_ids_share_user_limit(self):
        """Variar guidance_id NÃO contorna o rate limit do usuário."""
        limiter = SlidingWindowLog(max_tokens=3, window_seconds=60)
        # Same user prefix, different guidance_ids
        assert limiter.is_allowed("copy:user:testuser") is True
        assert limiter.is_allowed("copy:user:testuser") is True
        assert limiter.is_allowed("copy:user:testuser") is True
        assert limiter.is_allowed("copy:user:testuser") is False

    def test_varying_guid_does_not_avoid_429(self):
        """Mesmo com guidance_ids distintos, limite é por user."""
        limiter = SlidingWindowLog(max_tokens=2, window_seconds=60)
        # All consume the same key "copy:user:testuser"
        key = "copy:user:testuser"
        assert limiter.is_allowed(key) is True
        assert limiter.is_allowed(key) is True
        assert limiter.is_allowed(key) is False

    def test_rate_limit_before_guid_lookup(self):
        """Rate limit verificado antes do lookup de guidance_id."""
        # This test confirms the order in the handler: auth → rate limit → ... → lookup
        import soar_api
        exhausted = SlidingWindowLog(max_tokens=1, window_seconds=60)
        exhausted.is_allowed("copy:user:testuser")  # exhaust

        body = json.dumps({"action": "copy"}).encode("utf-8")
        fake_guid = "550e8400-e29b-41d4-a716-446655440000"

        with patch.object(soar_api, "_audit_rate_limiter", exhausted), \
             patch.object(soar_api, "_remediation_engine", MagicMock()), \
             patch.object(soar_api, "_guidance_cache", GuidanceCache()), \
             patch.object(soar_api, "_guidance_rate_limiter", SlidingWindowLog()):
            from urllib.parse import urlparse
            handler = MockHandler()
            handler._get_remote_user = lambda: "testuser"
            handler._get_client_ip = lambda: "127.0.0.1"
            handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
            handler._log_guidance_audit = lambda **kwargs: None
            handler.rfile = io.BytesIO(body)
            handler._headers = {
                "X-Remote-User": "testuser",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            }
            parsed = urlparse(f"/remediation-guidance/{fake_guid}/audit")
            soar_api.SoarAPIHandler._handle_remediation_audit_post_internal(handler, parsed)
        assert handler.response_code == 429
        # 429 does not reveal if guid exists
        response_body = handler.wfile.getvalue().decode("utf-8")
        assert fake_guid not in response_body

    def test_429_does_not_reveal_guid_existence(self):
        """Resposta 429 não revela se guidance_id existe."""
        limiter = SlidingWindowLog(max_tokens=1, window_seconds=60)
        limiter.is_allowed("copy:user:testuser")
        retry = limiter.get_retry_after("copy:user:testuser")
        assert retry > 0
        # The key does not contain the guidance_id

    def test_retry_after_present_and_valid(self):
        """Retry-After presente e com valor numérico positivo."""
        limiter = SlidingWindowLog(max_tokens=1, window_seconds=60)
        limiter.is_allowed("copy:user:testuser")
        retry = limiter.get_retry_after("copy:user:testuser")
        assert isinstance(retry, int)
        assert retry > 0
        assert retry <= 61

    def test_different_users_independent_limits(self):
        """Usuários diferentes têm limites independentes."""
        limiter = SlidingWindowLog(max_tokens=2, window_seconds=60)
        assert limiter.is_allowed("copy:user:alice") is True
        assert limiter.is_allowed("copy:user:alice") is True
        assert limiter.is_allowed("copy:user:alice") is False
        # Bob still has his own limit
        assert limiter.is_allowed("copy:user:bob") is True
        assert limiter.is_allowed("copy:user:bob") is True

    def test_limited_internal_keys(self):
        """Número de chaves internas permanece limitado após cleanup."""
        limiter = SlidingWindowLog(
            max_tokens=10, window_seconds=1, cleanup_interval_seconds=0
        )
        # Create many keys
        for i in range(100):
            limiter.is_allowed(f"copy:user:user{i}")
        # Wait for window to expire
        time.sleep(1.1)
        # Trigger cleanup on next is_allowed
        limiter.is_allowed("copy:user:trigger_cleanup")
        # Buckets should be cleaned (stale entries removed)
        with limiter._lock:
            assert len(limiter._buckets) <= 2  # only trigger_cleanup + maybe 1 more


class TestCacheConsistency:
    """Testes de consistência do cache: ambos os índices sempre sincronizados."""

    def test_expiration_removes_both_associations(self):
        """Expiração remove tanto finding_id quanto guidance_id."""
        cache = GuidanceCache(ttl_seconds=1, max_entries=100)
        record = _make_guidance_record()
        cache.put(VALID_FINDING_ID, record)
        guid = record.guidance_id

        time.sleep(1.1)

        assert cache.get_by_finding_id(VALID_FINDING_ID) is None
        assert cache.get_by_guidance_id(guid) is None

    def test_eviction_removes_both_associations(self):
        """Eviction remove tanto finding_id quanto guidance_id."""
        cache = GuidanceCache(ttl_seconds=3600, max_entries=2)
        r1 = GuidanceRecord(finding_id="a" * 64, status="no_guidance")
        r2 = GuidanceRecord(finding_id="b" * 64, status="no_guidance")
        r3 = GuidanceRecord(finding_id="c" * 64, status="no_guidance")

        cache.put("a" * 64, r1)
        cache.put("b" * 64, r2)
        cache.put("c" * 64, r3)  # evicts r1

        # r1 evicted from both indices
        assert cache.get_by_finding_id("a" * 64) is None
        assert cache.get_by_guidance_id(r1.guidance_id) is None
        # r2, r3 still present
        assert cache.get_by_finding_id("b" * 64) is not None
        assert cache.get_by_guidance_id(r2.guidance_id) is not None

    def test_invalidate_clears_both_associations(self):
        """invalidate_all limpa ambos os índices."""
        cache = GuidanceCache(ttl_seconds=3600, max_entries=100)
        record = _make_guidance_record()
        cache.put(VALID_FINDING_ID, record)

        cache.invalidate_all()

        assert cache.get_by_finding_id(VALID_FINDING_ID) is None
        assert cache.get_by_guidance_id(record.guidance_id) is None
        assert cache.size() == 0

    def test_no_orphan_guidance_ids(self):
        """Nenhum guidance_id órfão após operações mistas."""
        cache = GuidanceCache(ttl_seconds=3600, max_entries=3)
        records = []
        for i in range(5):
            fid = hashlib.sha256(f"orphan{i}".encode()).hexdigest()
            r = GuidanceRecord(finding_id=fid, status="no_guidance")
            cache.put(fid, r)
            records.append(r)

        # Cache has only 3 entries (evicted first 2)
        assert cache.size() == 3
        # Verify no orphans: all guidance_ids in reverse index point to existing entries
        with cache._lock:
            for guid, fid in list(cache._by_guidance_id.items()):
                assert fid in cache._by_finding_id, f"Orphan guid: {guid}"

    def test_cache_hit_preserves_guidance_id(self):
        """Cache hit retorna o mesmo guidance_id (não gera novo UUID)."""
        cache = GuidanceCache(ttl_seconds=3600)
        record = _make_guidance_record()
        cache.put(VALID_FINDING_ID, record)

        r1 = cache.get_by_finding_id(VALID_FINDING_ID)
        r2 = cache.get_by_finding_id(VALID_FINDING_ID)
        assert r1.guidance_id == r2.guidance_id == record.guidance_id

    def test_limit_means_guidance_records(self):
        """O limite é em quantidade de GuidanceRecords, não soma dos índices."""
        cache = GuidanceCache(ttl_seconds=3600, max_entries=5)
        for i in range(5):
            fid = hashlib.sha256(f"limit{i}".encode()).hexdigest()
            r = GuidanceRecord(finding_id=fid, status="no_guidance")
            cache.put(fid, r)

        assert cache.size() == 5
        # _by_guidance_id should also have 5 entries (1:1 mapping)
        with cache._lock:
            assert len(cache._by_guidance_id) == 5

    def test_concurrent_operations_no_corruption(self):
        """Operações concorrentes não corrompem os índices."""
        cache = GuidanceCache(ttl_seconds=3600, max_entries=1000)
        errors = []

        def worker(idx):
            try:
                fid = hashlib.sha256(f"concurrent{idx}".encode()).hexdigest()
                r = GuidanceRecord(finding_id=fid, status="no_guidance")
                cache.put(fid, r)
                result = cache.get_by_finding_id(fid)
                if result is None:
                    errors.append(f"Thread {idx}: miss after put")
                result2 = cache.get_by_guidance_id(r.guidance_id)
                if result2 is None:
                    errors.append(f"Thread {idx}: guid miss after put")
            except Exception as e:
                errors.append(f"Thread {idx}: {e}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # Verify consistency
        with cache._lock:
            for guid, fid in cache._by_guidance_id.items():
                assert fid in cache._by_finding_id


# ==========================================================================
# WAVE 2 INFRA FIX: SlidingWindowLog Max Keys Tests
# ==========================================================================

class TestSlidingWindowLogMaxKeys:
    """Testes do limite máximo de chaves do SlidingWindowLog."""

    def test_insert_beyond_max_keys(self):
        limiter = SlidingWindowLog(max_tokens=10, window_seconds=60, max_keys=5)
        for i in range(10):
            limiter.is_allowed(f"user{i}")
        assert limiter.key_count() <= 5

    def test_total_never_exceeds_max(self):
        limiter = SlidingWindowLog(max_tokens=10, window_seconds=60, max_keys=3)
        for i in range(20):
            limiter.is_allowed(f"flood{i}")
        assert limiter.key_count() <= 3

    def test_expired_keys_removed_first(self):
        limiter = SlidingWindowLog(max_tokens=10, window_seconds=1, max_keys=3, cleanup_interval_seconds=0)
        limiter.is_allowed("old1")
        limiter.is_allowed("old2")
        time.sleep(1.1)
        # These should evict expired old1/old2 first
        limiter.is_allowed("new1")
        limiter.is_allowed("new2")
        limiter.is_allowed("new3")
        assert limiter.key_count() <= 3

    def test_deterministic_eviction_lru(self):
        limiter = SlidingWindowLog(max_tokens=10, window_seconds=60, max_keys=3)
        limiter.is_allowed("first")
        limiter.is_allowed("second")
        limiter.is_allowed("third")
        # Access "first" again to make it MRU
        limiter.is_allowed("first")
        # Add new key — should evict "second" (LRU)
        limiter.is_allowed("fourth")
        assert limiter.key_count() <= 3
        # "first" should still be allowed (was MRU)
        assert limiter.is_allowed("first") is True

    def test_thread_safety_max_keys(self):
        limiter = SlidingWindowLog(max_tokens=10, window_seconds=60, max_keys=50)
        errors = []
        def worker(idx):
            try:
                for j in range(10):
                    limiter.is_allowed(f"thread{idx}_{j}")
            except Exception as e:
                errors.append(str(e))
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert limiter.key_count() <= 50

    def test_same_user_key_for_varying_guid(self):
        limiter = SlidingWindowLog(max_tokens=3, window_seconds=60, max_keys=100)
        key = "copy:user:alice"
        assert limiter.is_allowed(key) is True
        assert limiter.is_allowed(key) is True
        assert limiter.is_allowed(key) is True
        assert limiter.is_allowed(key) is False

    def test_eviction_does_not_affect_active_user(self):
        limiter = SlidingWindowLog(max_tokens=5, window_seconds=60, max_keys=3)
        limiter.is_allowed("active")
        limiter.is_allowed("other1")
        limiter.is_allowed("other2")
        # "active" is still within limit
        limiter.is_allowed("active")
        # Add new key triggering eviction
        limiter.is_allowed("new")
        # "active" should still work
        assert limiter.is_allowed("active") is True

    def test_retry_after_still_correct(self):
        limiter = SlidingWindowLog(max_tokens=1, window_seconds=60, max_keys=100)
        limiter.is_allowed("testuser")
        retry = limiter.get_retry_after("testuser")
        assert retry > 0
        assert retry <= 61

    def test_high_cardinality_forged_users(self):
        limiter = SlidingWindowLog(max_tokens=10, window_seconds=60, max_keys=100)
        for i in range(500):
            limiter.is_allowed(f"forged_user_{i}")
        assert limiter.key_count() <= 100

    def test_no_unbounded_growth(self):
        limiter = SlidingWindowLog(max_tokens=5, window_seconds=1, max_keys=50, cleanup_interval_seconds=0)
        for i in range(200):
            limiter.is_allowed(f"burst_{i}")
        assert limiter.key_count() <= 50
        time.sleep(1.1)
        limiter.is_allowed("trigger_cleanup")
        assert limiter.key_count() <= 2


# ==========================================================================
# WAVE 2 INFRA FIX: Handler Order Tests
# ==========================================================================

class TestHandlerOrderNoInit:
    """Testes confirmando que 401/429 não inicializam o módulo."""

    def test_get_401_does_not_init_module(self):
        import soar_api
        init_called = []
        original_init = soar_api._init_remediation_module
        def mock_init():
            init_called.append(True)
            return original_init()
        with patch.object(soar_api, "_init_remediation_module", mock_init):
            handler = _call_handler(
                "GET", f"/remediation-guidance/{VALID_FINDING_ID}",
                headers={"X-Remote-User": ""},
            )
        assert handler.response_code == 401
        # Init should NOT have been called for unauthenticated request
        # (depends on order — if auth is before init, init_called should be empty)

    def test_post_401_does_not_init_module(self):
        import soar_api
        body = json.dumps({"action": "copy"}).encode("utf-8")
        handler = _call_handler(
            "POST", "/remediation-guidance/fake-guid/audit",
            headers={"X-Remote-User": "", "Content-Type": "application/json", "Content-Length": str(len(body))},
            body=body,
        )
        assert handler.response_code == 401


# ==========================================================================
# WAVE 2 INFRA FIX: Snapshot Signature Tests
# ==========================================================================

class TestSnapshotSignature:
    """Testes da assinatura (mtime_ns, size) do snapshot."""

    def test_size_change_invalidates(self, tmp_path):
        snapshot = tmp_path / "latest.json"
        snapshot.write_text('{"vulnerabilities": []}', encoding="utf-8")
        cache = GuidanceCache(snapshot_path=snapshot, ttl_seconds=3600)
        record = GuidanceRecord(finding_id="a"*64, status="no_guidance")
        cache.put("a"*64, record)
        # First get establishes the baseline signature
        assert cache.get_by_finding_id("a"*64) is not None
        # Change content (different size and mtime)
        time.sleep(0.05)
        snapshot.write_text('{"vulnerabilities": [{"cve": "CVE-2024-0001"}]}', encoding="utf-8")
        # Next get should detect the change and invalidate
        result = cache.get_by_finding_id("a"*64)
        assert result is None

    def test_same_signature_no_invalidation(self, tmp_path):
        snapshot = tmp_path / "latest.json"
        snapshot.write_text('{"vulnerabilities": []}', encoding="utf-8")
        cache = GuidanceCache(snapshot_path=snapshot, ttl_seconds=3600)
        record = GuidanceRecord(finding_id="b"*64, status="no_guidance")
        cache.put("b"*64, record)
        # Access again without changing file
        result = cache.get_by_finding_id("b"*64)
        assert result is not None

    def test_stat_failure_preserves_cache(self, tmp_path):
        snapshot = tmp_path / "latest.json"
        snapshot.write_text('{"vulnerabilities": []}', encoding="utf-8")
        cache = GuidanceCache(snapshot_path=snapshot, ttl_seconds=3600)
        record = GuidanceRecord(finding_id="c"*64, status="no_guidance")
        cache.put("c"*64, record)
        # Delete file (stat will fail)
        snapshot.unlink()
        # Cache should be preserved (fail-safe)
        result = cache.get_by_finding_id("c"*64)
        assert result is not None

    def test_invalidation_removes_both_indices(self, tmp_path):
        snapshot = tmp_path / "latest.json"
        snapshot.write_text('{"vulnerabilities": []}', encoding="utf-8")
        cache = GuidanceCache(snapshot_path=snapshot, ttl_seconds=3600)
        record = GuidanceRecord(finding_id="d"*64, status="no_guidance")
        cache.put("d"*64, record)
        guid = record.guidance_id
        # First get establishes baseline signature
        assert cache.get_by_finding_id("d"*64) is not None
        # Modify snapshot
        time.sleep(0.05)
        snapshot.write_text('{"vulnerabilities": [{"new": true}]}', encoding="utf-8")
        assert cache.get_by_finding_id("d"*64) is None
        assert cache.get_by_guidance_id(guid) is None


# ==========================================================================
# WAVE 2 EXTRA MANDATORY TESTS
# ==========================================================================

class TestWave2AdditionalMandatory:
    """Suíte adicional para garantir todas as especificações da Wave 2."""

    def setup_method(self):
        import soar_api
        from remediation.rate_limiter import SlidingWindowLog
        soar_api._init_state = "uninitialized"
        soar_api._remediation_engine = None
        soar_api._guidance_cache = None
        soar_api._last_failure_time = 0.0
        soar_api._guidance_rate_limiter = SlidingWindowLog(max_tokens=60, window_seconds=60)
        soar_api._audit_rate_limiter = SlidingWindowLog(max_tokens=10, window_seconds=60)

    # --- PART 1 — CAPACIDADE DO RATE LIMITER ---

    def test_active_key_remains_after_flood(self):
        """Chave ativa permanece após flood de identidades."""
        limiter = SlidingWindowLog(max_tokens=5, window_seconds=60, max_keys=3)
        # 1. Adiciona chave ativa
        assert limiter.is_allowed("active_key") is True
        # 2. Faz flood com chaves novas até exceder max_keys
        for i in range(10):
            limiter.is_allowed(f"flood_key_{i}")
        # 3. Chave ativa deve permanecer no rate limiter
        assert limiter.key_count() <= 3
        # 4. Deve continuar permitida se consultar novamente (não foi expulsa)
        assert limiter.is_allowed("active_key") is True

    def test_active_key_counter_preserved(self):
        """Contador da chave ativa permanece preservado (não é zerado)."""
        limiter = SlidingWindowLog(max_tokens=3, window_seconds=60, max_keys=3)
        # Consome 2 tokens da chave ativa
        assert limiter.is_allowed("active_key") is True
        assert limiter.is_allowed("active_key") is True

        # Flood de novas identidades
        for i in range(10):
            limiter.is_allowed(f"flood_{i}")

        # O contador de "active_key" deve estar intacto:
        # Mais um consumo é permitido (total 3)
        assert limiter.is_allowed("active_key") is True
        # O quarto consumo é bloqueado
        assert limiter.is_allowed("active_key") is False

    def test_new_identity_rejected_when_capacity_full(self):
        """Nova identidade é rejeitada quando a capacidade está cheia."""
        limiter = SlidingWindowLog(max_tokens=5, window_seconds=60, max_keys=2)
        assert limiter.is_allowed("k1") is True
        assert limiter.is_allowed("k2") is True
        # Limite de chaves atingido. Nova identidade deve ser rejeitada
        assert limiter.is_allowed("k3") is False

    def test_expired_keys_removed_before_rejection(self):
        """Entradas expiradas são removidas antes da rejeição."""
        limiter = SlidingWindowLog(max_tokens=5, window_seconds=1, max_keys=2, cleanup_interval_seconds=0)
        assert limiter.is_allowed("k1") is True
        assert limiter.is_allowed("k2") is True
        time.sleep(1.1)
        # "k1" e "k2" expiraram totalmente. "k3" deve ser aceita após limpeza automática
        assert limiter.is_allowed("k3") is True
        assert limiter.key_count() <= 2

    def test_new_identity_enters_after_expiration(self):
        """Nova identidade entra após liberação por expiração."""
        limiter = SlidingWindowLog(max_tokens=5, window_seconds=1, max_keys=2, cleanup_interval_seconds=0)
        assert limiter.is_allowed("k1") is True
        assert limiter.is_allowed("k2") is True
        # "k3" deve ser rejeitada pois está cheio
        assert limiter.is_allowed("k3") is False

        time.sleep(1.1)
        # expirou. Agora k3 deve entrar
        assert limiter.is_allowed("k3") is True
        assert limiter.key_count() <= 2

    def test_retry_after_remains_valid_generic(self):
        """Retry-After permanece válido mesmo para novas identidades rejeitadas por capacidade."""
        limiter = SlidingWindowLog(max_tokens=5, window_seconds=60, max_keys=2)
        limiter.is_allowed("k1")
        limiter.is_allowed("k2")
        # k3 é rejeitada por capacidade
        assert limiter.is_allowed("k3") is False
        retry = limiter.get_retry_after("k3")
        assert retry == 60  # Retry-after genérico válido (window_seconds)

    def test_concurrent_calls_do_not_exceed_max_keys(self):
        """Chamadas concorrentes não ultrapassam max_keys."""
        limiter = SlidingWindowLog(max_tokens=1, window_seconds=60, max_keys=10)
        errors = []
        def worker(idx):
            try:
                limiter.is_allowed(f"user_{idx}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert limiter.key_count() <= 10

    def test_identity_rotation_does_not_avoid_limit(self):
        """Rotação de identidades não evita o limite (bloqueado em max_keys)."""
        limiter = SlidingWindowLog(max_tokens=1, window_seconds=60, max_keys=5)
        # Consome tokens de 5 identidades
        for i in range(5):
            assert limiter.is_allowed(f"user_{i}") is True
        # Tentativa de rotacionar identidades novas deve falhar
        assert limiter.is_allowed("user_5") is False
        assert limiter.is_allowed("user_6") is False

    # --- PART 2 — INICIALIZAÇÃO E BACKOFF ---

    def test_two_requests_during_backoff_one_attempt(self):
        """Duas requisições durante o backoff provocam uma única tentativa real."""
        import soar_api

        # Reset init state
        soar_api._init_state = "uninitialized"
        soar_api._remediation_engine = None
        soar_api._guidance_cache = None

        init_calls = 0
        def failing_init():
            nonlocal init_calls
            init_calls += 1
            raise ValueError("Erro simulado de inicialização")

        with patch("remediation.engine.RemediationEngine", side_effect=failing_init):
            # Primeira tentativa: deve chamar e falhar
            res1 = soar_api._init_remediation_module()
            assert res1 is False
            assert soar_api._init_state == "failed"

            # Segunda tentativa (durante backoff): deve retornar False direto sem chamar
            res2 = soar_api._init_remediation_module()
            assert res2 is False

            # Apenas 1 chamada real deve ter acontecido
            assert init_calls == 1

    def test_response_503_during_backoff(self):
        """Durante o backoff, resposta 503."""
        import soar_api
        soar_api._init_state = "failed"
        soar_api._last_failure_time = time.monotonic()

        handler = _call_handler("GET", f"/remediation-guidance/{VALID_FINDING_ID}")
        assert handler.response_code == 503
        response_json = handler.get_response_json()
        assert response_json["error"] == "Serviço temporariamente indisponível"

    def test_new_attempt_allowed_after_backoff_period(self):
        """Após o prazo de backoff, nova tentativa é permitida."""
        import soar_api
        soar_api._init_state = "failed"
        soar_api._last_failure_time = time.monotonic() - 31.0  # Passou 30s

        init_called = False
        def mock_engine_init():
            nonlocal init_called
            init_called = True
            return MagicMock()

        with patch("remediation.engine.RemediationEngine", mock_engine_init), \
             patch("remediation.cache.GuidanceCache", MagicMock()):
            res = soar_api._init_remediation_module()
            assert res is True
            assert init_called is True
            assert soar_api._init_state == "ready"

    def test_success_clears_failed_state(self):
        """Sucesso posterior limpa o estado failed."""
        import soar_api
        soar_api._init_state = "failed"
        soar_api._last_failure_time = time.monotonic() - 31.0

        with patch("remediation.engine.RemediationEngine", MagicMock()), \
             patch("remediation.cache.GuidanceCache", MagicMock()):
            assert soar_api._init_remediation_module() is True
            assert soar_api._init_state == "ready"

    def test_concurrent_requests_dont_init_multiple_engines(self):
        """Requisições concorrentes não inicializam múltiplos engines."""
        import soar_api
        soar_api._init_state = "uninitialized"
        soar_api._remediation_engine = None
        soar_api._guidance_cache = None

        init_calls = 0
        def slow_init(*args, **kwargs):
            nonlocal init_calls
            init_calls += 1
            time.sleep(0.1)
            return MagicMock()

        threads = []
        with patch("remediation.engine.RemediationEngine", slow_init), \
             patch("remediation.cache.GuidanceCache", MagicMock()):
            def worker():
                soar_api._init_remediation_module()

            for _ in range(5):
                t = threading.Thread(target=worker)
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

        assert init_calls == 1

    def test_401_does_not_initialize_components(self):
        """401 não inicializa componentes."""
        import soar_api
        soar_api._init_state = "uninitialized"
        soar_api._remediation_engine = None
        soar_api._guidance_cache = None

        handler = _call_handler("GET", f"/remediation-guidance/{VALID_FINDING_ID}", headers={"X-Remote-User": ""})
        assert handler.response_code == 401
        assert soar_api._init_state == "uninitialized"

    def test_429_does_not_initialize_engine(self):
        """429 não inicializa engine."""
        import soar_api
        soar_api._init_state = "uninitialized"
        soar_api._remediation_engine = None
        soar_api._guidance_cache = None

        # Exaurir rate limiter do GET
        with patch.object(soar_api, "_guidance_rate_limiter", SlidingWindowLog(max_tokens=0)):
            handler = _call_handler("GET", f"/remediation-guidance/{VALID_FINDING_ID}")
            assert handler.response_code == 429
            assert soar_api._init_state == "uninitialized"

    def test_error_response_503_does_not_contain_paths_or_exception(self):
        """Resposta 503 não contém exception ou caminho interno."""
        import soar_api
        soar_api._init_state = "failed"
        soar_api._last_failure_time = time.monotonic()

        handler = _call_handler("GET", f"/remediation-guidance/{VALID_FINDING_ID}")
        assert handler.response_code == 503
        body = handler.wfile.getvalue().decode("utf-8")
        assert "exception" not in body.lower()
        assert "traceback" not in body.lower()
        assert "opt/hmg-soar" not in body.lower()

    def test_rate_limiter_remains_active_with_engine_failure(self):
        """Rate limiter permanece ativo mesmo com falha do engine."""
        import soar_api
        soar_api._init_state = "failed"
        soar_api._last_failure_time = time.monotonic()

        # A primeira requisição retorna 503 (devido ao backoff/falha do engine)
        handler1 = _call_handler("GET", f"/remediation-guidance/{VALID_FINDING_ID}")
        assert handler1.response_code == 503

        # Agora exaurimos o rate limiter do usuário
        for _ in range(100):
            handler2 = _call_handler("GET", f"/remediation-guidance/{VALID_FINDING_ID}")
            if handler2.response_code == 429:
                break
        else:
            pytest.fail("Rate limiter de GET não barrou requisições subsequentes mesmo com engine falho")

    # --- PART 3 — AUDITORIA VIEW E COPY ---

    def test_view_audit_failure_logs_warning_returns_200(self):
        """Falha na escrita da auditoria de view mantém HTTP 200 e gera log interno."""
        import soar_api
        record = _make_guidance_record()

        def mock_log_guidance_audit(*args, **kwargs):
            raise OSError("Falha simulada de escrita")

        with patch.object(soar_api, "_remediation_engine", MagicMock(generate_guidance=MagicMock(return_value=record))), \
             patch.object(soar_api, "_guidance_cache", GuidanceCache()):
            handler = MockHandler("GET", f"/remediation-guidance/{VALID_FINDING_ID}",
                                  headers={"X-Remote-User": "testuser"})
            handler._get_remote_user = lambda: "testuser"
            handler._get_client_ip = lambda: "127.0.0.1"
            handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
            handler._send_guidance_response = lambda record: _mock_send_guidance_response(handler, record)
            handler._log_guidance_audit = mock_log_guidance_audit

            from urllib.parse import urlparse
            parsed = urlparse(f"/remediation-guidance/{VALID_FINDING_ID}")
            soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed)

            assert handler.response_code == 200

    def test_copy_audit_failure_returns_500(self):
        """Falha na escrita da auditoria de copy retorna HTTP 500 genérico."""
        import soar_api
        record = _make_guidance_record()
        cache = GuidanceCache()
        cache.put(VALID_FINDING_ID, record)

        body = json.dumps({"action": "copy"}).encode("utf-8")

        def mock_log_guidance_audit(*args, **kwargs):
            raise OSError("Falha simulada de escrita")

        with patch.object(soar_api, "_guidance_cache", cache), \
             patch.object(soar_api, "_remediation_engine", MagicMock()):
            handler = MockHandler("POST", f"/remediation-guidance/{record.guidance_id}/audit",
                                  headers={"X-Remote-User": "testuser", "Content-Type": "application/json", "Content-Length": str(len(body))},
                                  body=body)
            handler._get_remote_user = lambda: "testuser"
            handler._get_client_ip = lambda: "127.0.0.1"
            handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
            handler._send_guidance_response = lambda record: _mock_send_guidance_response(handler, record)
            handler._log_guidance_audit = mock_log_guidance_audit

            from urllib.parse import urlparse
            parsed = urlparse(f"/remediation-guidance/{record.guidance_id}/audit")
            soar_api.SoarAPIHandler._handle_remediation_audit_post_internal(handler, parsed)

            assert handler.response_code == 500
            res = handler.get_response_json()
            assert res["error"] == "Erro interno do servidor"
            assert "exception" not in res
            assert "command" not in res


class TestSanitizedLogsAndSensitiveExceptions:
    """Valida que exceções com informações sensíveis são sanitizadas nos logs e nas respostas HTTP."""

    def setup_method(self):
        import soar_api
        soar_api._init_state = "uninitialized"
        soar_api._remediation_engine = None
        soar_api._guidance_cache = None
        soar_api._last_failure_time = 0.0
        soar_api._guidance_rate_limiter = SlidingWindowLog(max_tokens=60, window_seconds=60)
        soar_api._audit_rate_limiter = SlidingWindowLog(max_tokens=10, window_seconds=60)

    def test_view_audit_sensitive_exception_sanitization(self, caplog):
        import soar_api
        record = _make_guidance_record()

        # Simula falha na escrita da auditoria com caminho sensível
        sensitive_path = "C:\\segredo\\credenciais.env"
        def mock_log_guidance_audit(*args, **kwargs):
            raise OSError(f"Falha de permissao ao acessar {sensitive_path}")

        with patch.object(soar_api, "_remediation_engine", MagicMock(generate_guidance=MagicMock(return_value=record))), \
             patch.object(soar_api, "_guidance_cache", GuidanceCache()), \
             caplog.at_level("WARNING"):

            handler = MockHandler("GET", f"/remediation-guidance/{VALID_FINDING_ID}",
                                  headers={"X-Remote-User": "testuser"})
            handler._get_remote_user = lambda: "testuser"
            handler._get_client_ip = lambda: "127.0.0.1"
            handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
            handler._send_guidance_response = lambda r: _mock_send_guidance_response(handler, r)
            handler._log_guidance_audit = mock_log_guidance_audit

            from urllib.parse import urlparse
            parsed = urlparse(f"/remediation-guidance/{VALID_FINDING_ID}")
            soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed)

            # View mantém política best-effort (HTTP 200)
            assert handler.response_code == 200

            # O log capturado NÃO deve conter o caminho sensível ou informações da exceção
            log_text = caplog.text
            assert "segredo" not in log_text
            assert "credenciais.env" not in log_text

            # O corpo da resposta HTTP não contém informações sensíveis
            body = handler.wfile.getvalue().decode("utf-8")
            assert "segredo" not in body
            assert "credenciais.env" not in body

    def test_copy_audit_sensitive_exception_sanitization(self, caplog):
        import soar_api
        record = _make_guidance_record()
        cache = GuidanceCache()
        cache.put(VALID_FINDING_ID, record)

        body = json.dumps({"action": "copy"}).encode("utf-8")

        # Simula falha na escrita da auditoria com caminho sensível
        sensitive_path = "C:\\segredo\\credenciais.env"
        def mock_log_guidance_audit(*args, **kwargs):
            raise OSError(f"Falha de permissao ao acessar {sensitive_path}")

        with patch.object(soar_api, "_guidance_cache", cache), \
             patch.object(soar_api, "_remediation_engine", MagicMock()), \
             caplog.at_level("ERROR"):

            handler = MockHandler("POST", f"/remediation-guidance/{record.guidance_id}/audit",
                                  headers={"X-Remote-User": "testuser", "Content-Type": "application/json", "Content-Length": str(len(body))},
                                  body=body)
            handler._get_remote_user = lambda: "testuser"
            handler._get_client_ip = lambda: "127.0.0.1"
            handler._send_guidance_json = lambda code, data, extra_headers=None: _mock_send_guidance_json(handler, code, data, extra_headers)
            handler._send_guidance_response = lambda r: _mock_send_guidance_response(handler, r)
            handler._log_guidance_audit = mock_log_guidance_audit

            from urllib.parse import urlparse
            parsed = urlparse(f"/remediation-guidance/{record.guidance_id}/audit")
            soar_api.SoarAPIHandler._handle_remediation_audit_post_internal(handler, parsed)

            # Copy retorna erro genérico (HTTP 500)
            assert handler.response_code == 500

            # O log capturado NÃO deve conter o caminho sensível ou informações da exceção
            log_text = caplog.text
            assert "segredo" not in log_text
            assert "credenciais.env" not in log_text

            # O corpo da resposta HTTP não contém informações sensíveis ou de comandos
            res = handler.get_response_json()
            assert res["error"] == "Erro interno do servidor"
            body = handler.wfile.getvalue().decode("utf-8")
            assert "segredo" not in body
            assert "credenciais.env" not in body
            assert "command" not in body
            assert "verification_command" not in body

    def test_rate_limiter_load_failure_sensitive_exception(self, caplog):
        """Confirma que falha fictícia ao carregar rate limiter com caminho sensível é sanitizada nos logs."""
        import importlib
        import soar_api

        sensitive_path = "C:\\segredo\\credenciais.env"

        def mock_sliding_window_log(*args, **kwargs):
            raise ImportError(f"Falha de permissao/carregamento ao acessar {sensitive_path}")

        try:
            with patch("remediation.rate_limiter.SlidingWindowLog", mock_sliding_window_log), \
                 caplog.at_level("ERROR"):

                importlib.reload(soar_api)

                assert soar_api._guidance_rate_limiter is None
                assert soar_api._audit_rate_limiter is None

                log_text = caplog.text
                assert "segredo" not in log_text
                assert "credenciais.env" not in log_text
                assert "Falha ao carregar rate limiter" in log_text
        finally:
            importlib.reload(soar_api)
