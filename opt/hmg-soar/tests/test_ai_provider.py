"""NVIDIA (OpenAI-compatible) AI explanations with simulated HTTP.

Covers transport limits and failures, response contract, data minimization,
secret handling, instance binding, staleness and operation without Kiro.
No real network call is made; the real NVIDIA endpoint is not exercised here.
"""
import datetime as dt
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import requests
from requests.structures import CaseInsensitiveDict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "cli"))

from operations import ai, ai_check, api, llm
from operations.ai_contract import AIContractError, parse_message_content, validate_response
from operations.security import OperationError, principal
from operations.planning import engine_for
from operations.service import Operations, read_snapshot
from operations.store import Store
from operations.worker import process

SECRET = "fake-key-for-tests-not-a-credential-0123456789"
MODEL = "nvidia/nemotron-3-super-120b-a12b"


# ----------------------------------------------------------------------
# Simulated transport
# ----------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status=200, body=None, headers=None, raw=None):
        self.status_code = status
        self.headers = CaseInsensitiveDict(headers or {"Content-Type": "application/json"})
        if raw is None:
            raw = json.dumps(body if body is not None else {}).encode()
        self._raw = raw

    def iter_content(self, size):
        for i in range(0, len(self._raw), size):
            yield self._raw[i:i + size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeSession:
    def __init__(self, responses, on_request=None):
        self.responses = list(responses)
        self.calls = []
        self.trust_env = True
        self.on_request = on_request

    def request(self, method, url, **kwargs):
        self.calls.append(dict(kwargs, method=method, url=url))
        if self.on_request:
            self.on_request(len(self.calls))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def completion(content, finish="stop", tool_calls=None, model=MODEL):
    message = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return FakeResponse(200, {"id": "x", "model": model, "choices": [{"index": 0, "message": message, "finish_reason": finish}]})


def answer(finding, evidence, explanation="A instalação usa a versão 1.0; falta a versão corrigida, então não há correção específica confirmada."):
    return json.dumps({"summary": "Contexto insuficiente para correção específica.",
                       "recommendations": [{"finding_id": finding, "evidence_ids": evidence, "explanation": explanation}]},
                      ensure_ascii=False)


FID = "a" * 64
PLAN = {
    "finding_id": FID, "cve": "CVE-2026-12345", "package_name": "openssl", "installed_version": "2.4.10.1-1ubuntu1",
    "fixed_version": None, "operating_system": "ubuntu", "os_version": "22.04", "architecture": "amd64",
    "package_manager": "apt", "status": "no_guidance", "guidance_kind": "textual", "confidence": "low",
    "command": "sudo apt-get install --only-upgrade openssl", "verification_command": "dpkg-query -W openssl",
    "agent_id": "001", "agent_name": "db-prod-01.corp.internal", "hostname": "db-prod-01.corp.internal",
    "rationale": "Coletado em 10.20.30.40 por admin@empresa.example; versão corrigida ausente.",
    "warnings": ["Agente 10.20.30.40 sem package.type"], "missing_context": ["vendor_fix_evidence"],
    "diagnostics": [{"label": "x", "script": "Get-ItemProperty secret-path", "shell": "powershell"}],
    "sources": [{"label": "Advisory oficial", "url": "https://ubuntu.com/security/CVE-2026-12345", "kind": "vendor_advisory"}],
}
CFG = {"integrations": {"ai": {"enabled": True, "provider": "nvidia", "model": MODEL}}}


def client(responses, sleep=None, clock=None, **overrides):
    settings = llm.resolve_settings(dict(CFG["integrations"]["ai"], **overrides))
    session = FakeSession(responses)
    kwargs = {"session": session, "sleep": sleep or (lambda s: None)}
    if clock:
        kwargs["clock"] = clock
    return llm.ChatCompletionsClient(settings, SECRET, **kwargs), session


MESSAGES = [{"role": "user", "content": "x"}]


# ----------------------------------------------------------------------
# Transport: success, failures, limits
# ----------------------------------------------------------------------

def test_success_uses_configured_official_endpoint_and_minimal_payload():
    session = FakeSession([completion(answer(FID, ["plan:" + FID, "source:" + FID + ":0"]))])
    result = ai.explain_plans([PLAN], CFG, {"NVIDIA_API_KEY": SECRET}, session=session)

    assert result["provider"] == "nvidia" and result["model"] == MODEL
    assert result["recommendations"][0]["finding_id"] == FID
    call = session.calls[0]
    assert call["url"] == "https://integrate.api.nvidia.com/v1/chat/completions"
    assert call["allow_redirects"] is False and call["verify"] is True
    assert call["headers"]["Authorization"] == "Bearer " + SECRET
    assert session.trust_env is False
    body = json.loads(call["data"])
    assert body["model"] == MODEL and body["stream"] is False
    assert body["chat_template_kwargs"] == {"enable_thinking": False}
    assert (body["temperature"], body["top_p"]) == (1.0, 0.95)
    sent = json.dumps(body["messages"], ensure_ascii=False)
    # Minimization: asset identity, addresses, users, commands and scripts never leave the server.
    for forbidden in ("db-prod-01", "corp.internal", "10.20.30.40", "admin@empresa", '"agent_id"', "agent_name",
                      "sudo apt-get", "dpkg-query", "Get-ItemProperty", SECRET):
        assert forbidden not in sent, forbidden
    facts = json.loads(body["messages"][1]["content"])["facts"][0]
    assert facts["installed_version"] == "2.4.10.1-1ubuntu1"  # version is not mistaken for an IP
    assert facts["validated_command_available"] is True and facts["fixed_version"] is None
    assert "[redigido]" in facts["rationale"]


def test_auth_failure_is_not_retried_and_hides_the_key():
    c, session = client([FakeResponse(401, {"detail": "bad key " + SECRET})])
    with pytest.raises(llm.AIProviderError) as exc:
        c.complete(MESSAGES)
    assert exc.value.code == "auth_failed" and len(session.calls) == 1
    assert SECRET not in str(exc.value) and "bad key" not in str(exc.value)


def test_429_honors_retry_after_within_budget():
    waits = []
    c, session = client([FakeResponse(429, headers={"Retry-After": "2", "Content-Type": "application/json"}),
                         completion("{}")], sleep=waits.append)
    assert c.complete(MESSAGES)[0] == "{}"
    assert waits == [2.0] and len(session.calls) == 2


def test_429_retry_after_beyond_budget_fails_without_waiting():
    waits = []
    c, session = client([FakeResponse(429, headers={"Retry-After": "600"})], sleep=waits.append)
    with pytest.raises(llm.AIProviderError) as exc:
        c.complete(MESSAGES)
    assert exc.value.code == "rate_limited" and exc.value.status == 429
    assert waits == [] and len(session.calls) == 1


def test_timeouts_are_retried_a_limited_number_of_times():
    waits = []
    c, session = client([requests.Timeout(), requests.Timeout(), requests.Timeout()], sleep=waits.append)
    with pytest.raises(llm.AIProviderError) as exc:
        c.complete(MESSAGES)
    assert exc.value.code == "timeout" and len(session.calls) == llm.MAX_ATTEMPTS
    assert len(waits) == llm.MAX_ATTEMPTS - 1 and all(w <= llm.MAX_RETRY_WAIT_SECONDS for w in waits)


def test_total_time_budget_bounds_retries():
    now = [0.0]
    c, session = client([FakeResponse(503), FakeResponse(503), FakeResponse(503)],
                        sleep=lambda s: now.__setitem__(0, now[0] + s), clock=lambda: now[0], timeout_seconds=15)
    now[0] = 0.0
    session.on_request = lambda n: now.__setitem__(0, now[0] + 13)  # each call consumes most of the budget
    with pytest.raises(llm.AIProviderError) as exc:
        c.complete(MESSAGES)
    assert exc.value.code == "provider_unavailable" and len(session.calls) == 1


@pytest.mark.parametrize("status,code", [(500, "provider_unavailable"), (502, "provider_unavailable"),
                                         (404, "model_unavailable"), (400, "request_rejected"), (418, "provider_error")])
def test_provider_errors_are_classified(status, code):
    c, _ = client([FakeResponse(status)] * llm.MAX_ATTEMPTS)
    with pytest.raises(llm.AIProviderError) as exc:
        c.complete(MESSAGES)
    assert exc.value.code == code


def test_transient_5xx_recovers_on_retry():
    c, session = client([FakeResponse(503), completion("ok")])
    assert c.complete(MESSAGES)[0] == "ok" and len(session.calls) == 2


def test_oversized_response_is_rejected():
    c, _ = client([FakeResponse(200, raw=b"{" + b" " * (300 * 1024) + b"}")])
    with pytest.raises(llm.AIProviderError) as exc:
        c.complete(MESSAGES)
    assert exc.value.code == "response_too_large"


def test_redirect_is_refused_so_key_never_reaches_another_host():
    c, session = client([FakeResponse(302, headers={"Location": "https://attacker.example/v1"})])
    with pytest.raises(llm.AIProviderError) as exc:
        c.complete(MESSAGES)
    assert exc.value.code == "redirect_refused"
    assert [call["url"] for call in session.calls] == ["https://integrate.api.nvidia.com/v1/chat/completions"]


@pytest.mark.parametrize("message", [
    {"content": "x", "tool_calls": [{"type": "function", "function": {"name": "run", "arguments": "{}"}}]},
])
def test_tool_calls_are_rejected(message):
    c, _ = client([completion(message["content"], tool_calls=message["tool_calls"])])
    with pytest.raises(llm.AIProviderError) as exc:
        c.complete(MESSAGES)
    assert exc.value.code == "tool_call_rejected"


def test_truncated_and_empty_answers_are_rejected():
    c, _ = client([completion("{", finish="length")])
    with pytest.raises(llm.AIProviderError, match="truncada"):
        c.complete(MESSAGES)
    c, _ = client([completion("   ")])
    with pytest.raises(llm.AIProviderError, match="vazia"):
        c.complete(MESSAGES)


def test_missing_key_fails_before_any_request():
    settings = llm.resolve_settings(CFG["integrations"]["ai"])
    with pytest.raises(llm.AIProviderError) as exc:
        llm.ChatCompletionsClient(settings, "", session=FakeSession([]))
    assert exc.value.code == "missing_credentials"


@pytest.mark.parametrize("base_url", ["http://integrate.api.nvidia.com/v1", "https://evil.example/v1",
                                      "https://user:pw@integrate.api.nvidia.com/v1", "https://integrate.api.nvidia.com:8443/v1",
                                      "https://integrate.api.nvidia.com/v1?x=1", "https://integrate.api.nvidia.com/other"])
def test_endpoint_must_match_administrative_allowlist(base_url):
    with pytest.raises(OperationError):
        llm.resolve_settings({"provider": "nvidia", "base_url": base_url})


def test_unknown_provider_and_invalid_model_are_rejected():
    with pytest.raises(OperationError):
        llm.resolve_settings({"provider": "other-company"})
    with pytest.raises(OperationError):
        llm.resolve_settings({"provider": "nvidia", "model": "bad model; rm -rf"})


# ----------------------------------------------------------------------
# Response contract
# ----------------------------------------------------------------------

EVID = {"plan:" + FID}


@pytest.mark.parametrize("content,code", [
    ("não é json", "invalid_json"),
    (answer("b" * 64, ["plan:" + FID]), "unknown_reference"),
    (answer(FID, ["source:invented"]), "unknown_reference"),
    (json.dumps({"summary": "x", "recommendations": [], "command": "sudo apt-get upgrade"}), "invalid_response"),
    (answer(FID, ["plan:" + FID], "Execute:\nsudo apt-get install --only-upgrade openssl"), "command_in_text"),
    (answer(FID, ["plan:" + FID], "Use ```bash\napt-get upgrade\n```"), "command_in_text"),
    (answer(FID, ["plan:" + FID], "Rode `apt-get install openssl` agora."), "command_in_text"),
    (json.dumps({"summary": "x", "recommendations": [{"finding_id": FID, "evidence_ids": [], "explanation": "x", "execute": True}]}),
     "invalid_response"),
])
def test_contract_rejects_invalid_or_invented_content(content, code):
    with pytest.raises(AIContractError) as exc:
        parse_message_content(content, EVID, {FID}, "NVIDIA")
    assert exc.value.code == code


def test_contract_accepts_fenced_json_and_prose_mentioning_package_managers():
    text = "<think>rascunho</think>\n```json\n" + answer(FID, ["plan:" + FID],
                                                            "O plano usa o gerenciador apt e contém um comando validado pelo motor.") + "\n```"
    result = parse_message_content(text, EVID, {FID}, "NVIDIA")
    assert result["recommendations"][0]["evidence_ids"] == ["plan:" + FID]


def test_kiro_legacy_contract_is_the_shared_contract():
    from operations.kiro import validate_response as kiro_validate
    with pytest.raises(OperationError):
        kiro_validate({"summary": "ok", "recommendations": [], "command": "x"}, set(), set())
    assert validate_response({"summary": "ok", "recommendations": []}, set(), set())["summary"] == "ok"


# ----------------------------------------------------------------------
# Provider selection and compatibility
# ----------------------------------------------------------------------

def test_works_without_kiro_and_legacy_kiro_config_is_preserved():
    assert ai.selection(CFG)[0] == "http"
    status = ai.public_status(CFG)
    assert status == {"provider": "nvidia", "provider_label": "NVIDIA", "model": MODEL, "enabled": True}
    legacy = {"integrations": {"kiro": {"enabled": True, "binary": "/usr/local/bin/kiro-cli"}}}
    assert ai.selection(legacy)[0] == "kiro"
    assert ai.public_status(legacy)["provider_label"] == "Kiro (legado)"
    assert ai.public_status({"integrations": {"ai": {"enabled": False}, "kiro": {"enabled": True}}})["enabled"] is False
    assert ai.public_status({})["enabled"] is False


def test_public_status_never_exposes_endpoint_or_secret_name():
    text = json.dumps(ai.public_status(dict(CFG, secret_prefix="HMG_")))
    assert "integrate.api" not in text and "NVIDIA_API_KEY" not in text


def test_secret_prefix_has_no_fallback():
    cfg = {"secret_prefix": "HMG_"}
    assert ai.scoped_secrets(cfg, {"NVIDIA_API_KEY": "global", "HMG_NVIDIA_API_KEY": "hmg"}) == {"NVIDIA_API_KEY": "hmg"}
    assert ai.scoped_secrets(cfg, {"NVIDIA_API_KEY": "global"}) == {}


# ----------------------------------------------------------------------
# Jobs: campaigns and single installations ("Ver correção")
# ----------------------------------------------------------------------

def date(offset=0):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=offset)).isoformat()


@pytest.fixture
def platform(tmp_path, monkeypatch):
    path = tmp_path / "latest.json"
    rows = [{"agent_id": "001", "cve": "CVE-2026-12345", "package": "openssl", "version": version,
             "operating_system": "Ubuntu", "severity": "critical", "package_type": "deb", "package_architecture": "amd64",
             "agent_name": "db-prod-01.corp.internal", "epss": None, "is_kev": True} for version in ("1.0", "1.1")]
    rows.append(dict(rows[0], agent_id="002"))
    path.write_text(json.dumps({"metadata": {"generated_at": date(-60), "agents_analyzed": ["001", "002"],
                                             "collection": {"complete": True}}, "vulnerabilities": rows}))
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    cfg = {"enabled": True,
           "projects": {"hmg": {"snapshot_path": str(path), "config_dir": str(config_dir),
                                "grype_snapshot_path": str(tmp_path / "grype.json"),
                                "integrations": {"ai": {"enabled": True, "provider": "nvidia", "model": MODEL}}}},
           "users": {"admin": {"role": "admin", "projects": ["*"]},
                     "owner": {"role": "owner", "projects": ["hmg"], "agent_ids": ["001"]},
                     "auditor": {"role": "auditor", "projects": ["hmg"]}}}
    store = Store(tmp_path / "state" / "operations.sqlite3")
    service = Operations(store, cfg, principal(cfg, "admin"))
    _, instances, _ = read_snapshot(cfg["projects"]["hmg"])
    ids = sorted(instances, key=lambda i: (instances[i]["agent_id"], instances[i]["version"]))
    return service, cfg, path, ids


def run_job(service, cfg, responses, secrets=None, on_request=None):
    """Mirror worker.main: failures are recorded as failed, never as completed."""
    session = FakeSession(responses, on_request)
    original = llm.new_session
    llm.new_session = lambda: session
    try:
        job = service.store.claim()
        try:
            result = process(service.store, cfg, job, secrets if secrets is not None else {"NVIDIA_API_KEY": SECRET})
            service.store.finish(job["id"], result=result)
        except OperationError as exc:
            service.store.finish(job["id"], error=str(exc))
        return job, session
    finally:
        llm.new_session = original


def test_finding_explanation_is_bound_to_one_installation(platform, caplog):
    service, cfg, path, (fid_10, fid_11, fid_other_agent) = platform
    assert service.finding_ai("hmg", fid_10)["state"] == "none"
    service.queue_finding_ai("hmg", fid_10)
    assert service.finding_ai("hmg", fid_10)["state"] == "queued"

    caplog.set_level(logging.DEBUG)
    job, session = run_job(service, cfg, [completion(answer(fid_10, ["plan:" + fid_10]))])
    done = service.finding_ai("hmg", fid_10)
    assert done["state"] == "succeeded" and done["provider_label"] == "NVIDIA" and done["model"] == MODEL
    assert done["recommendations"][0]["finding_id"] == fid_10
    # Same CVE, other version or other asset: never reused.
    assert service.finding_ai("hmg", fid_11)["state"] == "none"
    assert service.finding_ai("hmg", fid_other_agent)["state"] == "none"
    sent = session.calls[0]["data"].decode()
    assert "db-prod-01" not in sent and '"agent_id"' not in sent
    # The key never reaches logs, job records, stored results or API answers.
    stored = Path(service.store.path).read_bytes()
    for text in (caplog.text, json.dumps(service.store.jobs("hmg")), json.dumps(done)):
        assert SECRET not in text
    assert SECRET.encode() not in stored


def test_failed_generation_is_not_recorded_as_completed(platform):
    service, cfg, _, (fid, _, _) = platform
    service.queue_finding_ai("hmg", fid)
    run_job(service, cfg, [FakeResponse(401)])
    state = service.finding_ai("hmg", fid)
    assert state["state"] == "failed" and "autenticação" in state["error"]
    assert service.store.jobs("hmg")[0]["state"] == "failed"
    assert service.store.list("hmg", "ai_finding") == []


def test_result_outdated_during_generation_is_rejected(platform):
    service, cfg, path, (fid, _, _) = platform
    service.queue_finding_ai("hmg", fid)
    data = json.loads(path.read_text())

    def change_snapshot(_):
        data["metadata"]["generated_at"] = date()
        path.write_text(json.dumps(data))

    run_job(service, cfg, [completion(answer(fid, ["plan:" + fid]))], on_request=change_snapshot)
    assert service.store.list("hmg", "ai_finding") == []
    assert service.store.jobs("hmg")[0]["state"] == "failed"
    assert "mudaram" in service.store.jobs("hmg")[0]["error"]


def test_model_change_makes_previous_explanation_not_current(platform):
    service, cfg, _, (fid, _, _) = platform
    service.queue_finding_ai("hmg", fid)
    run_job(service, cfg, [completion(answer(fid, ["plan:" + fid]))])
    assert service.finding_ai("hmg", fid)["state"] == "succeeded"
    cfg["projects"]["hmg"]["integrations"]["ai"]["model"] = "nvidia/another-model"
    assert service.finding_ai("hmg", fid)["state"] == "none"


def test_scope_and_permissions_are_preserved(platform):
    service, cfg, _, (fid_001, _, fid_002) = platform
    owner = Operations(service.store, cfg, principal(cfg, "owner"))
    with pytest.raises(OperationError) as exc:
        owner.queue_finding_ai("hmg", fid_002)
    assert exc.value.status == 403
    owner.queue_finding_ai("hmg", fid_001)
    auditor = Operations(service.store, cfg, principal(cfg, "auditor"))
    with pytest.raises(OperationError):
        auditor.queue_finding_ai("hmg", fid_001)
    jobs = service.store.jobs("hmg")
    assert all(api.job_visible(j, set(), principal(cfg, "owner")) for j in jobs)
    hidden = dict(jobs[0], object_id=jobs[0]["object_id"].replace("finding:001:", "finding:002:"))
    assert not api.job_visible(hidden, set(), principal(cfg, "owner"))


def rewrite(path, data):
    """Replace a source file with a signature guaranteed to differ (coarse mtime clocks)."""
    previous = path.stat().st_mtime_ns if path.exists() else 0
    path.write_text(json.dumps(data))
    os.utime(path, ns=(previous + 5_000_000_000, previous + 5_000_000_000))


def test_cached_engine_never_serves_a_replaced_snapshot(platform):
    service, cfg, path, (fid, _, _) = platform
    project = cfg["projects"]["hmg"]
    engine = engine_for(project)
    assert engine_for(project) is engine
    assert engine_for(dict(project, snapshot_path=str(path) + ".other")) is not engine
    before = engine.generate_guidance(fid).snapshot_revision
    data = json.loads(path.read_text())
    data["metadata"]["generated_at"] = date()
    rewrite(path, data)
    assert engine_for(project).generate_guidance(fid).snapshot_revision != before


def comparable(record):
    data = record.to_dict()
    for volatile in ("guidance_id", "generation_date"):
        data.pop(volatile, None)
    return data


def test_cached_engine_is_safe_under_concurrent_requests(platform):
    _, cfg, _, ids = platform
    project = cfg["projects"]["hmg"]
    expected = {fid: comparable(engine_for(project).generate_guidance(fid)) for fid in ids}
    engines = set()

    def request(fid):
        engine = engine_for(project)
        engines.add(id(engine))
        return fid, comparable(engine.generate_guidance(fid))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(request, ids * 16))
    assert len(engines) == 1
    # Each answer belongs to the instance requested and matches a serial generation.
    assert all(result == expected[fid] and result["finding_id"] == fid for fid, result in results)


def test_cached_engine_isolates_projects_and_installations(platform, tmp_path):
    service, cfg, path, (fid, fid_other_version, _) = platform
    other_snapshot = tmp_path / "other" / "latest.json"
    other_snapshot.parent.mkdir()
    data = json.loads(path.read_text())
    data["vulnerabilities"] = [dict(data["vulnerabilities"][0], version="9.9")]
    other_snapshot.write_text(json.dumps(data))
    cfg["projects"]["dev"] = dict(cfg["projects"]["hmg"], snapshot_path=str(other_snapshot),
                                  config_dir=str(tmp_path / "other"))
    hmg, dev = engine_for(cfg["projects"]["hmg"]), engine_for(cfg["projects"]["dev"])
    assert hmg is not dev
    assert hmg.generate_guidance(fid).installed_version == "1.0"
    assert hmg.generate_guidance(fid_other_version).installed_version == "1.1"
    # An instance of one project is not served by another project's engine or API.
    assert dev.generate_guidance(fid).status == "not_found"
    with pytest.raises(OperationError) as exc:
        service.finding_ai("dev", fid)
    assert exc.value.status == 404
    # Mutating a returned record never leaks into the next request.
    record = hmg.generate_guidance(fid)
    record.warnings.append("alterado pelo chamador")
    record.missing_context.append("alterado")
    assert "alterado pelo chamador" not in hmg.generate_guidance(fid).warnings


def test_cached_engine_follows_configuration_and_evidence_changes(platform, tmp_path):
    service, cfg, path, (fid, _, _) = platform
    project = cfg["projects"]["hmg"]
    project["evidence_path"] = str(tmp_path / "evidence.json")
    config_dir = Path(project["config_dir"])
    grype = Path(project["grype_snapshot_path"])
    grype.write_text(json.dumps({
        "metadata": {"agents": {"001": {"last_success_at": date(-3 * 3600)}}},
        "vulnerabilities": [{"cve": "CVE-2026-12345", "agent_id": "001", "package_name": "openssl",
                             "installed_version": "1.0", "fixed_version": "1.2", "fixed_versions": ["1.2"],
                             "status": "fixed", "confidence": "high", "match_type": "exact-direct-match", "purl": ""}]}))

    def providers(max_age):
        return {"providers": [{"name": "wazuh_snapshot", "enabled": True},
                              {"name": "grype_snapshot", "enabled": True, "max_scan_age_hours": max_age}]}

    rewrite(config_dir / "remediation_providers.json", providers(24))
    rewrite(tmp_path / "evidence.json", {"entries": []})
    engine = engine_for(project)
    fresh = engine.generate_guidance(fid)
    assert not any("não confirmada pelo scanner Grype" in w for w in fresh.warnings)
    service.queue_finding_ai("hmg", fid)
    run_job(service, cfg, [completion(answer(fid, ["plan:" + fid]))])
    assert service.finding_ai("hmg", fid)["state"] == "succeeded"

    # Configuration change: the same cached engine applies the new Grype age limit.
    rewrite(config_dir / "remediation_providers.json", providers(1))
    expired = engine_for(project).generate_guidance(fid)
    assert engine_for(project) is engine
    assert any("não confirmada pelo scanner Grype" in w for w in expired.warnings)
    assert expired.snapshot_revision != fresh.snapshot_revision
    assert service.finding_ai("hmg", fid)["state"] != "succeeded"

    # Evidence change: new revision, previous explanation no longer current.
    before = engine.generate_guidance(fid).snapshot_revision
    rewrite(tmp_path / "evidence.json", {"entries": [], "updated": True})
    assert engine.generate_guidance(fid).snapshot_revision != before


@pytest.mark.parametrize("failure", [
    [FakeResponse(429, headers={"Retry-After": "1", "Content-Type": "application/json"})] * 3,
    [requests.Timeout()] * 3,
    [requests.ConnectionError()] * 3,
    [FakeResponse(503)] * 3,
    "missing_key",
])
def test_nvidia_failure_keeps_deterministic_guidance_without_kiro(platform, monkeypatch, failure):
    from operations import worker
    monkeypatch.setattr(worker, "explain", lambda *a, **k: pytest.fail("Kiro não deve ser usado"))
    waits = []
    monkeypatch.setattr(llm.ChatCompletionsClient.__init__, "__defaults__", (None, llm.time.monotonic, waits.append))
    service, cfg, _, (fid, _, _) = platform
    project = cfg["projects"]["hmg"]
    guidance = comparable(engine_for(project).generate_guidance(fid))
    service.queue_finding_ai("hmg", fid)
    if failure == "missing_key":
        run_job(service, cfg, [], secrets={})
    else:
        run_job(service, cfg, failure)
    state = service.finding_ai("hmg", fid)
    assert state["state"] == "failed" and state["error"]
    assert service.store.list("hmg", "ai_finding") == []
    # The deterministic guidance (status, rationale, validated command) is unaffected.
    assert comparable(engine_for(project).generate_guidance(fid)) == guidance
    cfg["projects"]["hmg"]["integrations"] = {}
    assert comparable(engine_for(project).generate_guidance(fid)) == guidance
    assert service.finding_ai("hmg", fid)["enabled"] is False


def test_disabled_ai_is_reported_and_not_queued(platform):
    service, cfg, _, (fid, _, _) = platform
    cfg["projects"]["hmg"]["integrations"]["ai"]["enabled"] = False
    assert service.finding_ai("hmg", fid)["enabled"] is False
    with pytest.raises(OperationError) as exc:
        service.queue_finding_ai("hmg", fid)
    assert exc.value.status == 503


def test_campaign_explanation_without_kiro_and_invalidated_by_new_plans(platform, monkeypatch):
    service, cfg, _, ids = platform
    from operations import worker
    monkeypatch.setattr(worker, "explain", lambda *a, **k: pytest.fail("Kiro não deve ser usado"))
    _, rows, revision = read_snapshot(cfg["projects"]["hmg"])
    c = service.create_campaign("hmg", {"name": "OpenSSL", "owner": "Equipe", "revision": revision, "finding_ids": ids})
    plans = [{"finding_id": i, "agent_id": rows[i]["agent_id"], "cve": rows[i]["cve"], "package": "openssl",
              "installed_version": rows[i]["version"], "status": "no_guidance", "missing_context": ["fixed_version"]} for i in ids]
    service.save_plans("hmg", c["id"], plans, revision, "admin")
    c = service.get_campaign("hmg", c["id"])
    service.queue("hmg", c["id"], "kiro", {})  # rota antiga → job de IA
    assert service.store.jobs("hmg")[0]["kind"] == "ai"
    content = json.dumps({"summary": "Faltam versões corrigidas.", "recommendations": [
        {"finding_id": i, "evidence_ids": ["plan:" + i], "explanation": "Sem versão corrigida confirmada."} for i in ids]})
    run_job(service, cfg, [completion(content)], secrets={"NVIDIA_API_KEY": SECRET})
    stored = service.get_campaign("hmg", c["id"])["ai_explanation"]
    assert stored["provider"] == "nvidia" and stored["model"] == MODEL and stored["plans_hash"] == ai.digest(plans)
    assert service.overview("hmg")["campaigns"][0]["ai_explanation"]["current"] is True
    service.save_plans("hmg", c["id"], plans, revision, "admin")
    assert "ai_explanation" not in service.get_campaign("hmg", c["id"])


def test_campaign_explanation_rejected_when_plans_change_meanwhile(platform):
    service, cfg, _, ids = platform
    _, rows, revision = read_snapshot(cfg["projects"]["hmg"])
    c = service.create_campaign("hmg", {"name": "OpenSSL", "owner": "Equipe", "revision": revision, "finding_ids": ids[:1]})
    plans = [{"finding_id": ids[0], "package": "openssl", "status": "no_guidance"}]
    service.save_plans("hmg", c["id"], plans, revision, "admin")
    service.queue("hmg", c["id"], "ai", {})
    content = answer(ids[0], ["plan:" + ids[0]])
    run_job(service, cfg, [completion(content)],
            on_request=lambda n: service.save_plans("hmg", c["id"], plans + [dict(plans[0], status="changed")], revision, "admin"))
    assert "ai_explanation" not in service.get_campaign("hmg", c["id"])
    assert service.store.jobs("hmg")[0]["state"] == "failed"


def test_campaign_ai_requires_plans(platform):
    service, cfg, _, ids = platform
    _, _, revision = read_snapshot(cfg["projects"]["hmg"])
    c = service.create_campaign("hmg", {"name": "x", "owner": "y", "revision": revision, "finding_ids": ids[:1]})
    with pytest.raises(OperationError, match="planos"):
        service.queue("hmg", c["id"], "ai", {})


# ----------------------------------------------------------------------
# Connection check, administration and interface
# ----------------------------------------------------------------------

def test_ai_check_uses_synthetic_data_and_never_prints_the_key(monkeypatch, capsys):
    session = FakeSession([completion(answer("0" * 64, ["plan:" + "0" * 64]))])
    monkeypatch.setattr(llm, "new_session", lambda: session)
    monkeypatch.setattr(ai_check, "load_config", lambda: {"projects": {"hmg": CFG}})
    monkeypatch.setenv("NVIDIA_API_KEY", SECRET)
    assert ai_check.main(["--project", "hmg"]) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["ok"] is True and SECRET not in output
    assert "pacote-exemplo" in session.calls[0]["data"].decode()


def test_ai_check_reports_failure_without_secret(monkeypatch, capsys):
    monkeypatch.setattr(llm, "new_session", lambda: FakeSession([FakeResponse(403)]))
    monkeypatch.setattr(ai_check, "load_config", lambda: {"projects": {"hmg": CFG}})
    monkeypatch.setenv("NVIDIA_API_KEY", SECRET)
    assert ai_check.main(["--project", "hmg"]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["code"] == "auth_failed" and SECRET not in json.dumps(output)


def test_cli_ai_check_runs_with_the_worker_identity_and_secrets_file(monkeypatch, capsys):
    import eyemole
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return type("Done", (), {"stdout": '{"ok": false, "code": "missing_key"}\n', "stderr": "", "returncode": 1})()

    monkeypatch.setattr(eyemole.subprocess, "run", fake_run)
    assert eyemole.ai_check("hmg") == 1
    argv = calls[0]
    properties = {argv[i + 1].split("=", 1)[0]: argv[i + 1].split("=", 1)[1] for i, a in enumerate(argv) if a == "-p"}
    unit = {}
    root = Path(__file__).resolve().parents[3]
    for line in (root / "systemd" / "eyemole-platform-worker.service").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            unit[key] = value
    assert f"--uid={unit['User']}" in argv and f"--gid={unit['Group']}" in argv
    for key in ("SupplementaryGroups", "EnvironmentFile", "WorkingDirectory", "RestrictAddressFamilies",
                "CapabilityBoundingSet", "ProtectSystem"):
        assert properties[key] == unit[key], key
    assert argv[argv.index("-m") - 1] == unit["ExecStart"].split()[0]
    with pytest.raises(eyemole.UpdateError):
        eyemole.ai_check("hmg; rm -rf /")


def test_configure_ai_preserves_existing_configuration(tmp_path, monkeypatch):
    import administration
    monkeypatch.setattr(administration.os, "chown", lambda *a: None, raising=False)
    path = tmp_path / "platform.json"
    original = {"enabled": True, "users": {"admin": {"role": "admin", "projects": ["*"]}},
                "projects": {"hmg": {"secret_prefix": "HMG_", "integrations": {"kiro": {"enabled": True}}}, "dev": {}}}
    path.write_text(json.dumps(original))
    result = administration.configure_ai("hmg", "nvidia", None, True, None, path=path)
    data = json.loads(path.read_text())
    assert result["secret"] == "HMG_NVIDIA_API_KEY" and result["enabled"] is True
    assert data["projects"]["hmg"]["integrations"]["kiro"] == {"enabled": True}
    assert data["projects"]["hmg"]["integrations"]["ai"]["base_url"] == "https://integrate.api.nvidia.com/v1"
    assert data["users"] == original["users"] and data["projects"]["dev"] == {}
    administration.configure_ai("hmg", "nvidia", "nvidia/outro-modelo", None, None, path=path)
    block = json.loads(path.read_text())["projects"]["hmg"]["integrations"]["ai"]
    assert block["model"] == "nvidia/outro-modelo" and block["enabled"] is True
    assert "NVIDIA_API_KEY" not in path.read_text().replace("HMG_NVIDIA_API_KEY", "")
    with pytest.raises(administration.RecoveryError):
        administration.configure_ai("hmg", "nvidia", "x; rm -rf /", None, None, path=path)


def test_interface_uses_ai_terms_and_safe_rendering():
    root = Path(__file__).resolve().parent.parent
    js = (root / "assets" / "operations.js").read_text(encoding="utf-8")
    assert "Explicar com IA" in js and "Kiro" not in js.replace("Explicação por IA (legado)", "")
    assert "escapeText(e.summary)" in js and "escapeText(r.explanation)" in js
    import analyserV1
    tpl = analyserV1.HTML_TEMPLATE
    assert 'id="guidance-ai-section"' in tpl and "loadGuidanceAi(record.finding_id, activeGuidanceRequestId);" in tpl
    block = tpl[tpl.index("async function refreshGuidanceAi"):tpl.index("async function loadGuidanceAi")]
    assert "innerHTML" not in block and "textContent = data.summary" in block
    assert "Não substitui o comando validado" in tpl
