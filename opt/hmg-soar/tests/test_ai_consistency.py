"""AI explanations must agree with the deterministic engine (simulated HTTP only).

Reproduces the homologation case: Debian 13 (trixie), vim-tiny 2:9.1.1230-2,
no fixed version known to EyeMole, textual guidance with read-only
diagnostics and no correction command — and a model answer claiming that "the
plan contains a command validated by the EyeMole engine". The synthetic data
below is test input only; no rule in the code depends on this CVE or package.
"""
import datetime as dt
import json
import sys
from pathlib import Path

import pytest
from requests.structures import CaseInsensitiveDict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from operations import ai, llm  # noqa: E402
from operations.security import OperationError, principal  # noqa: E402
from operations.service import Operations, read_snapshot  # noqa: E402
from operations.store import Store  # noqa: E402
from operations.worker import process  # noqa: E402

SECRET = "fake-key-for-tests-not-a-credential-0123456789"
MODEL = "nvidia/nemotron-3-super-120b-a12b"
TEMPLATES = Path(__file__).resolve().parent.parent / "remediation" / "data" / "remediation_templates.json"
CONTRADICTION = ("O plano contém um comando validado pelo motor do EyeMole que atualiza o pacote; "
                 "aplique-o pelo processo de mudança.")


class FakeResponse:
    def __init__(self, body):
        self.status_code = 200
        self.headers = CaseInsensitiveDict({"Content-Type": "application/json"})
        self._raw = json.dumps(body).encode()

    def iter_content(self, size):
        yield self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeSession:
    def __init__(self, contents):
        self.contents = list(contents)
        self.calls = []
        self.trust_env = True

    def request(self, method, url, **kwargs):
        self.calls.append(kwargs)
        message = {"role": "assistant", "content": self.contents.pop(0)}
        return FakeResponse({"model": MODEL, "choices": [{"index": 0, "message": message, "finish_reason": "stop"}]})


def reply(fid, explanation, claims=None, summary=None):
    item = {"finding_id": fid, "evidence_ids": ["plan:" + fid], "explanation": explanation}
    if claims is not None:
        item["claims"] = claims
    return json.dumps({"summary": summary or "Explicação da orientação do motor.", "recommendations": [item]},
                      ensure_ascii=False)


def row(**overrides):
    base = {"agent_id": "007", "agent_name": "srv-debian.corp.internal", "cve": "CVE-2026-73076", "package": "vim-tiny",
            "version": "2:9.1.1230-2", "operating_system": "Debian GNU/Linux", "os_version": "13",
            "package_type": "deb", "package_architecture": "amd64", "severity": "High", "epss": None, "is_kev": False}
    base.update(overrides)
    return base


@pytest.fixture
def platform(tmp_path):
    path = tmp_path / "latest.json"
    rows = [row(),
            # Separate synthetic installation whose sources report a fixed version → validated command.
            row(agent_id="008", cve="CVE-2026-00001", package="libexemplo", version="1.0-1",
                fixed_version="1.0-2", scanner_condition="Package less than 1.0-2")]
    generated = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat()
    path.write_text(json.dumps({"metadata": {"generated_at": generated, "agents_analyzed": ["007", "008"],
                                             "collection": {"complete": True}}, "vulnerabilities": rows}))
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    cfg = {"enabled": True,
           "projects": {"hmg": {"snapshot_path": str(path), "config_dir": str(config_dir),
                                "templates_path": str(TEMPLATES), "grype_snapshot_path": str(tmp_path / "grype.json"),
                                "integrations": {"ai": {"enabled": True, "provider": "nvidia", "model": MODEL}}}},
           "users": {"admin": {"role": "admin", "projects": ["*"]}}}
    store = Store(tmp_path / "state" / "operations.sqlite3")
    service = Operations(store, cfg, principal(cfg, "admin"))
    _, instances, _ = read_snapshot(cfg["projects"]["hmg"])
    by_package = {r["package"]: fid for fid, r in instances.items()}
    return service, cfg, by_package["vim-tiny"], by_package["libexemplo"]


def run(service, cfg, content):
    session = FakeSession([content])
    original = llm.new_session
    llm.new_session = lambda: session
    try:
        job = service.store.claim()
        try:
            service.store.finish(job["id"], result=process(service.store, cfg, job, {"NVIDIA_API_KEY": SECRET}))
        except OperationError as exc:
            service.store.finish(job["id"], error=str(exc))
    finally:
        llm.new_session = original
    return session


def guidance(cfg, fid):
    from operations.planning import engine_for
    return engine_for(cfg["projects"]["hmg"]).generate_guidance(fid).to_dict()


def claims_for(cfg, fid):
    from operations import ai_facts
    facts = ai_facts.engine_facts(guidance(cfg, fid))
    return {key: facts[key] for key in ai_facts.CLAIM_KEYS}


# ----------------------------------------------------------------------
# Reproduction: fails on the previous code, where the answer was stored.
# ----------------------------------------------------------------------

def test_reported_case_contradictory_answer_is_not_stored_or_shown(platform):
    service, cfg, vim, _ = platform
    plan = guidance(cfg, vim)
    assert plan["guidance_kind"] == "textual" and "command" not in plan and "fixed_version" not in plan
    assert plan["diagnostics"]  # read-only diagnostics exist, but no correction command
    service.queue_finding_ai("hmg", vim)
    run(service, cfg, reply(vim, CONTRADICTION))
    assert service.store.list("hmg", "ai_finding") == []
    assert service.store.jobs("hmg")[0]["state"] == "failed"
    state = service.finding_ai("hmg", vim)
    assert state["state"] == "failed" and "summary" not in state
    # The deterministic guidance is unchanged.
    assert {k: v for k, v in guidance(cfg, vim).items() if k not in {"guidance_id", "generation_date"}} == \
        {k: v for k, v in plan.items() if k not in {"guidance_id", "generation_date"}}


# ----------------------------------------------------------------------
# Payload: separated commands/diagnostics and engine-owned facts
# ----------------------------------------------------------------------

def test_textual_guidance_payload_separates_diagnostics_from_correction(platform):
    service, cfg, vim, _ = platform
    service.queue_finding_ai("hmg", vim)
    session = run(service, cfg, reply(vim, "As fontes do EyeMole não informaram a versão corrigida.", claims_for(cfg, vim)))
    messages = json.loads(session.calls[0]["data"])["messages"]
    assert "contém um comando validado" not in messages[0]["content"]
    sent = messages[1]["content"]
    facts = json.loads(sent)["facts"][0]
    engine = facts["engine_facts"]
    assert engine["correction_command_available"] is False
    assert engine["verification_command_available"] is False
    assert engine["read_only_diagnostics"] == ["Versão instalada", "Candidate disponível no repositório"]
    assert engine["fixed_version"] is None and engine["fix_state"] == "insufficient_data"
    # Missing fixed_version is "not determined", never "no fix published"; the repository is not observed.
    assert engine["fix_publication"] == "not_determined" and engine["repository_availability"] == "not_observed"
    assert "fixed_version" in engine["missing_context"]
    assert any("dados insuficientes, não que a correção inexista" in s for s in facts["engine_statements"])
    for forbidden in ("dpkg-query", "apt-cache", "srv-debian", '"agent_id"'):
        assert forbidden not in sent, forbidden


def test_diagnostics_never_make_the_correction_flag_true():
    from operations import ai_facts
    plan = {"finding_id": "c" * 64, "status": "textual_guidance", "guidance_kind": "textual",
            "diagnostics": [{"label": "Versão instalada", "script": "dpkg-query -W pkg", "shell": "bash"}]}
    assert ai_facts.engine_facts(plan)["correction_command_available"] is False
    # Even a command string is ignored when the engine did not validate it (status/kind).
    for inconsistent in (dict(plan, command="sudo apt-get install pkg"),
                         dict(plan, status="success", command="sudo apt-get install pkg")):
        assert ai_facts.engine_facts(inconsistent)["correction_command_available"] is False
    confirmed = dict(plan, status="success", guidance_kind="command", command="sudo apt-get install pkg",
                     verification_command="dpkg-query -W pkg", fixed_version="1.0-2")
    facts = ai_facts.engine_facts(confirmed)
    assert facts["correction_command_available"] and facts["verification_command_available"]
    assert facts["fix_state"] == "validated_command" and facts["fix_publication"] == "reported_by_sources"
    assert facts["read_only_diagnostics"] == ["Versão instalada"]
    fixed_only = dict(plan, fixed_version="1.0-2")
    assert ai_facts.engine_facts(fixed_only)["fix_state"] == "fixed_version_without_command"


# ----------------------------------------------------------------------
# Contradictions are rejected (claims and prose); consistent answers stored
# ----------------------------------------------------------------------

@pytest.mark.parametrize("explanation,claims_override", [
    (CONTRADICTION, None),
    ("Execute este comando de correção em homologação.", None),
    ("Não há correção publicada pelo Debian para esta CVE.", None),
    ("A correção já está disponível no repositório do ativo.", None),
    ("A versão corrigida é 2:9.1.1230-3.", None),
    ("As fontes do EyeMole não informaram a versão corrigida.", {"correction_command_available": True}),
    ("As fontes do EyeMole não informaram a versão corrigida.", {"fixed_version": "2:9.1.1230-3"}),
    ("As fontes do EyeMole não informaram a versão corrigida.", {"fix_state": "validated_command"}),
])
def test_contradictory_answer_is_rejected(platform, explanation, claims_override):
    service, cfg, vim, _ = platform
    claims = dict(claims_for(cfg, vim), **(claims_override or {}))
    service.queue_finding_ai("hmg", vim)
    run(service, cfg, reply(vim, explanation, claims))
    job = service.store.jobs("hmg")[0]
    assert job["state"] == "failed" and "contradiz os fatos do motor" in job["error"]
    assert service.store.list("hmg", "ai_finding") == []


def test_consistent_textual_answer_is_stored_with_engine_facts(platform):
    service, cfg, vim, _ = platform
    text = (f"Para {vim}, o motor não gerou comando de correção. As fontes do EyeMole não informaram a versão "
            "corrigida para 2:9.1.1230-2, o que é falta de dados. Use os diagnósticos somente leitura e verifique "
            "se o repositório configurado oferece versão corrigida.")
    service.queue_finding_ai("hmg", vim)
    run(service, cfg, reply(vim, text, claims_for(cfg, vim)))
    state = service.finding_ai("hmg", vim)
    assert state["state"] == "succeeded"
    recommendation = state["recommendations"][0]
    # The opaque finding_id never is the main text: replaced by package (CVE).
    assert vim not in recommendation["explanation"] and "vim-tiny (CVE-2026-73076)" in recommendation["explanation"]
    assert recommendation["subject"] == {"package": "vim-tiny", "cve": "CVE-2026-73076", "installed_version": "2:9.1.1230-2"}
    assert state["engine_facts"]["correction_command_available"] is False
    assert any("não gerou comando de correção" in s for s in state["engine_facts"]["statements"])


def test_confirmed_command_answer_is_accepted_and_denial_rejected(platform):
    service, cfg, _, lib = platform
    plan = guidance(cfg, lib)
    assert plan["status"] == "success" and plan["guidance_kind"] == "command" and plan["fixed_version"] == "1.0-2"
    claims = claims_for(cfg, lib)
    assert claims == {"correction_command_available": True, "fixed_version": "1.0-2", "fix_state": "validated_command"}
    service.queue_finding_ai("hmg", lib)
    run(service, cfg, reply(lib, "Não há comando de correção para esta instalação.", claims))
    assert service.store.jobs("hmg")[0]["state"] == "failed"
    service.queue_finding_ai("hmg", lib)
    run(service, cfg, reply(lib, "O plano contém um comando de correção validado pelo motor, que leva a 1.0-2.", claims))
    state = service.finding_ai("hmg", lib)
    assert state["state"] == "succeeded" and state["engine_facts"]["fix_state"] == "validated_command"


def test_kiro_answers_go_through_the_same_consistency_check(platform):
    from operations import ai_contract, ai_facts
    _, cfg, vim, _ = platform
    plan = guidance(cfg, vim)
    contract_valid = ai_contract.validate_response(json.loads(reply(vim, CONTRADICTION)), {"plan:" + vim}, {vim}, "Kiro")
    with pytest.raises(ai_contract.AIContractError) as exc:
        ai_facts.enforce(contract_valid, [plan], "Kiro", require_claims=False)
    assert exc.value.code == "contradicts_engine"


# ----------------------------------------------------------------------
# Old explanations: invalidated, never deleted
# ----------------------------------------------------------------------

def test_previous_contract_explanations_are_invalidated_but_kept(platform):
    import hashlib
    service, cfg, vim, _ = platform
    _, rows, revision = read_snapshot(cfg["projects"]["hmg"])
    plan = guidance(cfg, vim)
    legacy_id = f"finding:007:{vim}:{plan['snapshot_revision']}:{ai.provider_key(cfg['projects']['hmg'])}"
    old = {"finding_id": vim, "snapshot_revision": revision, "summary": CONTRADICTION,
           "recommendations": [{"finding_id": vim, "evidence_ids": [], "explanation": CONTRADICTION}]}
    service.store.put("hmg", "ai_finding", hashlib.sha256(legacy_id.encode()).hexdigest(), old, "worker", "ai.finding_explained")
    audit_before = len(service.store.audit_entries("hmg"))

    state = service.finding_ai("hmg", vim)
    assert state["state"] == "stale" and state["invalidated"] is True
    assert "summary" not in state and CONTRADICTION not in json.dumps(state, ensure_ascii=False)
    assert len(service.store.list("hmg", "ai_finding")) == 1  # record kept
    assert len(service.store.audit_entries("hmg")) == audit_before  # audit untouched

    # Campaign explanation from the previous contract: shown as invalidated, stored record unchanged.
    c = service.create_campaign("hmg", {"name": "vim", "owner": "Equipe", "revision": revision, "finding_ids": [vim]})
    stored = service.store.get("hmg", "campaign", c["id"])
    stored["ai_explanation"] = {"provider": "nvidia", "provider_label": "NVIDIA", "model": MODEL, "summary": CONTRADICTION,
                                "recommendations": [], "plans_hash": "x", "evidence_hash": "y", "generated_at": "2026-10-10"}
    service.store.put("hmg", "campaign", c["id"], stored, "worker", "ai.explained", stored["version"])
    shown = next(x for x in service.overview("hmg")["campaigns"] if x["id"] == c["id"])["ai_explanation"]
    assert shown["invalidated"] is True and shown["current"] is False and "summary" not in shown
    assert service.store.get("hmg", "campaign", c["id"])["ai_explanation"]["summary"] == CONTRADICTION


# ----------------------------------------------------------------------
# Interface
# ----------------------------------------------------------------------

def test_interface_has_no_this_command_message_without_correction_command():
    import analyserV1
    tpl = analyserV1.HTML_TEMPLATE
    static = tpl[tpl.index('id="guidance-command-disclaimer"'):]
    static = static[:static.index("</span>")]
    assert "este comando" not in static
    render = tpl[tpl.index("function renderGuidanceContent"):tpl.index("const GUIDANCE_KIND_LABELS")]
    assert "showsCorrection\n        ? 'O EyeMole não executa este comando." in render
    assert "Nenhum comando de correção validado para esta instalação." in render
    block = tpl[tpl.index("function renderGuidanceAiFacts"):tpl.index("async function loadGuidanceAi")]
    assert "innerHTML" not in block and "guidanceAiSubject(r)" in block
    js = (Path(__file__).resolve().parent.parent / "assets" / "operations.js").read_text(encoding="utf-8")
    assert "Instância: " not in js and "e.invalidated" in js and "Fatos do motor" in js
