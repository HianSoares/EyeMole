"""Remediation research ("Pesquisar correção") with recorded and synthetic source fixtures.

Regressions: Debian 13 (trixie), installed 2:9.1.1230-2, CVE-2026-73076 in
vim-tiny and CVE-2026-73072 in vim. The Debian tracker pages and GitHub
advisories under fixtures/research were recorded from the official sources;
the other scenarios use synthetic pages in the same format. No production rule
depends on these CVEs, packages or versions. No real network call is made.
"""
import datetime as dt
import json
import sys
from pathlib import Path

import pytest
import requests
from requests.structures import CaseInsensitiveDict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from operations import diagnostics, llm, research, research_sources  # noqa: E402
from operations.security import OperationError, principal  # noqa: E402
from operations.service import Operations, read_snapshot  # noqa: E402
from operations.store import Store  # noqa: E402
from operations.worker import process  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "research"
TEMPLATES = Path(__file__).resolve().parent.parent / "remediation" / "data" / "remediation_templates.json"
SECRET = "fake-key-for-tests-not-a-credential-0123456789"
MODEL = "nvidia/nemotron-3-super-120b-a12b"
INSTALLED = "2:9.1.1230-2"
DSA = "2:9.1.1230-2+deb13u1"  # synthetic distribution fix used only in synthetic pages


class Response:
    def __init__(self, status, body=b"", headers=None):
        self.status_code = status
        self.headers = CaseInsensitiveDict(headers or {"Content-Type": "application/json"})
        self._body = body if isinstance(body, bytes) else body.encode()

    def iter_content(self, size):
        for i in range(0, len(self._body), size):
            yield self._body[i:i + size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Sources:
    """Routes the allowlisted source URLs to fixtures; anything else is a test failure."""

    def __init__(self, routes, proposal=None):
        self.routes = dict(routes)
        self.calls = []
        self.proposal = proposal
        self.trust_env = True

    def request(self, method, url, **kwargs):
        self.calls.append(dict(kwargs, method=method, url=url))
        assert kwargs.get("allow_redirects") is False
        if url.startswith("https://integrate.api.nvidia.com/"):
            content = self.proposal if isinstance(self.proposal, str) else json.dumps(self.proposal, ensure_ascii=False)
            return Response(200, json.dumps({"model": MODEL, "choices": [{"index": 0, "finish_reason": "stop",
                                                                          "message": {"role": "assistant", "content": content}}]}))
        route = self.routes.get(url)
        if route is None:
            raise AssertionError("unexpected request " + url)
        if isinstance(route, Exception):
            raise route
        return route() if callable(route) else route


def debian_page(cve, status_rows, fixed_rows, notes=""):
    """Synthetic page in the security-tracker.debian.org format (see the recorded fixtures)."""
    status = "".join(f"<tr><td>{p}</td><td>{r}</td><td>{v}</td><td>{s}</td></tr>" for p, r, v, s in status_rows)
    fixed = "".join(f"<tr><td>{p}</td><td>source</td><td>{r}</td><td>{v}</td><td>{u}</td><td></td><td></td></tr>"
                    for p, r, v, u in fixed_rows)
    return Response(200, f"<html><body><h1>{cve}</h1><table><tr><td><b>Name</b></td><td>{cve}</td></tr></table>"
                         f"<table><tr><th>Source Package</th><th>Release</th><th>Version</th><th>Status</th></tr>{status}</table>"
                         f"<table><tr><th>Package</th><th>Type</th><th>Release</th><th>Fixed Version</th><th>Urgency</th>"
                         f"<th>Origin</th><th>Debian Bugs</th></tr>{fixed}</table><pre>{notes}</pre></body></html>",
                    {"Content-Type": "text/html"})


def recorded(name, ctype="application/json"):
    return lambda: Response(200, (FIXTURES / name).read_bytes(), {"Content-Type": ctype})


DEBIAN = "https://security-tracker.debian.org/tracker/"
GHSA_76 = "https://api.github.com/repos/vim/vim/security-advisories/GHSA-r22p-fhw4-84p2"
GHSA_72 = "https://api.github.com/repos/vim/vim/security-advisories/GHSA-9jqx-hgpr-6v64"
RECORDED = {DEBIAN + "CVE-2026-73076": recorded("debian_CVE-2026-73076.html", "text/html"),
            DEBIAN + "CVE-2026-73072": recorded("debian_CVE-2026-73072.html", "text/html"),
            GHSA_76: recorded("github_GHSA-r22p-fhw4-84p2.json"), GHSA_72: recorded("github_GHSA-9jqx-hgpr-6v64.json")}


def row(agent, cve, package, version=INSTALLED):
    return {"agent_id": agent, "agent_name": f"srv-{agent}.corp.internal", "cve": cve, "package": package,
            "version": version, "operating_system": "Debian GNU/Linux", "os_version": "13", "package_type": "deb",
            "package_architecture": "amd64", "severity": "High", "epss": None, "is_kev": False}


@pytest.fixture
def platform(tmp_path):
    path = tmp_path / "latest.json"
    rows = [row("007", "CVE-2026-73076", "vim-tiny"), row("007", "CVE-2026-73072", "vim"),
            row("008", "CVE-2026-73076", "vim-tiny")]
    generated = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat()
    path.write_text(json.dumps({"metadata": {"generated_at": generated, "agents_analyzed": ["007", "008"],
                                             "collection": {"complete": True}}, "vulnerabilities": rows}))
    (tmp_path / "config").mkdir()
    cfg = {"enabled": True,
           "projects": {"hmg": {"snapshot_path": str(path), "config_dir": str(tmp_path / "config"),
                                "templates_path": str(TEMPLATES), "grype_snapshot_path": str(tmp_path / "grype.json"),
                                "integrations": {"research": {"enabled": True, "cache_dir": str(tmp_path / "cache")}}}},
           "users": {"admin": {"role": "admin", "projects": ["*"]},
                     "owner": {"role": "owner", "projects": ["hmg"], "agent_ids": ["008"]}}}
    store = Store(tmp_path / "state" / "operations.sqlite3")
    service = Operations(store, cfg, principal(cfg, "admin"))
    _, instances, _ = read_snapshot(cfg["projects"]["hmg"])
    ids = {(r["agent_id"], r["cve"]): fid for fid, r in instances.items()}
    return service, cfg, ids


def enable_ai(cfg):
    cfg["projects"]["hmg"]["integrations"]["ai"] = {"enabled": True, "provider": "nvidia", "model": MODEL}


def run(service, cfg, fid, routes=None, proposal=None, monkeypatch=None):
    service.queue_research("hmg", fid)
    sources = Sources(routes if routes is not None else RECORDED, proposal)
    job = service.store.claim()
    original = (research_sources.new_session, llm.new_session)
    research_sources.new_session = llm.new_session = lambda: sources
    try:
        service.store.finish(job["id"], result=process(service.store, cfg, job, {"NVIDIA_API_KEY": SECRET}))
    except OperationError as exc:
        service.store.finish(job["id"], error=str(exc))
    finally:
        research_sources.new_session, llm.new_session = original
    return service.research_state("hmg", fid), sources


def import_diag(service, fid, **outputs):
    body = {"collected_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    body.update(outputs)
    return service.import_diagnostics("hmg", fid, body)


POLICY = """vim-tiny:
  Installed: {installed}
  Candidate: {candidate}
  Version table:
     {candidate} 500
        500 http://mirror.corp.internal/debian-security trixie-security/main amd64 Packages
 *** {installed} 500
        500 http://mirror.corp.internal/debian trixie/main amd64 Packages
        100 /var/lib/dpkg/status
"""
DPKG = "vim-tiny 2:9.1.1230-2 vim 2:9.1.1230-2\n"


# ----------------------------------------------------------------------
# Regressions: recorded official data (Debian 13 has no fix; upstream and sid do)
# ----------------------------------------------------------------------

def test_vim_tiny_missing_fixed_version_starts_research_and_reports_upstream_only(platform):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    assert service.research_state("hmg", fid)["state"] == "none"  # Wazuh has no fixed_version: research is offered
    state, sources = run(service, cfg, fid)
    result = state["result"]
    assert state["state"] == "succeeded" and result["classification"] == "upstream_fix_only"
    assessment = result["assessment"]
    assert assessment["distribution_fixed_version"] is None and assessment["distribution_status"] == "vulnerable"
    assert [u["version"] for u in assessment["upstream_fixed_versions"]] == ["9.2.0847"]
    # sid/forky fixes are reported but never taken as a fix for trixie.
    assert {f["release"] for f in assessment["other_release_fixes"]} >= {"sid"}
    assert any("não confirma pacote adequado para trixie" in n for n in assessment["notes"])
    assert not any(a["kind"] == "update_package" for a in result["alternatives"])
    # Binary → source association is not deduced from the name.
    assert result["context"]["source_package"] is None and assessment["source_association"] == "unverified"
    assert any("pacote fonte" in p for p in result["pending_verifications"])
    # Evidence provenance.
    evidence = {e["id"]: e for e in result["evidence"]}
    trixie = evidence["debian:CVE-2026-73076:status:1:trixie"]
    assert trixie["url"] == DEBIAN + "CVE-2026-73076" and trixie["publisher"] == "Debian Security Tracker"
    assert trixie["release"] == "trixie" and trixie["source_package"] == "vim" and trixie["version"] == INSTALLED
    assert len(trixie["content_sha256"]) == 64 and trixie["retrieved_at"] and trixie["excerpt"]
    assert evidence["upstream:GHSA-r22p-fhw4-84p2:0"]["publisher"] == "vim/vim (GitHub Security Advisory)"
    assert [c["url"] for c in sources.calls] == [DEBIAN + "CVE-2026-73076", GHSA_76]


def test_vim_73072_with_wazuh_inventory_source_mapping(platform):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73072")]
    inventory = {"observed_at": "2026-10-13T10:00:00+00:00", "source": "wazuh_api", "agent_ids": ["007"],
                 "os": {"codename": "trixie", "name": "Debian GNU/Linux"}, "packages": {"vim": INSTALLED},
                 "package_details": {"vim": [{"version": INSTALLED, "architecture": "amd64", "source": "vim"}]}}
    service.store.put("hmg", "inventory", "007", inventory, "worker", "inventory.collected")
    state, _ = run(service, cfg, fid)
    result = state["result"]
    assert result["classification"] == "upstream_fix_only"
    assert result["context"]["source_package"] == "vim"
    assert result["context"]["origins"]["source_package"]["origin"] == "wazuh_syscollector"
    assert result["context"]["origins"]["release"]["origin"] == "wazuh_syscollector"
    assert [u["version"] for u in result["assessment"]["upstream_fixed_versions"]] == ["9.2.0846"]


def test_imported_dpkg_maps_vim_tiny_to_source_vim(platform):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    imported = import_diag(service, fid, dpkg_query=DPKG,
                           os_release='ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n')
    assert imported["confidence"] == "imported_by_analyst" and "raw" not in imported
    state, _ = run(service, cfg, fid)
    context = state["result"]["context"]
    assert context["source_package"] == "vim" and context["origins"]["source_package"]["origin"] == "imported_by_analyst"
    assert state["result"]["assessment"]["source_association"] == "verified"
    assert state["result"]["classification"] == "upstream_fix_only"


# ----------------------------------------------------------------------
# Synthetic scenarios (same format as the official page)
# ----------------------------------------------------------------------

def with_distribution_fix(fixed_rows, status_rows=None):
    routes = dict(RECORDED)
    routes[DEBIAN + "CVE-2026-73076"] = lambda: debian_page(
        "CVE-2026-73076", status_rows or [("vim", "trixie", INSTALLED, "vulnerable"), ("", "trixie (security)", DSA, "fixed")],
        fixed_rows)
    return routes


def test_distribution_fix_with_fixing_candidate_is_validated(platform):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    import_diag(service, fid, dpkg_query=DPKG, apt_cache_policy=POLICY.format(installed=INSTALLED, candidate=DSA))
    state, _ = run(service, cfg, fid, with_distribution_fix([("vim", "trixie", DSA, "")]))
    result = state["result"]
    assert result["classification"] == "validated_fix"
    best = result["alternatives"][result["recommended"]]
    assert best["kind"] == "update_package" and best["validated"] is True and best["target_version"] == DSA
    assert best["command"] == f"sudo apt-get install --only-upgrade -- vim-tiny={DSA}"
    assert any(f"esperado: {DSA}" in v for v in best["verification"])
    # Debian rules: +deb13u1 is newer than the installed revision.
    assert research._cmp(DSA, INSTALLED) > 0
    # Repository URLs (internal mirror) are not kept in parsed data or results.
    assert "mirror.corp.internal" not in json.dumps(result)
    assert result["context"]["repository"]["candidate_suites"] == ["trixie-security/main"]


def test_candidate_not_fixed_requires_verification(platform):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    import_diag(service, fid, dpkg_query=DPKG, apt_cache_policy=POLICY.format(installed=INSTALLED, candidate=INSTALLED)
                .replace(f"     {INSTALLED} 500\n        500 http://mirror.corp.internal/debian-security trixie-security/main amd64 Packages\n", ""))
    state, _ = run(service, cfg, fid, with_distribution_fix([("vim", "trixie", DSA, "")]))
    result = state["result"]
    assert result["classification"] == "requires_verification"
    assert result["assessment"]["repository_status"] == "candidate_not_fixed"
    best = result["alternatives"][result["recommended"]]
    # Installing "the candidate" would not be the published fix: no command until the repository offers it.
    assert best["validated"] is False and best.get("command") is None
    assert any("anterior a" in p for p in result["pending_verifications"])


def test_candidate_not_observed_is_not_shown_as_collected(platform):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    import_diag(service, fid, dpkg_query=DPKG)
    state, _ = run(service, cfg, fid, with_distribution_fix([("vim", "trixie", DSA, "")]))
    result = state["result"]
    assert result["classification"] == "requires_verification"
    assert result["assessment"]["repository_status"] == "not_observed"
    assert all(d["executed"] is False for d in state["available_diagnostics"])


def test_backports_installation_uses_backports_fix(platform):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    backport_fix = "2:9.2.0858-1~bpo13+1"
    policy = ("vim-tiny:\n  Installed: 2:9.1.1230-2\n  Candidate: 2:9.2.0858-1~bpo13+1\n  Version table:\n"
              "     2:9.2.0858-1~bpo13+1 100\n        100 http://deb.debian.org/debian trixie-backports/main amd64 Packages\n"
              " *** 2:9.1.1230-2 100\n        100 http://deb.debian.org/debian trixie-backports/main amd64 Packages\n"
              "        100 /var/lib/dpkg/status\n")
    import_diag(service, fid, dpkg_query=DPKG, apt_cache_policy=policy)
    routes = with_distribution_fix([("vim", "trixie-backports", backport_fix, ""), ("vim", "trixie", DSA, "")],
                                   [("vim", "trixie", INSTALLED, "vulnerable"), ("", "trixie-backports", backport_fix, "fixed")])
    state, _ = run(service, cfg, fid, routes)
    result = state["result"]
    assert result["context"]["package_origin"] == "backports"
    assert result["assessment"]["distribution_fixed_version"] == backport_fix
    assert result["classification"] == "validated_fix"


def test_conflicting_distribution_evidence_requires_verification(platform):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    import_diag(service, fid, dpkg_query=DPKG, apt_cache_policy=POLICY.format(installed=INSTALLED, candidate=DSA))
    state, _ = run(service, cfg, fid, with_distribution_fix([("vim", "trixie", DSA, ""), ("vim", "trixie", "2:9.1.1230-2+deb13u2", "")]))
    result = state["result"]
    assert result["classification"] == "requires_verification" and result["assessment"].get("conflict") is True
    assert any("divergem" in p for p in result["pending_verifications"])


def test_stale_cache_after_outage_is_flagged_and_not_validated(platform, tmp_path):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    import_diag(service, fid, dpkg_query=DPKG, apt_cache_policy=POLICY.format(installed=INSTALLED, candidate=DSA))
    run(service, cfg, fid, with_distribution_fix([("vim", "trixie", DSA, "")]))
    # Age the cache beyond its validity and make the source fail: stale evidence is used but flagged.
    cache = Path(cfg["projects"]["hmg"]["integrations"]["research"]["cache_dir"])
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=8)).isoformat(timespec="seconds")
    for path in cache.glob("*.json"):
        entry = json.loads(path.read_text(encoding="utf-8"))
        entry.update(checked_at=old, retrieved_at=old)
        path.write_text(json.dumps(entry), encoding="utf-8")
    routes = {DEBIAN + "CVE-2026-73076": Response(503), GHSA_76: Response(503)}
    state, _ = run(service, cfg, fid, routes)
    result = state["result"]
    assert result["classification"] == "requires_verification"
    assert any(s.get("stale") for s in result["sources"])
    assert any("cache" in p for p in result["pending_verifications"])


def test_external_outage_is_insufficient_data_not_no_fix(platform):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    state, _ = run(service, cfg, fid, {DEBIAN + "CVE-2026-73076": requests.ConnectionError()})
    result = state["result"]
    assert result["classification"] == "insufficient_data"
    assert result["sources"][0]["available"] is False and "conexão" in result["sources"][0]["error"]
    assert any("indisponível" in p for p in result["pending_verifications"])


def test_cve_unknown_to_sources_is_not_found_not_inexistent(platform):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    state, _ = run(service, cfg, fid, {DEBIAN + "CVE-2026-73076": Response(404, b"", {"Content-Type": "text/html"})})
    assert state["result"]["classification"] == "no_fix_found"
    assert "não significa que não exista" in state["result"]["classification_label"]
    again, sources = run(service, cfg, fid, {})  # "not registered" is cached too: no new request
    assert sources.calls == [] and again["result"]["classification"] == "no_fix_found"


# ----------------------------------------------------------------------
# AI proposal: own contract, validated by the engine
# ----------------------------------------------------------------------

def proposal(alternatives, recommended=0, summary="Análise das alternativas para vim-tiny no Debian 13."):
    return {"summary": summary, "recommended": recommended, "alternatives": alternatives, "open_questions": []}


def alt(kind, evidence, **fields):
    base = {"kind": kind, "package": "vim", "target_version": None, "evidence_ids": evidence,
            "rationale": "Motivo baseado nas evidências.", "impact": "Impacto descrito.", "prerequisites": [],
            "verification": [], "rollback": None, "manual_steps": []}
    base.update(fields)
    return base


TRIXIE = "debian:CVE-2026-73076:status:1:trixie"
UPSTREAM = "upstream:GHSA-r22p-fhw4-84p2:0"


@pytest.mark.parametrize("bad", [
    proposal([alt("update_package", [TRIXIE], target_version="2:9.2.0900-1")]),  # invented version
    proposal([alt("wait_for_distribution_fix", [TRIXIE], rationale="Veja https://example.invalid/fix para detalhes.")]),
    proposal([alt("wait_for_distribution_fix", ["debian:invented"])]),
    proposal([alt("manual_build", [UPSTREAM], rationale="Compilar 9.2.0847 garante a correção.")]),
    proposal([alt("update_package", [TRIXIE], manual_steps=["sudo apt-get install vim-tiny"])]),
    proposal([alt("wait_for_distribution_fix", [TRIXIE], rationale="Aplique o KB5031234.")]),
    proposal([alt("wait_for_distribution_fix", [TRIXIE], rationale="Aguarde o pacote 2:9.2.0999-1 do Debian.")]),
])
def test_invented_ai_proposal_is_discarded_and_engine_result_kept(platform, bad):
    service, cfg, ids = platform
    enable_ai(cfg)
    fid = ids[("007", "CVE-2026-73076")]
    state, _ = run(service, cfg, fid, proposal=bad)
    result = state["result"]
    assert result["ai"]["state"] == "failed" and result["summary_origin"] == "engine"
    assert result["classification"] == "upstream_fix_only"


def test_valid_ai_proposal_is_verified_and_manual_steps_are_not_validated(platform):
    service, cfg, ids = platform
    enable_ai(cfg)
    fid = ids[("007", "CVE-2026-73076")]
    good = proposal([
        alt("manual_build", [UPSTREAM], target_version="9.2.0847",
            rationale="O projeto original corrigiu em 9.2.0847; compilar exige manter o pacote fora do apt.",
            impact="Alto: substitui binário gerenciado pelo dpkg.",
            manual_steps=["git clone do repositório oficial e checkout da tag v9.2.0847", "./configure && make"]),
        alt("update_package", [TRIXIE, "debian:CVE-2026-73076:fixed:0"], target_version="2:9.2.0858-1",
            rationale="Versão disponível em sid."),
        alt("wait_for_distribution_fix", [TRIXIE], package="vim",
            rationale="Debian 13 ainda está vulnerável segundo o tracker; acompanhar a publicação."),
        alt("remove_package", [TRIXIE], package="vim-tiny",
            rationale="Remover vim-tiny se não for necessário; avaliar dependências.", impact="Pode remover dependentes."),
    ], recommended=0)
    state, sources = run(service, cfg, fid, proposal=good)
    result = state["result"]
    assert result["ai"]["state"] == "used" and result["summary_origin"] == "ai"
    by_kind = {a["kind"]: a for a in result["alternatives"]}
    assert by_kind["manual_build"]["category"] == "manual_review" and by_kind["manual_build"]["validated"] is False
    assert by_kind["manual_build"]["manual_steps"] and not by_kind["manual_build"].get("command")
    # A sid version is never turned into a command for trixie.
    assert by_kind["update_package"]["command"] is None and by_kind["update_package"]["validated"] is False
    assert any("não publicada pela distribuição para trixie" in n for n in by_kind["update_package"]["engine_notes"])
    # The engine keeps the best-founded recommendation (wait) over the AI's manual build.
    assert result["alternatives"][result["recommended"]]["kind"] == "wait_for_distribution_fix"
    assert any("ajustada pelo motor" in p for p in result["pending_verifications"])
    # Minimization: no host, agent, IP or repository URL in the AI request.
    sent = next(c for c in sources.calls if "nvidia" in c["url"])["data"].decode()
    for forbidden in ("srv-007", "corp.internal", '"agent_id"', SECRET):
        assert forbidden not in sent


def test_ai_update_matching_distribution_fix_uses_backend_template(platform):
    service, cfg, ids = platform
    enable_ai(cfg)
    fid = ids[("007", "CVE-2026-73076")]
    import_diag(service, fid, dpkg_query=DPKG, apt_cache_policy=POLICY.format(installed=INSTALLED, candidate=DSA))
    routes = with_distribution_fix([("vim", "trixie", DSA, "")])
    ev = "debian:CVE-2026-73076:fixed:0"
    state, _ = run(service, cfg, fid, routes, proposal([alt("update_package", [ev], package="vim-tiny", target_version=DSA,
                                                            rationale="O Debian publicou a correção para trixie.")]))
    best = state["result"]["alternatives"][state["result"]["recommended"]]
    assert best["validated"] is True and best["command"] == f"sudo apt-get install --only-upgrade -- vim-tiny={DSA}"
    assert best["ai_rationale"] == "O Debian publicou a correção para trixie."


# ----------------------------------------------------------------------
# Isolation, staleness, cache, transport
# ----------------------------------------------------------------------

def test_isolation_between_installations_and_scope(platform):
    service, cfg, ids = platform
    mine, other = ids[("007", "CVE-2026-73076")], ids[("008", "CVE-2026-73076")]
    import_diag(service, mine, dpkg_query=DPKG)
    run(service, cfg, mine)
    assert service.research_state("hmg", other)["state"] == "none"  # same CVE, other asset
    assert service.research_state("hmg", other)["diagnostic"] is None
    owner = Operations(service.store, cfg, principal(cfg, "owner"))
    with pytest.raises(OperationError) as exc:
        owner.research_state("hmg", mine)
    assert exc.value.status == 403
    with pytest.raises(OperationError):
        import_diag(service, mine, dpkg_query="vim-tiny 2:9.0.0000-1 vim 2:9.0.0000-1\n")  # other version
    from operations.api import job_visible
    jobs = service.store.jobs("hmg")
    assert not any(job_visible(j, set(), principal(cfg, "owner")) for j in jobs if j["kind"] == "research")


def test_research_becomes_stale_on_context_model_or_evidence_change(platform):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    run(service, cfg, fid)
    assert service.research_state("hmg", fid)["state"] == "succeeded"
    import_diag(service, fid, dpkg_query=DPKG)
    stale = service.research_state("hmg", fid)
    assert stale["state"] == "stale" and "alternatives" not in stale["result"]
    run(service, cfg, fid)
    assert service.research_state("hmg", fid)["state"] == "succeeded"
    enable_ai(cfg)
    assert any("modelo" in r for r in service.research_state("hmg", fid)["stale_reasons"])
    del cfg["projects"]["hmg"]["integrations"]["ai"]
    cache = Path(cfg["projects"]["hmg"]["integrations"]["research"]["cache_dir"])
    url = DEBIAN + "CVE-2026-73076"
    path = research_sources.cache_path(cache, url)
    entry = json.loads(path.read_text(encoding="utf-8"))
    entry.update(content=entry["content"] + "<!-- updated -->", content_sha256="0" * 64)
    path.write_text(json.dumps(entry), encoding="utf-8")
    assert any("evidências" in r for r in service.research_state("hmg", fid)["stale_reasons"])


def test_cache_avoids_refetch_and_api_never_fetches(platform, monkeypatch):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    _, first = run(service, cfg, fid)
    assert len(first.calls) == 2
    # Queueing/reading in the API process does not touch the network.
    with monkeypatch.context() as patch:
        patch.setattr(research_sources, "new_session", lambda: pytest.fail("API não deve consultar fontes"))
        assert service.queue_research("hmg", fid)["state"] == "queued"
        assert service.research_state("hmg", fid)["state"] == "queued"
    _, second = run(service, cfg, fid)
    assert second.calls == []  # within validity: served from cache


def test_fetcher_refuses_redirects_oversize_and_other_hosts(tmp_path):
    settings = {"cache_dir": str(tmp_path)}
    url = DEBIAN + "CVE-2026-73076"
    fetcher = research_sources.Fetcher(settings, session=Sources({url: Response(302, b"", {"Location": "https://evil.example/"})}))
    with pytest.raises(research_sources.SourceUnavailable):
        fetcher.get(url, 1024)
    fetcher = research_sources.Fetcher(settings, session=Sources({DEBIAN + "CVE-2026-0001": Response(200, b"x" * 2048)}))
    with pytest.raises(research_sources.SourceUnavailable):
        fetcher.get(DEBIAN + "CVE-2026-0001", 1024)
    with pytest.raises(research_sources.SourceUnavailable) as exc:
        fetcher.get("https://example.com/advisory", 1024)
    assert exc.value.code == "destination_refused"
    with pytest.raises(research_sources.SourceUnavailable):
        research_sources.github_advisory("https://github.com/vim/vim/../../x/security/advisories/GHSA-r22p-fhw4-84p2",
                                         "CVE-2026-73076", fetcher)


def test_conditional_revalidation_uses_etag(tmp_path):
    url = DEBIAN + "CVE-2026-73076"
    clock = [dt.datetime(2026, 10, 13, tzinfo=dt.timezone.utc)]
    first = research_sources.Fetcher({"cache_dir": str(tmp_path)}, session=Sources(
        {url: Response(200, b"<table></table>", {"Content-Type": "text/html", "ETag": '"abc"'})}), clock=lambda: clock[0])
    assert first.get(url, 1024)["cached"] is False
    clock[0] += dt.timedelta(hours=7)
    session = Sources({url: Response(304)})
    again = research_sources.Fetcher({"cache_dir": str(tmp_path)}, session=session, clock=lambda: clock[0]).get(url, 1024)
    assert session.calls[0]["headers"]["If-None-Match"] == '"abc"' and again["cached"] is True


# ----------------------------------------------------------------------
# Diagnostics import parsing
# ----------------------------------------------------------------------

def test_policy_parser_english_portuguese_and_no_urls():
    english = POLICY.format(installed=INSTALLED, candidate=DSA)
    portuguese = english.replace("Installed:", "Instalado:").replace("Candidate:", "Candidato:").replace(
        "Version table:", "Tabela de versão:")
    for text in (english, portuguese):
        parsed = diagnostics.parse_policy(text, "vim-tiny")
        assert parsed["installed"] == INSTALLED and parsed["candidate"] == DSA
        assert "mirror.corp.internal" not in json.dumps(parsed)
    with pytest.raises(OperationError):
        diagnostics.parse_policy("rm -rf /\n", "vim-tiny")
    with pytest.raises(OperationError):
        diagnostics.parse_dpkg("vim 2:9.1.1230-2\n", "vim-tiny")


# ----------------------------------------------------------------------
# Explanation flow uses the research-extended facts
# ----------------------------------------------------------------------

def test_explanation_compares_with_research_facts(platform):
    from operations import ai_facts
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    run(service, cfg, fid)
    plan = service.research_state("hmg", fid)
    stored = service.store.get("hmg", "ai_research", service.installation_key("research", "007", fid))
    facts = ai_facts.engine_facts(dict(finding_id=fid, cve="CVE-2026-73076", package_name="vim-tiny",
                                       installed_version=INSTALLED, operating_system="debian", status="no_guidance",
                                       guidance_kind="textual", diagnostics=[{"label": "Versão instalada", "script": "x"}]),
                                  research.facts_summary(stored))
    assert plan["state"] == "succeeded"
    assert facts["fix_state"] == "upstream_fix_only" and facts["upstream_fixed_versions"] == ["9.2.0847"]
    assert any("sem correção confirmada para debian trixie" in s for s in facts["statements"])
    # Supported by the research: the upstream version and "Debian 13 still vulnerable".
    ai_facts.check_text("O projeto original corrigiu na 9.2.0847 e a distribuição não publicou correção para trixie.",
                        [facts], "IA")
    for contradiction in ("Os diagnósticos confirmam que a Candidate é antiga.", "Atualize para a 9.2.0900."):
        with pytest.raises(Exception):
            ai_facts.check_text(contradiction, [facts], "IA")


def test_interface_research_flow_and_wording():
    import analyserV1
    tpl = analyserV1.HTML_TEMPLATE
    assert "'Pesquisar correção'" in tpl and 'id="guidance-research-section"' in tpl
    block = tpl[tpl.index("function researchEl"):tpl.index("function resetGuidanceExtras")]
    assert "innerHTML" not in block and "Validado pelo EyeMole (template controlado)" in block
    assert "(não executado pelo EyeMole)" in block and "não validados, não executados" in block
    assert "loadGuidanceResearch(record.finding_id, activeGuidanceRequestId);" in tpl
    from operations import ai_facts
    facts = ai_facts.engine_facts({"finding_id": "a" * 64, "diagnostics": [{"label": "Versão instalada", "script": "x"}]})
    assert any("permitem consultar" in s for s in facts["statements"])
    assert not any("confirmam" in s for s in facts["statements"])


def test_explanation_identity_follows_research_and_previous_contracts_are_invalidated(platform):
    import hashlib
    service, cfg, ids = platform
    enable_ai(cfg)
    fid = ids[("007", "CVE-2026-73076")]
    before = service._finding("hmg", fid, "read")
    assert before[6].endswith(":facts4:none") and before[8] is None
    run(service, cfg, fid)
    after = service._finding("hmg", fid, "read")
    assert after[8]["classification"] == "upstream_fix_only" and after[6].endswith(":" + after[8]["revision"])
    # An explanation from the previous facts contract is kept but shown as invalidated, without text.
    legacy = next(old for old in after[7] if old.endswith(":facts3:" + after[8]["revision"]))
    service.store.put("hmg", "ai_finding", hashlib.sha256(legacy.encode()).hexdigest(),
                      {"summary": "antigo", "recommendations": []}, "worker", "ai.finding_explained")
    state = service.finding_ai("hmg", fid)
    assert state["state"] == "stale" and state.get("invalidated") is True and "summary" not in state
    assert state["engine_facts"]["fix_state"] == "upstream_fix_only"


def test_cli_research_commands(tmp_path, monkeypatch):
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "cli"))
    import administration
    import eyemole
    path = tmp_path / "platform.json"
    path.write_text(json.dumps({"enabled": True, "users": {}, "projects": {"hmg": {"integrations": {"ai": {"enabled": True}}}}}))
    monkeypatch.setattr(administration.os, "chown", lambda *a: None, raising=False)
    result = administration.configure_research("hmg", True, path=path)
    block = json.loads(path.read_text())["projects"]["hmg"]["integrations"]
    assert result["enabled"] is True and block["research"]["cache_ttl_hours"] == 6 and block["ai"] == {"enabled": True}
    calls = []
    monkeypatch.setattr(eyemole.subprocess, "run", lambda argv, **k: calls.append(argv) or type(
        "Done", (), {"stdout": '{"ok": true}', "stderr": "", "returncode": 0})())
    assert eyemole.research_check("hmg", "CVE-2026-73076", "debian") == 0
    argv = calls[0]
    assert "--uid=eyemole-worker" in argv and "ReadWritePaths=/var/lib/eyemole/platform" in argv
    assert argv[-6:] == ["--project", "hmg", "--cve", "CVE-2026-73076", "--distribution", "debian"]
    with pytest.raises(eyemole.UpdateError):
        eyemole.research_check("hmg", "CVE-2026-73076; rm -rf /", "debian")


def ubuntu_json(statuses, mitigation=""):
    """Synthetic answer in the ubuntu.com/security/cves/<CVE>.json format."""
    return Response(200, json.dumps({"id": "CVE-2026-90001", "packages": [{"name": "libexemplo", "statuses": [
        {"release_codename": r, "status": s, "description": d, "pocket": p, "component": None} for r, s, d, p in statuses]}],
        "mitigation": mitigation, "notices_ids": [], "references": []}))


@pytest.mark.parametrize("statuses,mitigation,expected", [
    ([("noble", "released", "1.0-1ubuntu0.1", "security"), ("upstream", "released", "1.1", "")], "", "requires_verification"),
    ([("noble", "needed", "", ""), ("upstream", "released", "1.1", "")], "", "upstream_fix_only"),
    ([("noble", "needed", "", "")], "Desabilite o módulo afetado até a correção.", "mitigation"),
    ([("noble", "needs-triage", "", "")], "", "no_fix_found"),
])
def test_ubuntu_connector_and_classification(tmp_path, statuses, mitigation, expected):
    url = "https://ubuntu.com/security/cves/CVE-2026-90001.json"
    collection = research_sources.collect("CVE-2026-90001", "ubuntu", {"cache_dir": str(tmp_path)},
                                          session=Sources({url: ubuntu_json(statuses, mitigation)}))
    row_ = {"agent_id": "009", "cve": "CVE-2026-90001", "package": "libexemplo", "version": "1.0-1",
            "operating_system": "Ubuntu", "os_version": "24.04", "package_architecture": "amd64"}
    plan = {"operating_system": "ubuntu", "os_version": "24.04", "package_manager": "apt", "snapshot_revision": "r"}
    inventory = {"observed_at": "2026-10-13T00:00:00+00:00",
                 "package_details": {"libexemplo": [{"version": "1.0-1", "architecture": "amd64", "source": "libexemplo"}]}}
    context = research.resolve_context(row_, plan, inventory)
    assert context["release"] == "noble" and context["origins"]["release"]["origin"] == "release_table"
    assessment = research.assess(context, collection)
    assert assessment["classification"] == expected
    if expected == "mitigation":
        assert any(a["kind"] == "mitigation" for a in assessment["alternatives"])


def test_fixing_candidate_without_verified_source_is_not_validated(platform):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    import_diag(service, fid, apt_cache_policy=POLICY.format(installed=INSTALLED, candidate=DSA))
    state, _ = run(service, cfg, fid, with_distribution_fix([("vim", "trixie", DSA, "")]))
    result = state["result"]
    assert result["assessment"]["repository_status"] == "candidate_fixes"
    assert result["classification"] == "requires_verification" and result["context"]["source_package"] is None
