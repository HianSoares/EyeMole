"""Validation seal conditions of the remediation research (regressions of the review of a8b2f1f).

1. Candidate origin must be an authorized suite of the asset release (backports only in its scope).
2. Imported diagnostics expire (configurable) and are kept as history.
3. Imports are checked against the installation and the asset context.
4. Time alone retires the classification when evidence or diagnostics expire (API, no network).

Clock controlled; synthetic data only. No rule depends on these packages or CVEs.
"""
import datetime as dt

import pytest

from operations import diagnostics, research, research_sources
from operations.security import OperationError
from test_research import (DEBIAN, DPKG, DSA, INSTALLED, platform, run,  # noqa: F401  (fixture)
                           with_distribution_fix)

NEWER = "2:9.2.0858-1"  # higher than the distribution fix: must still need an authorized origin
T0 = dt.datetime(2026, 10, 13, 12, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def clock(monkeypatch):
    now = [T0]
    for module in (research, diagnostics, research_sources):
        monkeypatch.setattr(module, "_now", lambda: now[0])
    return now


def policy(candidate, suites, installed_suite="trixie/main", arch="amd64"):
    lines = ["vim-tiny:", f"  Installed: {INSTALLED}", f"  Candidate: {candidate}", "  Version table:"]
    if candidate != INSTALLED:
        lines.append(f"     {candidate} 500")
        lines += [f"        500 http://deb.debian.org/debian {s} {arch} Packages" for s in suites]
    lines += [f" *** {INSTALLED} 500", f"        500 http://deb.debian.org/debian {installed_suite} {arch} Packages",
              "        100 /var/lib/dpkg/status"]
    return "\n".join(lines) + "\n"


def stamp(moment):
    return moment.isoformat()


def research_now(service, cfg, fid, clock, candidate=DSA, suites=("trixie-security/main",), **extra):
    diag(service, fid, clock, dpkg_query=DPKG, apt_cache_policy=policy(candidate, list(suites)), **extra)
    state, sources = run(service, cfg, fid, with_distribution_fix([("vim", "trixie", DSA, "")]))
    return state, sources


def collected(clock, hours=0):
    return stamp(clock[0] - dt.timedelta(hours=hours))


def diag(service, fid, clock, hours_ago=0, **outputs):
    """Import collected on the controlled clock."""
    body = {"collected_at": collected(clock, hours_ago)}
    body.update(outputs)
    return service.import_diagnostics("hmg", fid, body)


def commands(result):
    return [a.get("command") for a in result["alternatives"] if a.get("command")]


# ----------------------------------------------------------------------
# 1. Candidate origin
# ----------------------------------------------------------------------

@pytest.mark.parametrize("suites,status", [
    (["sid/main"], "candidate_unauthorized_origin"),
    (["unstable/main"], "candidate_unauthorized_origin"),
    (["forky/main"], "candidate_unauthorized_origin"),
    (["noble-security/main"], "candidate_unauthorized_origin"),      # other distribution's release
    (["trixie-proposed-updates/main"], "candidate_unauthorized_origin"),  # pocket not authorized
    (["trixie-backports/main"], "candidate_unauthorized_origin"),    # backports outside its scope
    (["trixie-security/main", "sid/main"], "candidate_unauthorized_origin"),  # also offered by sid
    ([], "candidate_origin_unknown"),
])
def test_candidate_from_unauthorized_or_unknown_origin_is_never_validated(platform, clock, suites, status):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    diag(service, fid, clock, dpkg_query=DPKG, apt_cache_policy=policy(NEWER, suites))
    state, _ = run(service, cfg, fid, with_distribution_fix([("vim", "trixie", DSA, "")]))
    result = state["result"]
    assert result["assessment"]["repository_status"] == status
    assert result["classification"] == "requires_verification"
    assert not any(a.get("validated") for a in result["alternatives"])
    assert not any(NEWER in c for c in commands(result)) and commands(result) == []
    assert any("origem" in p for p in result["pending_verifications"])


@pytest.mark.parametrize("suites,settings", [
    (["trixie-security/main"], {}),
    (["trixie-updates/main"], {}),
    (["trixie/main"], {}),
    (["corp-trixie-security/main"], {"extra_authorized_suites": ["corp-trixie-security"]}),
])
def test_candidate_from_authorized_suite_is_validated(platform, clock, suites, settings):
    service, cfg, ids = platform
    cfg["projects"]["hmg"]["integrations"]["research"].update(settings)
    fid = ids[("007", "CVE-2026-73076")]
    diag(service, fid, clock, dpkg_query=DPKG, apt_cache_policy=policy(NEWER, suites))
    state, _ = run(service, cfg, fid, with_distribution_fix([("vim", "trixie", DSA, "")]))
    result = state["result"]
    assert result["classification"] == "validated_fix" and result["assessment"]["candidate_origin"] == "authorized"
    assert commands(result) == [f"sudo apt-get install --only-upgrade -- vim-tiny={NEWER}"]


def test_unauthorized_pockets_can_be_restricted(platform, clock):
    service, cfg, ids = platform
    cfg["projects"]["hmg"]["integrations"]["research"]["authorized_pockets"] = ["-security"]
    fid = ids[("007", "CVE-2026-73076")]
    diag(service, fid, clock, dpkg_query=DPKG, apt_cache_policy=policy(NEWER, ["trixie-updates/main"]))
    state, _ = run(service, cfg, fid, with_distribution_fix([("vim", "trixie", DSA, "")]))
    assert state["result"]["assessment"]["repository_status"] == "candidate_unauthorized_origin"


# ----------------------------------------------------------------------
# 2. Diagnostic validity and history
# ----------------------------------------------------------------------

def test_ancient_import_is_history_and_never_validates(platform, clock):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    imported = service.import_diagnostics("hmg", fid, {"collected_at": "2000-01-01T00:00:00+00:00", "dpkg_query": DPKG,
                                                       "apt_cache_policy": policy(DSA, ["trixie-security/main"])})
    state, _ = run(service, cfg, fid, with_distribution_fix([("vim", "trixie", DSA, "")]))
    result = state["result"]
    assert result["classification"] != "validated_fix" and not any(a.get("validated") for a in result["alternatives"])
    assert imported["validity"]["status"] == "expired"
    assert result["classification"] == "requires_verification" and commands(result) == [
        "sudo apt-get install --only-upgrade -- vim-tiny"]  # unpinned, with prerequisites: candidate not observed
    assert result["context"]["source_package"] is None and result["context"]["diagnostic"]["used"] is False
    assert any("expirou" in p for p in result["pending_verifications"])
    assert len(service.store.list("hmg", "diagnostic_history")) == 1


def test_diagnostic_validity_is_configurable_and_new_import_keeps_history(platform, clock):
    service, cfg, ids = platform
    cfg["projects"]["hmg"]["integrations"]["research"]["diagnostics_max_age_hours"] = 2
    fid = ids[("007", "CVE-2026-73076")]
    assert diag(service, fid, clock, hours_ago=1, dpkg_query=DPKG)["validity"]["status"] == "valid"
    assert diag(service, fid, clock, hours_ago=3, dpkg_query=DPKG)["validity"]["status"] == "expired"
    assert len(service.store.list("hmg", "diagnostic_history")) == 2
    state = service.research_state("hmg", fid)
    assert state["diagnostic"]["validity"]["status"] == "expired"


# ----------------------------------------------------------------------
# 3. Coherence of imports with the installation and the asset context
# ----------------------------------------------------------------------

@pytest.mark.parametrize("os_release,conflict", [
    ("ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n", "ubuntu"),
    ("ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n", "bookworm"),
])
def test_context_conflict_is_stored_visible_and_blocks_validation(platform, clock, os_release, conflict):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    imported = diag(service, fid, clock, dpkg_query=DPKG, apt_cache_policy=policy(DSA, ["trixie-security/main"]),
                    os_release=os_release)
    state, _ = run(service, cfg, fid, with_distribution_fix([("vim", "trixie", DSA, "")]))
    result = state["result"]
    assert result["classification"] != "validated_fix" and not any(a.get("validated") for a in result["alternatives"])
    assert result["context"]["release"] == "trixie"  # a conflicting import never redefines the asset context
    assert imported["validity"]["status"] == "conflict" and any(conflict in c for c in imported["conflicts"])
    assert result["context"]["diagnostic"]["status"] == "conflict"
    assert state["diagnostic"]["validity"]["status"] == "conflict"
    assert any(conflict in p for p in result["pending_verifications"])


def test_coherent_os_release_is_valid(platform, clock):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    state, _ = research_now(service, cfg, fid, clock, os_release='ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n')
    assert state["diagnostic"]["validity"]["status"] == "valid"
    assert state["result"]["classification"] == "validated_fix"
    assert state["result"]["context"]["origins"]["release"]["origin"] == "imported_by_analyst"


NOT_INSTALLED = "vim-tiny:\n  Installed: (none)\n  Candidate: 2:9.1.1230-2\n  Version table:\n     2:9.1.1230-2 500\n" \
                "        500 http://deb.debian.org/debian trixie/main amd64 Packages\n"
NO_CANDIDATE_FIELD = f"vim-tiny:\n  Installed: {INSTALLED}\n  Version table:\n *** {INSTALLED} 500\n" \
                     "        100 /var/lib/dpkg/status\n"
CANDIDATE_NOT_IN_TABLE = f"vim-tiny:\n  Installed: {INSTALLED}\n  Candidate: {DSA}\n  Version table:\n *** {INSTALLED} 500\n" \
                         "        500 http://deb.debian.org/debian trixie/main amd64 Packages\n"
STAR_MISMATCH = f"vim-tiny:\n  Installed: {INSTALLED}\n  Candidate: {INSTALLED}\n  Version table:\n *** {DSA} 500\n" \
                "        500 http://deb.debian.org/debian trixie-security/main amd64 Packages\n"


@pytest.mark.parametrize("outputs,fragment", [
    ({"apt_cache_policy": NOT_INSTALLED}, "não está instalado"),
    ({"apt_cache_policy": NO_CANDIDATE_FIELD}, "Installed/Candidate"),
    ({"apt_cache_policy": CANDIDATE_NOT_IN_TABLE}, "Candidate não aparece"),
    ({"apt_cache_policy": STAR_MISMATCH}, "difere de Installed"),
    ({"apt_cache_policy": policy(DSA, ["trixie-security/main"], arch="arm64")}, "arquitetura"),
    ({"dpkg_query": "vim 2:9.1.1230-2 vim 2:9.1.1230-2\n"}, "não contém o pacote"),          # another package
    ({"dpkg_query": "vim-tiny 2:9.0.0000-1 vim 2:9.0.0000-1\n"}, "outra versão"),             # another installation
    ({"dpkg_query": "vim-tiny:arm64 2:9.1.1230-2 vim 2:9.1.1230-2\n"}, "arquitetura"),
    ({"os_release": "NAME=Debian\n"}, "os-release"),
])
def test_imports_of_another_installation_or_incomplete_are_rejected(platform, clock, outputs, fragment):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    with pytest.raises(OperationError) as exc:
        diag(service, fid, clock, **outputs)
    assert fragment in str(exc.value)
    assert service.store.list("hmg", "diagnostic_import") == []


# ----------------------------------------------------------------------
# 4. Time retires the classification and the seal (API without network)
# ----------------------------------------------------------------------

def test_diagnostic_expiry_retires_validation_without_network(platform, clock, monkeypatch):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    state, _ = research_now(service, cfg, fid, clock)
    assert state["result"]["classification"] == "validated_fix"
    assert service.research_facts("hmg", cfg["projects"]["hmg"], *_installation(service, fid)) is not None
    clock[0] += dt.timedelta(hours=73)  # default diagnostic validity: 72 h
    monkeypatch.setattr(research_sources, "new_session", lambda: pytest.fail("a API não deve consultar a rede"))
    stale = service.research_state("hmg", fid)
    assert stale["state"] == "stale" and "alternatives" not in stale["result"]
    assert any("expirou" in r for r in stale["stale_reasons"])
    assert stale["diagnostic"]["validity"]["status"] == "expired"
    # The explanation flow no longer receives the research facts (no command/seal from it).
    assert service.research_facts("hmg", cfg["projects"]["hmg"], *_installation(service, fid)) is None


def test_evidence_expiry_retires_classification_and_worker_refreshes(platform, clock, monkeypatch):
    service, cfg, ids = platform
    cfg["projects"]["hmg"]["integrations"]["research"]["diagnostics_max_age_hours"] = 24 * 10
    fid = ids[("007", "CVE-2026-73076")]
    state, first = research_now(service, cfg, fid, clock)
    assert state["result"]["classification"] == "validated_fix" and len(first.calls) == 1
    clock[0] += dt.timedelta(hours=25)  # default evidence validity: 24 h, content unchanged
    with monkeypatch.context() as patch:
        patch.setattr(research_sources, "new_session", lambda: pytest.fail("a API não deve consultar a rede"))
        stale = service.research_state("hmg", fid)
    assert stale["state"] == "stale" and any("expirou" in r for r in stale["stale_reasons"])
    # A new research in the worker re-confirms the source (cache validity elapsed) and validates again.
    again, sources = run(service, cfg, fid, with_distribution_fix([("vim", "trixie", DSA, "")]))
    assert again["state"] == "succeeded" and again["result"]["classification"] == "validated_fix"
    assert [c["url"] for c in sources.calls] == [DEBIAN + "CVE-2026-73076"]


def test_expired_evidence_at_assessment_is_not_validated(clock):
    context = {"distribution": "debian", "release": "trixie", "source_package": "vim", "binary_package": "vim-tiny",
               "installed_version": INSTALLED, "package_manager": "apt", "package_origin": "distribution",
               "repository": {"candidate_version": DSA, "candidate_suites": ["trixie-security/main"]}}
    old = stamp(T0 - dt.timedelta(hours=30))
    evidence = [{"id": "e1", "distribution": "debian", "kind": "distribution_fix", "release": "trixie",
                 "source_package": "vim", "fixed_version": DSA, "status": "fixed", "checked_at": old, "retrieved_at": old}]
    sources = [{"source": "debian_security_tracker", "available": True, "found": True}]
    assessment = research.assess(context, {"evidence": evidence, "sources": sources}, {}, T0)
    assert assessment["classification"] == "requires_verification"
    assert any("expirada" in p for p in assessment["pending"])
    fresh = [dict(evidence[0], checked_at=stamp(T0), retrieved_at=stamp(T0))]
    ok = research.assess(context, {"evidence": fresh, "sources": sources}, {}, T0)
    assert ok["classification"] == "validated_fix" and ok["valid_until"] == stamp(T0 + dt.timedelta(hours=24))


def test_previous_contract_results_are_not_current_and_are_kept(platform, clock):
    service, cfg, ids = platform
    fid = ids[("007", "CVE-2026-73076")]
    research_now(service, cfg, fid, clock)
    key = service.installation_key("research", "007", fid)
    stored = service.store.get("hmg", "ai_research", key)
    stored["research_version"] = 1  # classified under the previous rules
    service.store.put("hmg", "ai_research", key, stored, "worker", "research.completed")
    audit = len(service.store.audit_entries("hmg"))
    state = service.research_state("hmg", fid)
    assert state["state"] == "stale" and any("contrato" in r for r in state["stale_reasons"])
    assert service.store.get("hmg", "ai_research", key)["classification"] == "validated_fix"  # history kept
    assert len(service.store.audit_entries("hmg")) == audit


def test_interface_shows_validity_conflicts_and_origin():
    import analyserV1
    tpl = analyserV1.HTML_TEMPLATE
    block = tpl[tpl.index("function renderResearchResult"):tpl.index("async function submitGuidanceDiagnostics")]
    for text in ("NÃO autorizada para a release", "Classificação válida até", "EXPIRADO", "EM CONFLITO",
                 "Diagnóstico importado não usado"):
        assert text in block, text
    assert "innerHTML" not in block


def _installation(service, fid):
    cfg, row, agent, _ = service._installation("hmg", fid, "read")
    from operations.planning import engine_for
    return row, agent, fid, engine_for(cfg).generate_guidance(fid).to_dict()
