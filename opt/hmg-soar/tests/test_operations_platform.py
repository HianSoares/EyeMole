"""Authorization, campaign lifecycle, coverage, version verification and durable jobs."""
import datetime as dt
import io
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from operations import api, security
from operations.security import OperationError, principal
from operations.service import Operations, read_snapshot, quality
from operations.store import Store
from operations.kiro import validate_response
from operations.worker import correlate, process


def date(offset=0):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=offset)).isoformat()


@pytest.fixture
def platform(tmp_path):
    path = tmp_path / "latest.json"
    rows = [{"agent_id": "001", "cve": "CVE-2026-12345", "package": "openssl", "version": version,
             "operating_system": "Ubuntu", "severity": "critical", "package_type": "deb", "package_architecture": "amd64",
             "epss": None, "is_kev": True} for version in ("1.0", "1.1")]
    rows.append(dict(rows[0], agent_id="002"))
    snapshot = {"metadata": {"generated_at": date(-60), "agents_analyzed": ["001", "002"], "collection": {"complete": True}}, "vulnerabilities": rows}
    path.write_text(json.dumps(snapshot))
    cfg = {"enabled": True, "projects": {"hmg": {"snapshot_path": str(path)}},
           "users": {"admin": {"role": "admin", "projects": ["*"]},
                     "analyst": {"role": "analyst", "projects": ["hmg"]},
                     "owner": {"role": "owner", "projects": ["hmg"], "agent_ids": ["001"]},
                     "auditor": {"role": "auditor", "projects": ["hmg"]}}}
    store = Store(tmp_path / "state" / "operations.sqlite3")
    service = Operations(store, cfg, principal(cfg, "admin"))
    return service, cfg, path, snapshot


def create(service, ids=None):
    _, rows, revision = read_snapshot(service.config["projects"]["hmg"])
    return service.create_campaign("hmg", {"name": "Atualização OpenSSL", "owner": "Equipe", "revision": revision, "finding_ids": ids or list(rows)})


def test_store_persists_and_rolls_back_audit_on_conflict(platform):
    service, _, _, _ = platform
    c = create(service)
    other = Store(service.store.path)
    assert other.get("hmg", "campaign", c["id"])["name"] == c["name"]
    entries = other.audit_entries("hmg")
    with pytest.raises(OperationError, match="outro usuário"):
        other.put("hmg", "campaign", c["id"], {}, "admin", "wrong", expected=0)
    assert other.audit_entries("hmg") == entries


def test_instances_do_not_duplicate_exposure_and_unknown_epss(platform):
    service, _, _, _ = platform
    summary = service.overview("hmg")
    assert summary["instances"] == 3 and summary["exposures"] == 2
    assert summary["quality"]["missing_epss"] == 3
    assert create(service)["exposure_count"] == 2


def test_scope_filters_proposals_and_blocks_cross_asset_and_project(platform):
    service, cfg, _, _ = platform
    owner = Operations(service.store, cfg, principal(cfg, "owner"))
    assert owner.overview("hmg")["instances"] == 2
    with pytest.raises(OperationError):
        create(owner, list(read_snapshot(cfg["projects"]["hmg"])[1]))
    with pytest.raises(OperationError):
        owner.overview("prod")
    assert owner.proposals("hmg")["items"][0]["agent_ids"] == ["001"]


@pytest.mark.parametrize("role", ["owner", "analyst", "auditor"])
def test_only_admin_can_accept_or_approve(platform, role):
    service, cfg, _, _ = platform
    c = create(service, list(read_snapshot(cfg["projects"]["hmg"])[1])[:1])
    other = Operations(service.store, cfg, principal(cfg, role))
    with pytest.raises(OperationError) as exc:
        other.accept("hmg", c["id"], {"reason": "Teste", "expires_at": date(3600), "version": c["version"]})
    assert exc.value.status == 403


def test_campaign_cannot_be_manually_confirmed(platform):
    service, _, _, _ = platform
    c = create(service)
    with pytest.raises(OperationError):
        service.transition("hmg", c["id"], {"status": "confirmed", "reason": "Não apareceu", "version": c["version"]})


def prepare_applied(service):
    c = create(service)
    c = service.transition("hmg", c["id"], {"status": "analyzing", "reason": "Análise", "version": c["version"]})
    c = service.transition("hmg", c["id"], {"status": "planned", "reason": "Manutenção", "version": c["version"],
                          "maintenance_window": {"start": date(-30), "end": date(3600)}})
    plans = [{"finding_id": m["finding_id"], "agent_id": m["agent_id"], "package": "openssl", "fixed_version": "2.0", "ecosystem": "dpkg"} for m in c["members"]]
    c = service.save_plans("hmg", c["id"], plans, c["baseline_revision"], "admin")
    return service.transition("hmg", c["id"], {"status": "applied", "reason": "Registro da mudança", "version": c["version"]})


@pytest.mark.parametrize("failure", ["none", "partial", "stale", "no_inventory", "old_version", "disconnected", "residual", "no_coverage"])
def test_verification_requires_post_change_version_coverage_and_agent(platform, failure):
    service, _, path, snapshot = platform
    c = prepare_applied(service)
    # Applied time is deliberately earlier than the controlled subsequent observation.
    c["applied_at"] = date(-15)
    c = service.store.put("hmg", "campaign", c["id"], c, "admin", "test.applied", c["version"])
    snapshot["vulnerabilities"] = snapshot["vulnerabilities"] if failure == "residual" else []
    snapshot["metadata"]["generated_at"] = date(-90000 if failure == "stale" else -5)
    snapshot["metadata"]["collection"]["complete"] = failure != "partial"
    if failure == "no_coverage":
        snapshot["metadata"]["agents_analyzed"] = ["001"]
    path.write_text(json.dumps(snapshot))
    if failure != "no_inventory":
        for agent in c["agent_ids"]:
            service.inventory("hmg", agent, {"observed_at": date(-2), "agent_status": "disconnected" if failure == "disconnected" else "active",
                                             "packages": {"openssl": "1.0" if failure == "old_version" else "2.1"}})
    result = service.verify("hmg", c["id"], {"version": c["version"]})
    assert (result["status"] == "confirmed") == (failure == "none")


def test_jobs_are_claimed_once_and_external_failures_not_replayed(platform):
    service, _, _, _ = platform
    c = create(service)
    one = service.queue("hmg", c["id"], "ticket", {})
    two = service.queue("hmg", c["id"], "ticket", {})
    assert one["id"] == two["id"]
    assert service.store.claim()["id"] == one["id"]
    assert service.store.claim() is None
    service.store.recover_interrupted()
    assert service.store.jobs("hmg")[0]["state"] == "interrupted"
    assert service.queue("hmg", c["id"], "ticket", {})["id"] == one["id"]


def test_worker_rechecks_revoked_actor_before_external_work(platform):
    service, cfg, _, _ = platform
    c = create(service)
    service.queue("hmg", c["id"], "ticket", {})
    job = service.store.claim()
    del cfg["users"]["admin"]
    with pytest.raises(OperationError):
        process(service.store, cfg, job, {})


@pytest.mark.parametrize("response", [
    {"summary": "ok", "recommendations": [], "command": "sudo evil"},
    {"summary": "ok", "recommendations": [{"finding_id": "unknown", "evidence_ids": [], "explanation": "x"}]},
    {"summary": "ok", "recommendations": [{"finding_id": "known", "evidence_ids": ["invented"], "explanation": "x"}]},
])
def test_kiro_cannot_add_commands_or_invent_evidence(response):
    with pytest.raises(OperationError):
        validate_response(response, {"evidence"}, {"known"})


def test_incident_correlation_is_explicit_and_does_not_claim_exploitation():
    incidents = [{"observables": ["host.example.com"], "external_id": "example", "title": "Alert"}]
    assert correlate(incidents, {}, {"001"}) == []
    result = correlate(incidents, {"host.example.com": "001"}, {"001"})
    assert result[0]["agent_ids"] == ["001"] and not result[0]["exploitation_confirmed"]


@pytest.mark.parametrize("resource,allowed", [("/soar/assets/operations.html", True), ("/soar/", False), ("/soar/data/latest.json", False), ("/soar/reports/example.html", False)])
def test_access_subrequest_blocks_unfiltered_static_snapshots(platform, monkeypatch, resource, allowed):
    _, cfg, _, _ = platform
    monkeypatch.setattr(api, "load_config", lambda: cfg)
    output = []
    handler = SimpleNamespace(headers={"X-Original-URI": resource}, _get_remote_user=lambda: "owner", _send_json=lambda s,d: output.append((s,d)))
    assert api.handle(handler, "GET", "/platform/access")
    assert (output[0][0] == 200) == allowed


def test_invalid_policy_does_not_disable_authorization(tmp_path):
    path = tmp_path / "platform.json"
    path.write_text("not-json")
    with pytest.raises(OperationError):
        security.load_config(path)


def test_expired_acceptance_and_stale_campaign_updates_are_rejected(platform):
    service, _, _, _ = platform
    c = create(service)
    with pytest.raises(OperationError):
        service.accept("hmg", c["id"], {"expires_at": date(-10), "reason": "x", "version": c["version"]})
    service.transition("hmg", c["id"], {"status": "analyzing", "reason": "x", "version": c["version"]})
    with pytest.raises(OperationError):
        service.transition("hmg", c["id"], {"status": "planned", "reason": "x", "version": c["version"], "maintenance_window": {"start": date(), "end": date(60)}})


def test_entire_pilot_is_validated_before_any_remote_action(platform, monkeypatch):
    import hashlib
    from operations import worker
    service, cfg, _, _ = platform
    c = create(service)
    c['status'] = 'planned'
    c['maintenance_window'] = {'start': date(-60), 'end': date(600)}
    plans = []
    for member in c['members']:
        p = {'agent_id': member['agent_id'], 'package': 'openssl', 'fixed_version': '2.0',
             'installed_version': '1.0', 'confidence': 'high', 'command': 'apt-get upgrade openssl', 'package_manager': 'apt'}
        p['source_revision'] = worker.source_revision(worker.engine_for(cfg['projects']['hmg']))
        p['execution_action'] = worker.execution_action(p)
        plans.append(p)
    # Only the last target is invalid. No earlier valid target may be dispatched.
    plans[-1] = dict(plans[-1], package_manager='powershell', execution_action=None)
    c['plans'] = plans
    c['approval'] = {'approved_by': 'admin', 'revision': c['baseline_revision'],
                     'plans_hash': hashlib.sha256(json.dumps(plans, sort_keys=True).encode()).hexdigest()}
    cfg['projects']['hmg']['execution'] = {'enabled': True, 'agent_ids': ['001', '002']}
    cfg['projects']['hmg']['integrations'] = {'wazuh': {'enabled': True, 'url': 'https://example.com'}}
    calls = []
    monkeypatch.setattr(worker, 'Wazuh', lambda *a, **k: calls.append('connection'))
    with pytest.raises(OperationError, match='apt/dnf/yum'):
        worker.execute_campaign(c, 'hmg', cfg, 'admin', ['001', '002'],
                                {'EYEMOLE_AGENT_KEYS': json.dumps({'001': 'x'*64, '002': 'y'*64})})
    assert calls == []


def test_replaced_snapshot_revokes_execution_approval(platform, monkeypatch):
    from operations import worker
    service, cfg, path, snapshot = platform
    c = create(service)
    c.update(status='planned', maintenance_window={'start': date(-60), 'end': date(600)}, plans=[],
             approval={'approved_by': 'admin', 'revision': c['baseline_revision'], 'plans_hash': 'old'})
    cfg['projects']['hmg']['execution'] = {'enabled': True, 'agent_ids': ['001']}
    snapshot['metadata']['generated_at'] = date(-1)
    path.write_text(json.dumps(snapshot))
    calls = []
    monkeypatch.setattr(worker, 'Wazuh', lambda *a, **k: calls.append('connection'))
    with pytest.raises(OperationError, match='Aprovação'):
        worker.execute_campaign(c, 'hmg', cfg, 'admin', ['001'], {})
    assert calls == []
