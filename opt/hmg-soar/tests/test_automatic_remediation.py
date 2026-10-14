"""Automatic remediation analysis ("Ver correção"), Windows and Linux, end to end.

Opening the modal (POST /analysis) starts or reuses the worker analysis; the
worker refreshes the inventory, queries official sources, requests a fixed
read-only agent collection when indispensable data is missing, and the engine
validates applicability and builds the command. Fixtures: Microsoft Security
Update Guide answers recorded on 2026-10-14 (CVE-2025-59287, CVE-2024-38063),
Debian/GitHub recordings and synthetic variants. No real network, Wazuh, agent
or NVIDIA call is made. No production rule depends on these CVEs or products.
"""
import datetime as dt
import importlib.util
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from operations import collection, llm, research, research_sources, worker
from operations.security import OperationError, principal
from operations.service import Operations, read_snapshot
from operations.store import Store
from test_research import DEBIAN, DSA, INSTALLED, RECORDED, Response, Sources, recorded, with_distribution_fix

FIX = Path(__file__).resolve().parent / "fixtures" / "research"
ROOT = Path(__file__).resolve().parents[3]
TEMPLATES = Path(__file__).resolve().parent.parent / "remediation" / "data" / "remediation_templates.json"
SECRET = "fake-key-for-tests-not-a-credential-0123456789"
MODEL = "nvidia/nemotron-3-super-120b-a12b"
COLLECT_KEY = "c" * 40
WS2019 = "Microsoft Windows Server 2019 Datacenter"
WIN_BUILD = "10.0.17763.7919"


def msrc_url(cve):
    return research_sources.MSRC_BASE + "?%24filter=cveNumber%20eq%20%27" + cve + "%27"


MSRC = {msrc_url("CVE-2025-59287"): recorded("msrc_CVE-2025-59287.json"),
        msrc_url("CVE-2024-38063"): recorded("msrc_CVE-2024-38063.json")}


class FakeWazuh:
    calls = []
    commands = []
    inventories = {}
    fail = False

    def __init__(self, settings, secrets):
        pass

    def login(self):
        if FakeWazuh.fail:
            raise OperationError("Autenticação Wazuh inválida.", 502)

    def inventory(self, agent):
        return FakeWazuh.inventories.get(agent, {"observed_at": None, "packages": {}})

    def collect(self, agent, argument, windows=False):
        FakeWazuh.calls.append((agent, argument))
        FakeWazuh.commands.append("!eyemole-collect-win" if windows else "!eyemole-collect")
        return {"error": 0}


def win_inventory(**overrides):
    base = {"observed_at": "2026-10-14T10:00:00+00:00", "source": "wazuh_api", "agent_ids": ["012"],
            "os": {"name": WS2019, "version": WIN_BUILD}, "architecture": "x86_64",
            "hotfixes": ["KB5005112", "KB5066586"], "hotfixes_complete": True, "packages": {}}
    base.update(overrides)
    return base


@pytest.fixture
def env(tmp_path, monkeypatch):
    FakeWazuh.calls, FakeWazuh.commands, FakeWazuh.inventories, FakeWazuh.fail = [], [], {"012": win_inventory()}, False
    monkeypatch.setattr(worker, "Wazuh", FakeWazuh)
    monkeypatch.setattr(collection, "Wazuh", FakeWazuh)
    path = tmp_path / "latest.json"
    rows = [{"agent_id": "012", "agent_name": "srv-win.corp.internal", "cve": "CVE-2025-59287", "package": WS2019,
             "version": WIN_BUILD, "operating_system": "windows", "os_version": WIN_BUILD, "package_type": "windows",
             "severity": "Critical", "epss": None, "is_kev": True},
            {"agent_id": "007", "agent_name": "srv-debian.corp.internal", "cve": "CVE-2026-73076", "package": "vim-tiny",
             "version": INSTALLED, "operating_system": "Debian GNU/Linux", "os_version": "13", "package_type": "deb",
             "package_architecture": "amd64", "severity": "High", "epss": None, "is_kev": False}]
    generated = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat()
    path.write_text(json.dumps({"metadata": {"generated_at": generated, "agents_analyzed": ["012", "007"],
                                             "collection": {"complete": True}}, "vulnerabilities": rows}))
    (tmp_path / "config").mkdir()
    cfg = {"enabled": True,
           "projects": {"hmg": {"snapshot_path": str(path), "config_dir": str(tmp_path / "config"),
                                "templates_path": str(TEMPLATES), "grype_snapshot_path": str(tmp_path / "grype.json"),
                                "integrations": {"research": {"enabled": True, "cache_dir": str(tmp_path / "cache")},
                                                 "collection": {"enabled": True, "expiry_minutes": 10},
                                                 "wazuh": {"enabled": True, "url": "https://wazuh.example:55000"}}}},
           "users": {"admin": {"role": "admin", "projects": ["*"]},
                     "auditor": {"role": "auditor", "projects": ["hmg"]}}}
    store = Store(tmp_path / "state" / "operations.sqlite3")
    service = Operations(store, cfg, principal(cfg, "admin"))
    _, instances, _ = read_snapshot(cfg["projects"]["hmg"])
    ids = {r["agent_id"]: fid for fid, r in instances.items()}
    return service, cfg, ids


SECRETS = {"NVIDIA_API_KEY": SECRET, "EYEMOLE_COLLECTOR_KEYS": json.dumps({"012": COLLECT_KEY, "007": COLLECT_KEY}),
           "EYEMOLE_WAZUH_USER": "x", "EYEMOLE_WAZUH_PASSWORD": "y"}


def work(service, cfg, routes, proposal=None, secrets=SECRETS):
    """Run the queued analysis job like the worker loop does."""
    sources = Sources(routes, proposal)
    original = (research_sources.new_session, llm.new_session)
    research_sources.new_session = llm.new_session = lambda: sources
    try:
        job = service.store.claim()
        assert job is not None, "nenhum job na fila"
        try:
            service.store.finish(job["id"], result=worker.process(service.store, cfg, job, secrets))
        except OperationError as exc:
            service.store.finish(job["id"], error=str(exc))
    finally:
        research_sources.new_session, llm.new_session = original
    return sources


def open_modal(service, fid):
    return service.ensure_analysis("hmg", fid)


def upload(service, cfg, agent, results, request_id=None):
    request_id = request_id or json.loads(_payload(FakeWazuh.calls[-1][1]))["id"]
    body = {"request_id": request_id, "agent_id": agent, "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "results": results}
    return collection.receive_upload(agent, body, store=service.store, config=cfg)


def _payload(argument):
    import base64
    packet = json.loads(base64.urlsafe_b64decode(argument + "=" * (-len(argument) % 4)))
    return base64.urlsafe_b64decode(packet["p"] + "=" * (-len(packet["p"]) % 4)).decode()


def win_results(ubr=7919, hotfixes=("KB5005112", "KB5066586"), offered=True, feature="Installed", kb="KB5070883"):
    out = {"windows_build": {"ok": True, "output": json.dumps({"ProductName": "Windows Server 2019 Datacenter",
                                                               "EditionID": "ServerDatacenter", "InstallationType": "Server",
                                                               "CurrentBuild": "17763", "UBR": ubr, "Architecture": "AMD64"})},
           "windows_hotfixes": {"ok": True, "output": json.dumps(list(hotfixes))},
           f"wu_search:{kb}": {"ok": True, "output": json.dumps({"kb": kb, "offered": offered})}}
    if feature:
        out["windows_feature:UpdateServices"] = {"ok": True, "output": json.dumps({"Name": "UpdateServices",
                                                                                     "InstallState": feature})}
    return out


# ----------------------------------------------------------------------
# Opening the modal: start, progress, reuse, invalidation
# ----------------------------------------------------------------------

def test_opening_starts_analysis_once_shows_progress_and_reuses_result(env):
    service, cfg, ids = env
    fid = ids["012"]
    first = open_modal(service, fid)
    assert first["started"] is True and first["state"] == "queued"
    again = open_modal(service, fid)  # reopening: same job, no duplicate
    assert again["started"] is False and len(service.store.jobs("hmg")) == 1
    job = service.store.claim()
    service.store.progress(job["id"], "sources")
    assert service.research_state("hmg", fid)["progress"] == "sources"
    service.store.finish(job["id"], error="interrompido no teste")  # simulate, then run for real
    service.store.queue("hmg", "research", job["object_id"], "admin", json.loads(job["payload"]))
    work(service, cfg, MSRC)
    done = open_modal(service, fid)
    assert done["state"] == "succeeded" and done["started"] is False
    calls_before = len(service.store.jobs("hmg"))
    assert open_modal(service, fid)["state"] == "succeeded" and len(service.store.jobs("hmg")) == calls_before


def test_context_change_invalidates_and_reopening_restarts(env):
    service, cfg, ids = env
    fid = ids["012"]
    open_modal(service, fid)
    work(service, cfg, MSRC)
    assert service.research_state("hmg", fid)["state"] == "succeeded"
    service.store.put("hmg", "inventory", "012", win_inventory(hotfixes=["KB5070883"]), "worker", "inventory.collected")
    assert service.research_state("hmg", fid)["state"] == "stale"
    assert open_modal(service, fid)["started"] is True


def test_recent_failure_is_not_retried_automatically_and_readers_do_not_start(env):
    service, cfg, ids = env
    fid = ids["012"]
    auditor = Operations(service.store, cfg, principal(cfg, "auditor"))
    view = auditor.ensure_analysis("hmg", fid)
    assert view["started"] is False and "não iniciar" in view["reason_not_started"]
    assert service.store.jobs("hmg") == []
    open_modal(service, fid)
    job = service.store.claim()
    service.store.finish(job["id"], error="falha simulada")
    failed = open_modal(service, fid)
    assert failed["state"] == "failed" and failed["started"] is False and failed.get("retry_after")


# ----------------------------------------------------------------------
# Windows
# ----------------------------------------------------------------------

def test_windows_applicable_kb_collection_then_validated(env):
    service, cfg, ids = env
    fid = ids["012"]
    open_modal(service, fid)
    work(service, cfg, MSRC)
    state = service.research_state("hmg", fid)
    result = state["result"]
    primary = result["primary"]
    assert result["classification"] == "requires_verification"  # channel offer not observed yet
    assert primary["target"] == "KB5070883" and primary["fixed_build"] == "10.0.17763.7922"
    assert primary["terminal"] == "PowerShell (Executar como administrador)" and primary["privilege"] == "Administrador local"
    assert primary["reboot"].startswith("possível") and "$kb='5070883'" in primary["command"]
    assert "Microsoft.Update.Session" in primary["command"] and primary["validated"] is False
    # Indispensable data missing → fixed read-only collection through the agent, signed and deduplicated.
    assert state["collection"]["state"] == "pending" and len(FakeWazuh.calls) == 1
    payload = json.loads(_payload(FakeWazuh.calls[0][1]))
    assert FakeWazuh.commands == ["!eyemole-collect-win"]
    assert payload["agent_id"] == "012" and {a["action"] for a in payload["actions"]} == {
        "windows_build", "windows_hotfixes", "wu_search", "windows_feature"}
    requirement = result["exploitation_requirements"][0]
    assert requirement["status"] == "unknown" and "UpdateServices" in requirement["description"]
    # The agent answers; the analysis becomes stale and restarts on the next poll/opening.
    assert upload(service, cfg, "012", win_results())["status"] == "accepted"
    assert service.research_state("hmg", fid)["state"] == "stale"
    assert open_modal(service, fid)["started"] is True
    work(service, cfg, MSRC)
    final = service.research_state("hmg", fid)["result"]
    assert final["classification"] == "validated_fix" and final["primary"]["validated"] is True
    assert final["context"]["origins"]["channel"]["origin"] == "collected_by_agent"
    assert final["exploitation_requirements"][0]["status"] == "present"
    assert len(FakeWazuh.calls) == 1  # nothing else missing: no new collection


@pytest.mark.parametrize("inventory,expected", [
    (win_inventory(hotfixes=["KB5070883"]), "já consta como instalada"),
    (win_inventory(os={"name": WS2019, "version": "10.0.17763.7922"}), "já é igual ou posterior"),
])
def test_windows_kb_already_installed_or_build_already_fixed(env, inventory, expected):
    service, cfg, ids = env
    FakeWazuh.inventories["012"] = inventory
    fid = ids["012"]
    open_modal(service, fid)
    work(service, cfg, MSRC)
    result = service.research_state("hmg", fid)["result"]
    assert result["classification"] == "requires_verification" and result["primary"]["available"] is False
    assert any(expected in p for p in result["pending_verifications"])
    assert not any(a.get("command") for a in result["alternatives"])


def test_windows_superseded_kb_installed_is_reported(env):
    service, cfg, ids = env
    FakeWazuh.inventories["012"] = win_inventory(hotfixes=["KB5041578"], os={"name": WS2019, "version": "10.0.17763.6189"})
    rows = json.loads(Path(env[1]["projects"]["hmg"]["snapshot_path"]).read_text())
    rows["vulnerabilities"][0].update(cve="CVE-2024-38063", version="10.0.17763.6189", os_version="10.0.17763.6189")
    Path(env[1]["projects"]["hmg"]["snapshot_path"]).write_text(json.dumps(rows))
    _, instances, _ = read_snapshot(cfg["projects"]["hmg"])
    fid = next(f for f, r in instances.items() if r["agent_id"] == "012")
    open_modal(service, fid)
    work(service, cfg, MSRC)
    result = service.research_state("hmg", fid)["result"]
    assert result["primary"]["target"] == "KB5043050"
    assert any("KB5041578, substituída por KB5043050" in n for n in result["assessment"]["notes"])


@pytest.mark.parametrize("inventory,note", [
    (win_inventory(architecture="arm64"), "outro produto/arquitetura"),            # incompatible architecture
    (win_inventory(os={"name": "Microsoft Windows 10 Pro", "version": "10.0.19045.5011"}), None),  # product not listed
])
def test_windows_incompatible_product_or_architecture_gets_no_command(env, inventory, note):
    service, cfg, ids = env
    FakeWazuh.inventories["012"] = inventory
    fid = ids["012"]
    open_modal(service, fid)
    work(service, cfg, MSRC)
    result = service.research_state("hmg", fid)["result"]
    assert result["classification"] in {"no_fix_found", "insufficient_data"}
    assert result["primary"]["available"] is False and not any(a.get("command") for a in result["alternatives"])
    if note:
        assert any(note in n for n in result["assessment"]["notes"])


def test_windows_kb_not_offered_by_channel_and_requirement_absent(env):
    service, cfg, ids = env
    fid = ids["012"]
    open_modal(service, fid)
    work(service, cfg, MSRC)
    upload(service, cfg, "012", win_results(offered=False, feature="Available"))
    open_modal(service, fid)
    work(service, cfg, MSRC)
    result = service.research_state("hmg", fid)["result"]
    assert result["classification"] == "requires_verification" and result["primary"]["command"] is None
    assert any("não é oferecida pelo canal" in p for p in result["pending_verifications"])
    requirement = result["exploitation_requirements"][0]
    assert requirement["status"] == "absent" and "não é encerrado" in requirement["effect"]
    catalog = next(a for a in result["alternatives"] if a["kind"] == "other_manual")
    assert catalog["catalog_url"].startswith("https://catalog.update.microsoft.com/") and catalog["validated"] is False


def test_windows_source_unavailable_and_collection_unavailable_are_explicit(env):
    service, cfg, ids = env
    cfg["projects"]["hmg"]["integrations"]["collection"]["enabled"] = False
    fid = ids["012"]
    open_modal(service, fid)
    work(service, cfg, {msrc_url("CVE-2025-59287"): Response(503)})
    state = service.research_state("hmg", fid)
    result = state["result"]
    assert result["classification"] == "insufficient_data" and result["primary"]["available"] is False
    assert state["collection"] is None or state["collection"]["state"] != "pending"
    collected = result["collection"]
    assert collected["state"] == "unavailable" and "desabilitada" in collected["reason"]
    missing = {m["key"]: m for m in collected["missing"]}
    assert "Get-HotFix" in missing["windows_hotfixes"]["diagnostic"] and missing["windows_hotfixes"]["shell"] == "powershell"


def test_wazuh_dispatch_failure_is_reported(env):
    service, cfg, ids = env
    # Inventory collected earlier; now the Wazuh API fails (no refresh, no collection dispatch).
    service.store.put("hmg", "inventory", "012", win_inventory(), "worker", "inventory.collected")
    FakeWazuh.fail = True
    fid = ids["012"]
    open_modal(service, fid)
    work(service, cfg, MSRC)
    result = service.research_state("hmg", fid)["result"]
    assert result["collection"]["state"] == "failed" and result["primary"]["target"] == "KB5070883"


def test_ai_failure_or_invented_kb_keeps_engine_result(env):
    service, cfg, ids = env
    cfg["projects"]["hmg"]["integrations"]["ai"] = {"enabled": True, "provider": "nvidia", "model": MODEL}
    fid = ids["012"]
    bad = {"summary": "Instale a KB5099999.", "recommended": 0, "open_questions": [], "exploitation_requirements": [],
           "alternatives": [{"kind": "update_package", "package": WS2019, "target_version": "KB5099999",
                             "evidence_ids": [], "rationale": "x", "impact": "x", "prerequisites": [], "verification": [],
                             "rollback": None, "manual_steps": []}]}
    open_modal(service, fid)
    work(service, cfg, MSRC, proposal=bad)
    result = service.research_state("hmg", fid)["result"]
    assert result["ai"]["state"] == "failed" and result["primary"]["target"] == "KB5070883"
    assert "KB5099999" not in json.dumps(result["primary"])


def test_ai_requirements_need_evidence_and_are_unverified(env):
    service, cfg, ids = env
    cfg["projects"]["hmg"]["integrations"]["ai"] = {"enabled": True, "provider": "nvidia", "model": MODEL}
    fid = ids["012"]
    open_modal(service, fid)
    first = work(service, cfg, MSRC)  # collect evidence ids
    evidence = service.research_state("hmg", fid)["result"]["evidence"]
    kb_id = next(e["id"] for e in evidence if e.get("kb") == "KB5070883" and e["product"] == "Windows Server 2019")
    good = {"summary": "A Microsoft publicou a KB5070883 para o Windows Server 2019.", "recommended": 0, "open_questions": [],
            "exploitation_requirements": [{"description": "Servidor com o papel WSUS habilitado.", "evidence_ids": [kb_id]}],
            "alternatives": [{"kind": "update_package", "package": WS2019, "target_version": "KB5070883",
                              "evidence_ids": [kb_id], "rationale": "Atualização oficial do produto.",
                              "impact": "Reinício possível.", "prerequisites": [], "verification": [], "rollback": None,
                              "manual_steps": []}]}
    service.store.put("hmg", "inventory", "012", win_inventory(hotfixes=["KB5005112"]), "worker", "inventory.collected")
    open_modal(service, fid)
    work(service, cfg, MSRC, proposal=good)
    result = service.research_state("hmg", fid)["result"]
    assert result["ai"]["state"] == "used" and result["summary_origin"] == "ai"
    ai_items = [r for r in result["exploitation_requirements"] if r["origin"] == "ia_com_evidencias"]
    assert ai_items and ai_items[0]["status"] == "unknown"
    assert first.calls  # the first run queried MSRC


# ----------------------------------------------------------------------
# Linux through the automatic collection
# ----------------------------------------------------------------------

POLICY_OK = ("vim-tiny:\n  Installed: 2:9.1.1230-2\n  Candidate: 2:9.1.1230-2+deb13u1\n  Version table:\n"
             "     2:9.1.1230-2+deb13u1 500\n        500 http://deb.debian.org/debian-security trixie-security/main amd64 Packages\n"
             " *** 2:9.1.1230-2 500\n        500 http://deb.debian.org/debian trixie/main amd64 Packages\n"
             "        100 /var/lib/dpkg/status\n")


def linux_results(policy=POLICY_OK):
    return {"os_release": {"ok": True, "output": "ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie"},
            "dpkg_source": {"ok": True, "output": "vim-tiny 2:9.1.1230-2 vim 2:9.1.1230-2\n"},
            "apt_policy": {"ok": True, "output": policy}}


def test_linux_agent_collection_gives_validated_bash_command(env):
    service, cfg, ids = env
    fid = ids["007"]
    routes = with_distribution_fix([("vim", "trixie", DSA, "")])
    open_modal(service, fid)
    work(service, cfg, routes)
    first = service.research_state("hmg", fid)
    assert first["result"]["classification"] == "requires_verification" and first["collection"]["state"] == "pending"
    actions = json.loads(_payload(FakeWazuh.calls[-1][1]))["actions"]
    assert actions == [{"action": "os_release"}, {"action": "dpkg_source", "package": "vim-tiny"},
                       {"action": "apt_policy", "package": "vim-tiny"}]
    upload(service, cfg, "007", linux_results())
    open_modal(service, fid)
    work(service, cfg, routes)
    result = service.research_state("hmg", fid)["result"]
    primary = result["primary"]
    assert result["classification"] == "validated_fix" and primary["validated"] is True
    assert primary["command"] == f"sudo apt-get install --only-upgrade -- vim-tiny={DSA}"
    assert primary["terminal"] == "Terminal Linux (bash)" and primary["privilege"] == "root (via sudo)"
    assert result["context"]["origins"]["source_package"]["origin"] == "collected_by_agent"


def test_linux_incompatible_origin_from_agent_is_not_validated(env):
    service, cfg, ids = env
    fid = ids["007"]
    routes = with_distribution_fix([("vim", "trixie", DSA, "")])
    open_modal(service, fid)
    work(service, cfg, routes)
    upload(service, cfg, "007", linux_results(POLICY_OK.replace("trixie-security/main", "sid/main")))
    open_modal(service, fid)
    work(service, cfg, routes)
    result = service.research_state("hmg", fid)["result"]
    assert result["classification"] == "requires_verification" and result["primary"]["command"] is None


def test_linux_without_distribution_update_recommends_wait_with_reason(env):
    service, cfg, ids = env
    fid = ids["007"]
    open_modal(service, fid)
    work(service, cfg, RECORDED)
    primary = service.research_state("hmg", fid)["result"]["primary"]
    assert primary["kind"] == "wait_for_distribution_fix" and primary["command"] is None and primary["sources"]


# ----------------------------------------------------------------------
# Agent upload contract
# ----------------------------------------------------------------------

def test_agent_upload_is_bound_to_request_agent_actions_and_time(env):
    service, cfg, ids = env
    open_modal(service, ids["012"])
    work(service, cfg, MSRC)
    request_id = json.loads(_payload(FakeWazuh.calls[-1][1]))["id"]
    with pytest.raises(OperationError) as exc:
        upload(service, cfg, "007", win_results(), request_id)  # another agent
    assert exc.value.status == 403
    with pytest.raises(OperationError):
        upload(service, cfg, "012", dict(win_results(), apt_policy={"ok": True, "output": "x"}), request_id)
    with pytest.raises(OperationError) as exc:
        upload(service, cfg, "012", win_results(), "f" * 32)
    assert exc.value.status == 404
    with pytest.raises(OperationError):  # another installation (build branch)
        upload(service, cfg, "012", dict(win_results(), windows_build={"ok": True, "output": json.dumps(
            {"ProductName": "x", "CurrentBuild": "20348", "UBR": 1, "Architecture": "AMD64"})}), request_id)
    service.store.put("hmg", "collection_request", request_id, dict(
        service.store.get("hmg", "collection_request", request_id), state="pending",
        expires_at=(dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat()), "t", "t")
    with pytest.raises(OperationError) as exc:
        upload(service, cfg, "012", win_results(), request_id)
    assert "expirado" in str(exc.value)


# ----------------------------------------------------------------------
# Agent receivers (fixed read-only actions)
# ----------------------------------------------------------------------

def load_linux_receiver():
    spec = importlib.util.spec_from_file_location("eyemole_collect", ROOT / "agents" / "eyemole-collect.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def signed(actions, agent="012", key=COLLECT_KEY, issued=None, **extra):
    now = issued or int(time.time())
    payload = {"id": "a" * 32, "project": "hmg", "agent_id": agent, "finding_id": "b" * 64, "actions": actions,
               "issued_at": now, "expires_at": now + 600}
    payload.update(extra)
    return collection.sign(payload, key)


def test_linux_receiver_runs_only_fixed_actions():
    receiver = load_linux_receiver()
    policy = {"enabled": True, "agent_id": "007", "hmac_key": COLLECT_KEY}
    actions = [{"action": "dpkg_source", "package": "vim-tiny"}, {"action": "apt_policy", "package": "vim-tiny"}]
    payload = receiver.verify(signed(actions, "007"), policy)
    assert payload["actions"] == actions
    assert receiver.argv_for(actions[1]) == ["/usr/bin/apt-cache", "policy", "vim-tiny"]
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, b"vim-tiny 2:9.1.1230-2 vim 2:9.1.1230-2\n", b"")

    assert receiver.run_action(actions[0], runner)["ok"] is True
    assert "shell" not in calls[0][1] and calls[0][1]["env"]["LANG"] == "C"
    for bad in (signed(actions, "007", key="d" * 40), signed(actions, "012"),
                signed([{"action": "apt_policy", "package": "vim; rm -rf /"}], "007"),
                signed([{"action": "run", "cmd": "id"}], "007"),
                signed(actions, "007", issued=int(time.time()) - 4000)):
        with pytest.raises(ValueError):
            receiver.verify(bad, policy)
    with pytest.raises(ValueError):
        receiver.upload(dict(policy, upload_url="https://evil.example/soar-api/agent-context/999"), {})


@pytest.mark.skipif(not (shutil.which("pwsh") or shutil.which("powershell")), reason="PowerShell indisponível")
def test_windows_receiver_verifies_the_same_signature():
    shell = shutil.which("pwsh") or shutil.which("powershell")
    script = ROOT / "agents" / "eyemole-collect.ps1"
    good = signed([{"action": "windows_build"}, {"action": "wu_search", "kb": "KB5070883"}])
    tampered = signed([{"action": "windows_build"}], key="d" * 40)
    injected = signed([{"action": "wu_search", "kb": "KB1; Remove-Item C:\\"}])
    command = (f". '{script}'; $p=[pscustomobject]@{{enabled=$true; agent_id='012'; hmac_key='{COLLECT_KEY}'}}; "
               f"$r=Confirm-Request '{good}' $p; Write-Output ('ok:' + $r.id + ':' + @($r.actions).Count); "
               f"foreach ($a in @('{tampered}','{injected}')) {{ try {{ Confirm-Request $a $p | Out-Null; 'accepted' }} "
               "catch { 'rejected:' + $_.Exception.Message } }")
    output = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True,
                            timeout=120).stdout.split()
    assert output == ["ok:" + "a" * 32 + ":2", "rejected:signature", "rejected:parameters"]


def test_windows_receiver_has_no_free_execution():
    text = (ROOT / "agents" / "eyemole-collect.ps1").read_text(encoding="utf-8")
    for forbidden in ("Invoke-Expression", "iex ", "Start-Process", "Install(", "CreateUpdateInstaller", "Remove-Item"):
        assert forbidden not in text, forbidden


# ----------------------------------------------------------------------
# Interface
# ----------------------------------------------------------------------

def test_modal_starts_analysis_on_open_and_shows_ready_command():
    import analyserV1
    tpl = analyserV1.HTML_TEMPLATE
    assert 'id="guidance-primary"' in tpl and tpl.index('id="guidance-primary"') < tpl.index('id="guidance-meta-cve"')
    load = tpl[tpl.index("async function loadGuidanceResearch"):tpl.index("function resetGuidanceExtras")]
    assert "await ensureGuidanceAnalysis(findingId, requestId);" in load
    block = tpl[tpl.index("const ANALYSIS_PROGRESS"):tpl.index("async function submitGuidanceDiagnostics")]
    assert "'/analysis?'" in block and "scheduleGuidanceAnalysis" in block and "copyButton(p.command)" in block
    assert "'Terminal: '" in block and "'Privilégio: '" in block and "'Reinício: '" in block
    assert "innerHTML" not in block
    for removed in ("Explicar com IA", "'Pesquisar correção'", "guidance-ai-section"):
        assert removed not in tpl, removed
