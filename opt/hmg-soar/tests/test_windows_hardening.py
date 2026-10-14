"""Hardening of the automatic remediation for Windows (PR #19 review).

1. Collection request persisted before dispatch (agent answering during dispatch).
2. KB selection through proven supersedence chains and the asset's channel metadata.
3. PowerShell command: administrator, license, blocking conditions, download/install results, reboot.
4. Native architecture: Sysnative wrapper and OS architecture from 32-bit processes.

PowerShell tests run with simulated COM objects (Windows PowerShell or pwsh). Tests marked
"Windows real" only run on Windows and use the real OS (no Windows Update call is made).
"""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from operations import collection, windows_fix
from operations.security import OperationError
from test_automatic_remediation import (COLLECT_KEY, MSRC, SECRETS, FakeWazuh, _payload, env, open_modal,  # noqa: F401
                                        win_results, work)

ROOT = Path(__file__).resolve().parents[3]
SHELL = shutil.which("pwsh") or shutil.which("powershell")
GUID = {name: f"{i:08x}-0000-4000-8000-00000000000{i}" for i, name in enumerate("ABCDEFG", start=1)}


# ----------------------------------------------------------------------
# 1. Agent answering while the request is being dispatched
# ----------------------------------------------------------------------

def test_agent_answer_during_dispatch_is_accepted_and_not_overwritten(env, monkeypatch):
    service, cfg, ids = env
    outcome = {}

    class AnsweringWazuh(FakeWazuh):
        def collect(self, agent, argument, windows=False):
            FakeWazuh.calls.append((agent, argument))
            request_id = json.loads(_payload(argument))["id"]
            body = {"request_id": request_id, "agent_id": agent, "collected_at": "2026-10-14T10:00:00+00:00",
                    "results": win_results()}
            try:  # the agent is fast: its upload arrives before collect() returns
                outcome["upload"] = collection.receive_upload(agent, body, store=service.store, config=cfg)
            except OperationError as exc:
                outcome["upload"] = exc
            return {"error": 0}

    monkeypatch.setattr(collection, "Wazuh", AnsweringWazuh)
    import operations.worker as worker
    monkeypatch.setattr(worker, "Wazuh", AnsweringWazuh)
    open_modal(service, ids["012"])
    work(service, cfg, MSRC)
    assert isinstance(outcome["upload"], dict) and outcome["upload"]["status"] == "accepted", outcome["upload"]
    request_id = json.loads(_payload(FakeWazuh.calls[-1][1]))["id"]
    record = service.store.get("hmg", "collection_request", request_id)
    assert record["state"] == "received"  # not overwritten by the dispatcher afterwards
    state = service.research_state("hmg", ids["012"])
    assert state["collection"]["state"] == "received"
    actions = [e["action"] for e in service.store.audit_entries("hmg")]
    assert "collection.requested" in actions and "collection.received" in actions
    with pytest.raises(OperationError):  # replay of the same answer
        collection.receive_upload("012", {"request_id": request_id, "agent_id": "012",
                                          "collected_at": "2026-10-14T10:00:00+00:00", "results": win_results()},
                                  store=service.store, config=cfg)


def test_dispatch_failure_marks_only_unanswered_requests(env, monkeypatch):
    service, cfg, ids = env

    class BrokenWazuh(FakeWazuh):
        def collect(self, agent, argument, windows=False):
            FakeWazuh.calls.append((agent, argument))
            raise OperationError("Wazuh não confirmou o envio.", 502)

    monkeypatch.setattr(collection, "Wazuh", BrokenWazuh)
    import operations.worker as worker
    monkeypatch.setattr(worker, "Wazuh", BrokenWazuh)
    open_modal(service, ids["012"])
    work(service, cfg, MSRC)
    request_id = json.loads(_payload(FakeWazuh.calls[-1][1]))["id"]
    assert service.store.get("hmg", "collection_request", request_id)["state"] == "failed"
    with pytest.raises(OperationError):  # a late answer for a failed dispatch is refused
        collection.receive_upload("012", {"request_id": request_id, "agent_id": "012",
                                          "collected_at": "2026-10-14T10:00:00+00:00", "results": win_results()},
                                  store=service.store, config=cfg)


# ----------------------------------------------------------------------
# 2. KB selection and supersedence
# ----------------------------------------------------------------------

def kb_row(kb, fixed, supersedes=None, product="Windows Server 2019", arch="x64", name="Security Update"):
    return {"id": f"msrc:{kb}:{product}:{arch}", "kind": "windows_kb", "distribution": "windows", "product": product,
            "architecture": arch, "base_version": "10.0.17763.0", "kb": kb, "fixed_build": fixed, "download_name": name,
            "reboot": "Yes", "supersedes": supersedes, "status": "fixed", "url": "https://api.msrc.microsoft.com/x",
            "publisher": "MSRC", "retrieved_at": "2026-10-14T10:00:00+00:00", "checked_at": "2026-10-14T10:00:00+00:00"}


def wu(kb, guid, supersedes=(), cves=(), downloaded=False, eula=True):
    return {"update_id": guid, "title": f"Atualização cumulativa ({kb})", "kb_ids": [kb[2:]], "cve_ids": list(cves),
            "superseded_update_ids": list(supersedes), "is_downloaded": downloaded, "eula_accepted": eula}


def context(updates=None, hotfixes=("KB5005112",)):
    ctx = {"distribution": "windows", "product_name": "Microsoft Windows Server 2019 Datacenter", "os_class": "server",
           "os_build": "10.0.17763.7000", "architecture": "x64", "installation_type": "Server",
           "hotfixes": list(hotfixes), "channel": {}, "features": {}, "missing": [], "cve": "CVE-2026-90010",
           "origins": {"os_build": {"origin": "collected_by_agent"}, "architecture": {"origin": "collected_by_agent"},
                       "hotfixes": {"origin": "collected_by_agent"}}}
    if updates is not None:
        ctx["channel_updates"] = {"cve": "CVE-2026-90010", "updates": updates,
                                  "observed_at": "2026-10-14T10:00:00+00:00"}
        ctx["origins"]["channel"] = {"origin": "collected_by_agent"}
    return ctx


SOURCES = [{"source": "msrc_security_update_guide", "available": True, "found": True}]


def assess(rows, updates=None, **kwargs):
    return windows_fix.assess(context(updates, **kwargs), {"evidence": rows, "sources": SOURCES})


def test_proven_chain_selects_offered_successor_without_conflict():
    rows = [kb_row("KB5010001", "10.0.17763.7100"), kb_row("KB5020002", "10.0.17763.7200", supersedes="KB5010001")]
    # Old KB not offered (superseded in WSUS); successor offered. KB numbers are not used as proof of recency.
    result = assess(rows, [wu("KB5020002", GUID["B"])])
    assert result["kb"] == "KB5020002" and not result.get("conflict")
    assert result["classification"] == "validated_fix" and result["update_id"] == GUID["B"]
    assert result["supersedence_chain"] == ["KB5020002", "KB5010001"]


def test_successor_not_offered_keeps_listed_offered_kb_or_uncertainty():
    rows = [kb_row("KB5010001", "10.0.17763.7100"), kb_row("KB5020002", "10.0.17763.7200", supersedes="KB5010001")]
    offered_old = assess(rows, [wu("KB5010001", GUID["A"])])
    assert offered_old["kb"] == "KB5010001" and offered_old["classification"] == "validated_fix"
    assert any("KB5020002" in n and "não é oferecida" in n for n in offered_old["notes"])
    none_offered = assess(rows, [])
    assert none_offered["kb"] == "KB5020002" and none_offered["classification"] == "requires_verification"
    assert not any(a.get("validated") for a in none_offered["alternatives"])


def test_successor_proven_by_channel_metadata_beyond_msrc_listing():
    rows = [kb_row("KB5010001", "10.0.17763.7100")]
    updates = [wu("KB5010001", GUID["A"]), wu("KB5030003", GUID["C"], supersedes=[GUID["A"]])]
    result = assess(rows, updates)
    assert result["kb"] == "KB5030003" and result["update_id"] == GUID["C"]
    assert result["classification"] == "validated_fix" and result["supersedence_chain"] == ["KB5030003", "KB5010001"]
    # Without metadata linking it to a listed KB, a newer-looking KB number proves nothing.
    unrelated = assess(rows, [wu("KB5099999", GUID["D"])])
    assert unrelated["kb"] == "KB5010001" and unrelated["classification"] == "requires_verification"


def test_incompatible_product_does_not_prove_succession():
    rows = [kb_row("KB5010001", "10.0.17763.7100"),
            kb_row("KB5040004", "10.0.17763.7300", supersedes="KB5010001", arch="ARM")]  # other architecture
    result = assess(rows, [wu("KB5040004", GUID["E"])])
    assert result["kb"] == "KB5010001" and result["classification"] != "validated_fix"


def test_supersedence_cycle_is_uncertain():
    rows = [kb_row("KB5010001", "10.0.17763.7100", supersedes="KB5020002"),
            kb_row("KB5020002", "10.0.17763.7200", supersedes="KB5010001")]
    result = assess(rows, [wu("KB5010001", GUID["A"]), wu("KB5020002", GUID["B"])])
    assert result.get("conflict") and result["classification"] == "requires_verification"
    assert not any(a.get("validated") for a in result["alternatives"])
    assert any("ciclo" in p for p in result["pending"])


def test_true_conflict_between_unrelated_offered_updates():
    rows = [kb_row("KB5010001", "10.0.17763.7100"), kb_row("KB5050005", "10.0.17763.7400")]
    result = assess(rows, [wu("KB5010001", GUID["A"]), wu("KB5050005", GUID["F"])])
    assert result.get("conflict") and result["classification"] == "requires_verification"
    assert not any(a.get("validated") for a in result["alternatives"])


def test_collection_requests_channel_metadata_for_all_listed_kbs(env):
    service, cfg, ids = env
    open_modal(service, ids["012"])
    work(service, cfg, MSRC)
    actions = json.loads(_payload(FakeWazuh.calls[-1][1]))["actions"]
    channel = [a for a in actions if a["action"] == "wu_updates"]
    assert channel == [{"action": "wu_updates", "cve": "CVE-2025-59287", "kbs": "KB5070883"}]


# ----------------------------------------------------------------------
# 3. PowerShell command with simulated COM objects
# ----------------------------------------------------------------------

FAKE_PRELUDE = r"""
$global:Scenario = ConvertFrom-Json '__SCENARIO__'
function global:Fake-Admin { if (-not $global:Scenario.admin) { throw 'Execute este comando no PowerShell como Administrador.' } }
function global:New-FakeUpdate($s) {
  $u = [pscustomobject]@{ Title = 'Atualização cumulativa (KB5070883)'; KBArticleIDs = @('5070883');
        Identity = [pscustomobject]@{ UpdateID = $s.update_id }; EulaAccepted = [bool]$s.eula_accepted; EulaText = 'Licença';
        IsDownloaded = [bool]$s.is_downloaded; InstallationBehavior = [pscustomobject]@{ CanRequestUserInput = [bool]$s.user_input } }
  $u | Add-Member ScriptMethod AcceptEula { $this.EulaAccepted = $true; $global:EulaAcceptedBy = 'script' }
  return $u
}
function global:New-FakeResult($code, $hresult, $itemCode, $reboot) {
  $r = [pscustomobject]@{ ResultCode = $code; HResult = $hresult; RebootRequired = $reboot }
  $item = [pscustomobject]@{ ResultCode = $itemCode; HResult = $hresult; RebootRequired = $reboot }
  $r | Add-Member NoteProperty Item $item
  $r | Add-Member ScriptMethod GetUpdateResult { param($i) $this.Item }
  return $r
}
function global:New-FakeObject {
  param([string]$ComObject)
  switch ($ComObject) {
    'Microsoft.Update.SystemInfo' { return [pscustomobject]@{ RebootRequired = [bool]$global:Scenario.pending_reboot } }
    'Microsoft.Update.UpdateColl' { $c = [pscustomobject]@{ Items = [System.Collections.ArrayList]::new() }
                                     $c | Add-Member ScriptMethod Add { param($x) $this.Items.Add($x) }; return $c }
    'Microsoft.Update.Session' {
      $global:FakeUpdates = @($global:Scenario.updates | ForEach-Object { New-FakeUpdate $_ })
      $session = [pscustomobject]@{}
      $session | Add-Member ScriptMethod CreateUpdateSearcher {
        $searcher = [pscustomobject]@{ IncludePotentiallySupersededUpdates = $false }
        $searcher | Add-Member ScriptMethod Search { param($criteria) $global:Criteria = $criteria; [pscustomobject]@{ Updates = $global:FakeUpdates } }
        return $searcher }
      $session | Add-Member ScriptMethod CreateUpdateDownloader {
        $d = [pscustomobject]@{ Updates = $null }
        $d | Add-Member ScriptMethod Download {
          $global:Downloaded = $true
          if ($global:Scenario.download_ok) { foreach ($u in $global:FakeUpdates) { $u.IsDownloaded = $true } }
          New-FakeResult $global:Scenario.download_code -2145124329 $global:Scenario.download_code $false }
        return $d }
      $session | Add-Member ScriptMethod CreateUpdateInstaller {
        $i = [pscustomobject]@{ Updates = $null; IsBusy = [bool]$global:Scenario.busy }
        $i | Add-Member ScriptMethod Install { $global:Installed = $true
          New-FakeResult $global:Scenario.install_code -2145124330 $global:Scenario.item_code ([bool]$global:Scenario.reboot) }
        return $i }
      return $session }
    default { throw "objeto COM inesperado: $ComObject" }
  }
}
Set-Alias -Name New-Object -Value New-FakeObject -Scope Global
Set-Alias -Name Assert-EyeMoleAdministrator -Value Fake-Admin -Scope Global
"""

BASE = {"admin": True, "pending_reboot": False, "busy": False, "download_ok": True, "download_code": 2,
        "install_code": 2, "item_code": 2, "reboot": False,
        "updates": [{"update_id": "11111111-2222-4333-8444-555555555555", "eula_accepted": True, "is_downloaded": False,
                     "user_input": False}]}


def run_command(command, **changes):
    scenario = json.loads(json.dumps(BASE))
    updates = changes.pop("updates", None)
    scenario.update(changes)
    if updates is not None:
        scenario["updates"] = updates
    script = "$ProgressPreference = 'SilentlyContinue'\n[Console]::OutputEncoding = [Text.Encoding]::UTF8\n" + FAKE_PRELUDE.replace("__SCENARIO__", json.dumps(scenario).replace("'", "''")) + "\n" + command + \
        "\n'INSTALLED=' + [bool]$global:Installed; 'EULA=' + $global:EulaAcceptedBy"
    import tempfile
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "simulacao.ps1"
        path.write_text(script, encoding="utf-8-sig")  # BOM: Windows PowerShell 5.1 reads UTF-8 correctly
        done = subprocess.run([SHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)],
                              capture_output=True, timeout=120)
    return done.returncode, (done.stdout + done.stderr).decode("utf-8", errors="replace")


@pytest.fixture(scope="module")
def command():
    generated = windows_fix.commands("KB5070883", "10.0.17763.7922", "Yes", update_id="11111111-2222-4333-8444-555555555555")
    return generated


pytestmark_ps = pytest.mark.skipif(SHELL is None, reason="PowerShell indisponível")


@pytestmark_ps
@pytest.mark.parametrize("changes,expected,installed", [
    ({}, "reinício não exigido", True),
    ({"reboot": True}, "Reinício necessário", True),
    ({"admin": False}, "como Administrador", False),
    ({"pending_reboot": True}, "reinício pendente", False),
    ({"busy": True}, "em andamento", False),
    ({"updates": []}, "não é oferecida", False),
    ({"download_ok": False, "download_code": 4}, "Falha no download", False),
    ({"download_ok": False, "download_code": 2}, "Falha no download", False),   # result OK but IsDownloaded false
    ({"install_code": 4, "item_code": 4}, "falhou", True),
    ({"install_code": 3, "item_code": 2}, "sucesso parcial", True),
    ({"install_code": 5, "item_code": 5}, "cancelada", True),
    ({"updates": [dict(BASE["updates"][0], user_input=True)]}, "interação", False),
])
def test_powershell_install_command_with_simulated_com(command, changes, expected, installed):
    code, output = run_command(command["command"], **changes)
    assert expected in output, output
    assert ("INSTALLED=True" in output) == installed or code != 0, output
    if expected not in ("reinício não exigido", "Reinício necessário"):
        assert code != 0, output  # stops with an error
    assert "Restart-Computer" not in command["command"]


@pytestmark_ps
def test_license_requires_explicit_acceptance(command):
    pending = [dict(BASE["updates"][0], eula_accepted=False)]
    code, output = run_command(command["command"], updates=pending)
    assert code != 0 and "aceite da licença" in output and "INSTALLED=True" not in output
    accepted = command["command"].replace("$AcceptEula = $false", "$AcceptEula = $true")
    code, output = run_command(accepted, updates=pending)
    assert "EULA=script" in output and "INSTALLED=True" in output, output


@pytestmark_ps
def test_selection_is_restricted_to_the_validated_update(command):
    other = [dict(BASE["updates"][0], update_id="99999999-2222-4333-8444-555555555555")]
    code, output = run_command(command["command"], updates=other)
    assert code != 0 and "não é oferecida" in output


@pytestmark_ps
def test_simulation_never_downloads_or_installs(command):
    code, output = run_command(command["simulation"])
    assert code == 0 and "Oferecida" in output and "INSTALLED=False" in output


# ----------------------------------------------------------------------
# 4. Native architecture and Sysnative
# ----------------------------------------------------------------------

def test_wrapper_prefers_sysnative_powershell():
    text = (ROOT / "agents" / "eyemole-collect.cmd").read_text(encoding="utf-8")
    assert "Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe" in text
    assert text.index("Sysnative") < text.index("-File")


@pytest.mark.parametrize("value,expected", [("X64", "x64"), ("Arm64", "ARM"), ("X86", "x86"), ("AMD64", "x64"),
                                            ("ARM64", "ARM"), ("x86", "x86")])
def test_architecture_names_reported_by_the_collector(value, expected):
    assert windows_fix.normalize_arch(value) == expected


@pytest.mark.skipif(os.name != "nt", reason="Windows real")
def test_real_windows_wrapper_runs_native_powershell_from_32_bit(tmp_path):
    shutil.copy(ROOT / "agents" / "eyemole-collect.cmd", tmp_path / "eyemole-collect.cmd")
    (tmp_path / "eyemole-collect.ps1").write_text("Write-Output ('64BIT=' + [Environment]::Is64BitProcess)", encoding="utf-8")
    cmd32 = Path(os.environ["SystemRoot"]) / "SysWOW64" / "cmd.exe"
    if not cmd32.exists():
        pytest.skip("Windows de 32 bits: não há processo de 32 bits sobre 64 bits")
    done = subprocess.run([str(cmd32), "/c", str(tmp_path / "eyemole-collect.cmd")], capture_output=True, text=True,
                          timeout=120, stdin=subprocess.DEVNULL)
    assert "64BIT=True" in done.stdout, done.stdout + done.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows real")
def test_real_windows_native_architecture_and_build_from_32_bit_powershell():
    ps32 = Path(os.environ["SystemRoot"]) / "SysWOW64" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not ps32.exists():
        pytest.skip("Windows de 32 bits")
    script = (f". '{ROOT / 'agents' / 'eyemole-collect.ps1'}'; $b = Get-EyeMoleWindowsBuild | ConvertFrom-Json; "
              "'ARCH=' + $b.Architecture; 'PROC=' + $b.ProcessArchitecture; 'BUILD=' + $b.CurrentBuild; 'UBR=' + $b.UBR")
    done = subprocess.run([str(ps32), "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True,
                          timeout=120)
    lines = dict(line.split("=", 1) for line in done.stdout.split() if "=" in line)
    native = os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE")
    assert windows_fix.normalize_arch(lines.get("ARCH")) == windows_fix.normalize_arch(native), done.stdout + done.stderr
    assert windows_fix.normalize_arch(lines.get("PROC")) == "x86"  # really ran as a 32-bit process
    assert lines.get("BUILD", "").isdigit() and lines.get("UBR", "").isdigit()
