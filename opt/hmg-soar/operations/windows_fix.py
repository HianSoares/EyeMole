"""Windows (operating system) remediation: product identity, KB selection and commands.

Evidence comes from the Microsoft Security Update Guide (research_sources.msrc_sug).
The engine, not the model, decides:
- which MSRC product rows describe the asset (build branch major.minor.build,
  server/client, architecture, Server Core when known);
- whether the asset already has the fix (KB in the hotfix list, or OS build
  at/after the fixed build of the same branch), or an older superseded KB;
- whether the KB is offered by the asset's own update channel (Windows
  Update/WSUS), observed only through a read-only collection;
- the PowerShell command, from a fixed template with validated parameters.

Only Windows operating system updates published by MSRC are supported here;
other Windows products are reported as not supported (no generic update).
"""
import re

from remediation.versioning import parse_windows_build

KB = re.compile(r"KB\d{6,8}")
_ARCH = {"x86_64": "x64", "amd64": "x64", "x64": "x64", "arm64": "ARM", "aarch64": "ARM", "arm": "ARM",
         "x86": "x86", "i686": "x86", "i386": "x86", "32-bit": "x86"}
REBOOT = {"yes": "obrigatório", "maybe": "possível (depende do estado do sistema)", "no": "não necessário"}


def normalize_arch(value):
    return _ARCH.get(str(value or "").strip().lower())


def _branch(version):
    parsed = parse_windows_build(version or "")
    return ".".join(str(p) for p in parsed[:3]) if parsed else None


def _ubr(version):
    parsed = parse_windows_build(version or "")
    return parsed[3] if parsed else None


def resolve_windows(row, plan, inventory=None, parsed=None, diag_origin=None):
    """Asset facts with origin: collected/imported diagnostic > Wazuh inventory > snapshot row."""
    parsed = parsed or {}
    inventory = inventory or {}
    os_inv = inventory.get("os") or {}
    inv_origin = {"origin": "wazuh_syscollector", "observed_at": inventory.get("observed_at")}
    out = {"distribution": "windows", "origins": {}, "missing": []}
    win = parsed.get("windows") or {}
    name = win.get("product_name") or os_inv.get("name") or row.get("package") or ""
    out["product_name"] = str(name)[:160]
    out["installation_type"] = win.get("installation_type")
    if win.get("current_build") and win.get("ubr") is not None:
        version = f"10.0.{win['current_build']}.{win['ubr']}" if str(win["current_build"]).isdigit() else None
        if version and parse_windows_build(version):
            out["os_build"], out["origins"]["os_build"] = version, diag_origin
    if "os_build" not in out:
        for candidate, origin in ((os_inv.get("version"), inv_origin), (row.get("version"), {"origin": "wazuh_snapshot"}),
                                  (row.get("os_version"), {"origin": "wazuh_snapshot"})):
            if parse_windows_build(str(candidate or "")):
                out["os_build"], out["origins"]["os_build"] = str(candidate), origin
                break
    arch = normalize_arch(win.get("architecture")) or normalize_arch(inventory.get("architecture")) \
        or normalize_arch(row.get("package_architecture") or row.get("architecture"))
    out["architecture"] = arch
    if arch:
        out["origins"]["architecture"] = diag_origin if normalize_arch(win.get("architecture")) else inv_origin \
            if normalize_arch(inventory.get("architecture")) else {"origin": "wazuh_snapshot"}
    out["os_class"] = "server" if "server" in out["product_name"].lower() else "client" if out["product_name"] else None
    hotfixes, origin = None, None
    if isinstance(parsed.get("hotfixes"), list):
        hotfixes, origin = parsed["hotfixes"], diag_origin
    elif isinstance(inventory.get("hotfixes"), list) and inventory.get("hotfixes_complete"):
        hotfixes, origin = inventory["hotfixes"], inv_origin
    out["hotfixes"] = sorted({h.upper() for h in hotfixes if KB.fullmatch(str(h).upper())}) if hotfixes is not None else None
    if origin:
        out["origins"]["hotfixes"] = origin
    out["channel"] = {k: v for k, v in (parsed.get("wu_offered") or {}).items() if KB.fullmatch(k)}
    out["channel_updates"] = parsed.get("wu_updates")
    if out["channel"]:
        out["origins"]["channel"] = diag_origin
    out["features"] = dict(parsed.get("features") or {})
    for key, label in (("os_build", "build do sistema"), ("architecture", "arquitetura"), ("hotfixes", "hotfixes instalados")):
        if out.get(key) is None:
            out["missing"].append(key)
    return out


def _row_matches(evidence, ctx):
    branch = _branch(ctx.get("os_build"))
    base = str(evidence.get("base_version") or "")
    if not branch or not base.startswith(branch + "."):
        return False
    product = str(evidence.get("product") or "")
    if ctx.get("os_class") == "server" and not product.startswith("Windows Server"):
        return False
    if ctx.get("os_class") == "client" and product.startswith("Windows Server"):
        return False
    return normalize_arch(evidence.get("architecture")) == ctx.get("architecture")


GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _msrc_graph(listed_rows):
    """KB → KB it supersedes (MSRC "supercedence"), restricted to KBs listed for the asset's product."""
    edges = {}
    for kb, rows in listed_rows.items():
        for row in rows:
            if row.get("supersedes") in listed_rows and row["supersedes"] != kb:
                edges.setdefault(kb, set()).add(row["supersedes"])
    return edges


def _has_cycle(edges):
    state = {}

    def visit(node):
        if state.get(node) == 1:
            return True
        if state.get(node) == 2:
            return False
        state[node] = 1
        if any(visit(n) for n in edges.get(node, ())):
            return True
        state[node] = 2
        return False

    return any(visit(n) for n in list(edges))


def _reach(edges):
    """Transitive closure: node → every node it supersedes directly or through intermediates (acyclic graph)."""
    memo = {}

    def visit(node):
        if node not in memo:
            memo[node] = set()
            for nxt in edges.get(node, ()):
                memo[node] |= {nxt} | visit(nxt)
        return memo[node]

    return {node: visit(node) for node in list(edges)}


def _chain(kb, edges):
    out, seen = [kb], {kb}
    while edges.get(out[-1]):
        nxt = sorted(edges[out[-1]] - seen)
        if not nxt:
            break
        out.append(nxt[0])
        seen.add(nxt[0])
    return out


def select_update(matched, context):
    """Most recent update proven to fix the CVE for this product, preferring what the asset's channel offers.

    Proof of coverage/succession only from: the MSRC listing for the product (and its
    supersedence field), or Windows Update metadata collected on the asset (the offered
    update's CVE IDs or SupersededUpdateIDs reaching a listed KB). KB numbers or textual
    order are never used as evidence of recency. Cycles or several unrelated heads stay
    uncertain (conflict), without validation.
    """
    out = {"kb": None, "rows": [], "fixed_build": None, "update_id": None, "chain": [], "proof": None,
           "offered": None, "notes": [], "pending": [], "conflict": False}
    listed_rows = {}
    for e in matched:
        listed_rows.setdefault(e["kb"], []).append(e)
    primary = {kb for kb, rows in listed_rows.items() if any(r.get("download_name") == "Security Update" for r in rows)} \
        or set(listed_rows)
    out["listed"] = sorted(listed_rows)
    edges = _msrc_graph({kb: listed_rows[kb] for kb in primary})
    if _has_cycle(edges):
        out.update(conflict=True)
        out["pending"].append("A Microsoft descreve um ciclo de supersedência entre as KBs deste produto; não é possível "
                              "determinar a mais recente.")
    superseded_by_msrc = {k for targets in edges.values() for k in targets}
    heads = sorted(primary - superseded_by_msrc) if not out["conflict"] else []

    def listed_fix(kb):
        builds = {r.get("fixed_build") for r in listed_rows.get(kb, []) if r.get("fixed_build")}
        return (sorted(builds)[0] if len(builds) == 1 else None), listed_rows.get(kb, [])

    channel = context.get("channel_updates")
    if channel and isinstance(channel.get("updates"), list):
        updates = [u for u in channel["updates"] if GUID.fullmatch(str(u.get("update_id") or ""))]
        kb_of = {u["update_id"]: [f"KB{k}" for k in u.get("kb_ids", [])] for u in updates}
        covered = {u["update_id"] for u in updates if set(kb_of[u["update_id"]]) & set(listed_rows)}
        covered |= {u["update_id"] for u in updates if context.get("cve") in (u.get("cve_ids") or [])}
        supersedes = {u["update_id"]: set(u.get("superseded_update_ids") or []) for u in updates}
        changed = True
        while changed:  # transitive succession through metadata of the asset's channel
            changed = False
            for uid, older in supersedes.items():
                if uid not in covered and older & covered:
                    covered.add(uid)
                    changed = True
        channel_edges = {uid: older & covered for uid, older in supersedes.items() if uid in covered}
        if _has_cycle(channel_edges):
            out.update(conflict=True, kb=heads[0] if len(heads) == 1 else None)
            out["pending"].append("Os metadados do Windows Update descrevem um ciclo de supersedência; nenhuma "
                                  "atualização é validada.")
        else:
            candidates = sorted(covered)
            # MSRC succession also orders the offered candidates (both listed for the CVE and product), through
            # the whole chain: an intermediate KB proves the relation even when the channel does not offer it.
            # (Channel metadata needs no closure: every update on a path between covered updates is covered.)
            msrc_reach = _reach(edges) if not out["conflict"] else {}
            superseded = {uid for uid in candidates for other in candidates if other != uid and (
                uid in channel_edges.get(other, set()) or
                any(k2 in msrc_reach.get(k1, set()) for k1 in kb_of[other] for k2 in kb_of[uid]))}
            channel_heads = [uid for uid in candidates if uid not in superseded]
            if len(channel_heads) == 1:
                uid = channel_heads[0]
                listed = [k for k in kb_of[uid] if k in listed_rows]
                kb = listed[0] if listed else kb_of[uid][0] if kb_of[uid] else None
                proof = "msrc_listed" if listed else "channel_supersedence"
                base = kb if listed else None
                if not listed:  # find the listed KB this successor reaches
                    frontier, seen = set(supersedes.get(uid, ())), set()
                    while frontier and not base:
                        nxt = frontier.pop()
                        seen.add(nxt)
                        hit = [k for k in kb_of.get(nxt, []) if k in listed_rows]
                        if hit:
                            base = hit[0]
                        frontier |= supersedes.get(nxt, set()) - seen
                    if not base:
                        proof = "channel_cve_metadata"
                fixed, rows = listed_fix(base or (heads[0] if len(heads) == 1 else None))
                chain = [kb] + (_chain(base, edges) if base and base != kb else _chain(kb, edges)[1:] if listed else [])
                out.update(kb=kb, rows=rows, fixed_build=fixed, update_id=uid, chain=list(dict.fromkeys(chain)),
                           proof=proof, offered=True)
                if heads and kb not in heads and listed:
                    out["notes"].append(f"A sucessora {', '.join(heads)} (listada pela Microsoft) não é oferecida pelo canal "
                                        f"do ativo; {kb}, também listada para esta CVE, é a oferecida.")
                if proof == "channel_supersedence":
                    out["notes"].append(f"{kb} é oferecida pelo canal do ativo e substitui {base} (metadados do Windows "
                                        "Update), que a Microsoft lista para esta CVE.")
                return out
            if len(channel_heads) > 1:
                out.update(conflict=True)
                out["pending"].append("O canal do ativo oferece mais de uma atualização que cobre a CVE sem relação de "
                                      "supersedência comprovada; confirme qual aplicar.")
            else:
                out["offered"] = False
    if out["conflict"] and not heads:
        return out
    if len(heads) != 1:
        out["conflict"] = True
        out["pending"].append("A Microsoft lista mais de uma atualização principal para este produto sem relação de "
                              "supersedência; confirme na página da KB qual se aplica.")
        if not heads:
            return out
    kb = heads[0]
    fixed, rows = listed_fix(kb)
    out.update(kb=kb, rows=rows, fixed_build=fixed, chain=_chain(kb, edges), proof="msrc_listed")
    return out


def ps_quote(value):
    """PowerShell single-quoted literal (doubling quotes); parameters are validated before this."""
    return "'" + str(value).replace("'", "''") + "'"


INSTALL_TEMPLATE = r"""$ErrorActionPreference = 'Stop'
# EyeMole: instala somente a atualização validada (__KB__), pelo canal configurado neste servidor (Windows Update/WSUS).
$AcceptEula = $false   # altere para $true somente depois de ler e aceitar a licença da atualização, se ela exigir
$kb = __KBNUM__
$updateId = __UPDATEID__
function Assert-EyeMoleAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Execute este comando no PowerShell como Administrador.' }
}
Assert-EyeMoleAdministrator
if ((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired) {
  throw 'Há um reinício pendente neste servidor: reinicie em janela aprovada antes de instalar a atualização.' }
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$searcher.IncludePotentiallySupersededUpdates = $true
$found = @($searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates | Where-Object {
  ($_.KBArticleIDs -contains $kb) -and ($updateId -eq '' -or $_.Identity.UpdateID -eq $updateId) })
if ($found.Count -ne 1) { throw "KB$kb não é oferecida (ou é ambígua) pelo canal de atualização deste servidor (Windows Update/WSUS)." }
$update = $found[0]
if ($update.InstallationBehavior.CanRequestUserInput) { throw "KB$kb pode exigir interação do usuário; instale-a manualmente." }
if (-not $update.EulaAccepted) {
  if (-not $AcceptEula) { throw "KB$kb exige aceite da licença. Leia o texto (`$update.EulaText) e execute novamente com `$AcceptEula = `$true." }
  $update.AcceptEula()
}
$collection = New-Object -ComObject Microsoft.Update.UpdateColl
[void]$collection.Add($update)
$installer = $session.CreateUpdateInstaller()
if ($installer.IsBusy) { throw 'Outra instalação do Windows Update está em andamento; tente novamente mais tarde.' }
$status = @{ 0 = 'não iniciada'; 1 = 'em andamento'; 2 = 'concluída'; 3 = 'concluída com erros (sucesso parcial)'; 4 = 'falhou'; 5 = 'cancelada' }
if (-not $update.IsDownloaded) {
  $downloader = $session.CreateUpdateDownloader()
  $downloader.Updates = $collection
  $download = $downloader.Download()
  $item = $download.GetUpdateResult(0)
  if ($download.ResultCode -ne 2 -or $item.ResultCode -ne 2 -or -not $update.IsDownloaded) {
    throw ("Falha no download da KB${kb}: " + $status[[int]$download.ResultCode] + ' (ResultCode=' + $download.ResultCode + ', HResult=0x' + ('{0:X8}' -f $download.HResult) + ').') }
}
$installer.Updates = $collection
$result = $installer.Install()
$item = $result.GetUpdateResult(0)
if ($result.ResultCode -ne 2 -or $item.ResultCode -ne 2) {
  throw ("Instalação da KB$kb " + $status[[int]$result.ResultCode] + ' (ResultCode=' + $result.ResultCode + ', HResult=0x' + ('{0:X8}' -f $result.HResult) + '; atualização: ResultCode=' + $item.ResultCode + ', HResult=0x' + ('{0:X8}' -f $item.HResult) + ').') }
if ($result.RebootRequired -or $item.RebootRequired) {
  Write-Warning "KB$kb instalada. Reinício necessário: reinicie o servidor em janela aprovada (nenhum reinício foi feito automaticamente)."
} else { "KB$kb instalada; reinício não exigido." }"""

SIMULATION_TEMPLATE = r"""$kb = __KBNUM__
$updateId = __UPDATEID__
$searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
$searcher.IncludePotentiallySupersededUpdates = $true
$found = @($searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates | Where-Object {
  ($_.KBArticleIDs -contains $kb) -and ($updateId -eq '' -or $_.Identity.UpdateID -eq $updateId) })
if ($found.Count -eq 1) { 'Oferecida pelo canal: ' + $found[0].Title + ' | baixada: ' + $found[0].IsDownloaded + ' | licença aceita: ' + $found[0].EulaAccepted }
else { "KB$kb não oferecida (ou ambígua) pelo canal deste servidor" }"""


def commands(kb, fixed_build, reboot, update_id=None):
    """PowerShell (administrator) through the Windows Update Agent API, from a fixed template.

    Installs only the validated update (KB and, when known, its UpdateID from the asset's
    channel), through the channel configured on the asset; checks administrator, pending
    reboot, busy installer, user input, license (explicit acceptance), download result and
    IsDownloaded, overall and per-update ResultCode/HResult; never reboots.
    """
    if not KB.fullmatch(kb or "") or not parse_windows_build(fixed_build or ""):
        return None
    if update_id is not None and not GUID.fullmatch(str(update_id)):
        return None
    values = {"__KB__": kb, "__KBNUM__": ps_quote(kb[2:]), "__UPDATEID__": ps_quote(update_id or "")}
    install, simulation = INSTALL_TEMPLATE, SIMULATION_TEMPLATE
    for key, value in values.items():
        install, simulation = install.replace(key, value), simulation.replace(key, value)
    ubr = parse_windows_build(fixed_build)[3]
    return {
        "terminal": "PowerShell (Executar como administrador)",
        "shell": "powershell",
        "privilege": "Administrador local",
        "reboot": REBOOT.get(str(reboot or "").lower(), "não informado pela Microsoft"),
        "command": install,
        "simulation": simulation,
        "prerequisites": ["PowerShell aberto como Administrador.",
                          "Janela de manutenção aprovada (a atualização pode exigir reinício).",
                          "Sem reinício pendente (o comando interrompe se houver).",
                          "Pré-requisitos (ex.: SSU) indicados na página da KB devem estar instalados.",
                          "Se a atualização exigir licença, leia-a e altere $AcceptEula para $true antes de executar."],
        "verification": [f"Get-HotFix -Id {kb}",
                         "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').UBR  "
                         f"# esperado: {ubr} ou maior (build {fixed_build})",
                         "Aguardar nova coleta do Wazuh e confirmar que o achado deixou de ser reportado."],
        "rollback": (f"wusa.exe /uninstall /kb:{kb[2:]} /norestart  # atualizações combinadas SSU+LCU podem não "
                     "permitir desinstalação pelo wusa; siga a página da KB (DISM /Remove-Package)"),
    }


def assess(context, collection, now_expired=False):
    """Classify a Windows OS finding. Returns fields merged into the research assessment."""
    evidence = [e for e in collection.get("evidence", []) if e.get("kind") == "windows_kb"]
    sources = [s for s in collection.get("sources", []) if s.get("source") == "msrc_security_update_guide"]
    out = {"distribution_fixed_version": None, "distribution_status": "unknown", "upstream_fixed_versions": [],
           "other_release_fixes": [], "repository_status": "not_observed", "candidate_version": None,
           "candidate_suites": [], "authorized_suites": [], "fix_scope": "windows_update",
           "source_association": "verified", "evidence_used": [], "notes": [], "pending": [], "alternatives": [],
           "kb": None, "fixed_build": None, "installed_build": context.get("os_build"), "matched_products": []}
    pending, notes = out["pending"], out["notes"]
    if sources and not any(s.get("available") for s in sources):
        out["classification"] = "insufficient_data"
        pending.append("Security Update Guide da Microsoft indisponível; a análise será refeita quando a fonte responder.")
        return out
    for key, label in (("os_build", "build do Windows (CurrentBuild/UBR)"), ("architecture", "arquitetura do sistema")):
        if not context.get(key):
            pending.append(f"Dado ausente: {label}.")
    if not context.get("os_build") or not context.get("architecture"):
        out["classification"] = "insufficient_data"
        return out
    matched = [e for e in evidence if _row_matches(e, context)]
    core = str(context.get("installation_type") or "").lower()
    if core:
        wanted = [e for e in matched if ("server core" in str(e.get("product")).lower()) == ("server core" in core)]
        matched = wanted or matched
    out["matched_products"] = sorted({e["product"] for e in matched})
    if not matched:
        same_branch = [e for e in evidence if str(e.get("base_version") or "").startswith((_branch(context["os_build"]) or "-") + ".")]
        if same_branch:
            notes.append("A Microsoft lista KB para este build apenas em outro produto/arquitetura "
                         f"({', '.join(sorted({e['product'] for e in same_branch}))}); nada é aplicável a "
                         f"{context.get('product_name')} ({context['architecture']}).")
        out["classification"] = "no_fix_found" if any(s.get("available") for s in sources) else "insufficient_data"
        if not evidence:
            notes.append("O Security Update Guide não lista atualização para esta CVE.")
        return out
    selection = select_update(matched, context)
    notes.extend(selection["notes"])
    pending.extend(selection["pending"])
    if selection.get("conflict"):
        out["conflict"] = True
    kb, rows, fixed = selection["kb"], selection["rows"], selection["fixed_build"]
    out["listed_kbs"] = selection["listed"]
    if not kb:
        out["classification"] = "requires_verification"
        return out
    reboot = next((r.get("reboot") for r in rows if r.get("reboot")), None)
    out.update(kb=kb, fixed_build=fixed, distribution_fixed_version=fixed, distribution_status="fixed",
               evidence_used=[r["id"] for r in rows], reboot=REBOOT.get(str(reboot or "").lower()),
               update_id=selection.get("update_id"), supersedence_chain=selection["chain"], proof=selection["proof"])
    hotfixes = context.get("hotfixes")
    installed_branch_cmp = None
    if fixed and _branch(fixed) == _branch(context["os_build"]):
        installed_branch_cmp = (_ubr(context["os_build"]) or 0) - (_ubr(fixed) or 0)
    covering = [k for k in [kb] + selection["listed"] if hotfixes and k in hotfixes]
    kb_installed = covering[0] if covering else kb
    if covering:
        out["installed"] = "kb_installed"
    elif installed_branch_cmp is not None and installed_branch_cmp >= 0:
        out["installed"] = "build_at_or_after_fix"
    superseded = sorted({r["supersedes"] for r in rows if r.get("supersedes")} - set(selection["listed"]))
    if superseded and hotfixes and set(superseded) & set(hotfixes) and not out.get("installed"):
        notes.append(f"Instalada a {', '.join(sorted(set(superseded) & set(hotfixes)))}, substituída por {kb}; "
                     "a correção desta CVE está na atualização mais recente.")
    if hotfixes is None:
        pending.append("Lista de hotfixes instalados não coletada: não é possível confirmar se a KB já está instalada.")
    offered = selection["offered"]
    out["repository_status"] = ("candidate_fixes" if offered is True else "candidate_not_fixed" if offered is False
                                else "not_observed")
    out["candidate_version"] = kb if offered is True else None
    stale = any(e.get("stale") for e in rows) or now_expired
    if stale:
        pending.append("Evidência da Microsoft antiga ou expirada; a análise será refeita.")
    templates = commands(kb, fixed, reboot, update_id=selection.get("update_id")) if fixed else None
    if out.get("installed"):
        out["classification"] = "requires_verification"
        pending.append({"kb_installed": f"{kb_installed} (que corrige esta CVE) já consta como instalada; "
                                        "o achado pode estar desatualizado — aguarde nova coleta.",
                        "build_at_or_after_fix": f"O build instalado ({context['os_build']}) já é igual ou posterior a {fixed}; "
                                                 "o achado pode estar desatualizado."}[out["installed"]])
        return out
    validated = (offered is True and hotfixes is not None and not stale and not out.get("conflict") and templates
                 and context["origins"].get("os_build", {}).get("origin") != "wazuh_snapshot")
    out["classification"] = "validated_fix" if validated else "requires_verification"
    if offered is False:
        pending.append(f"{kb} não é oferecida pelo canal de atualização do ativo (WSUS/Windows Update): aprove-a no WSUS "
                       "ou use o pacote do Microsoft Update Catalog.")
    elif offered is None:
        pending.append(f"Oferta de {kb} pelo canal do ativo não observada; o comando verifica isso antes de instalar.")
    if context["origins"].get("os_build", {}).get("origin") == "wazuh_snapshot":
        pending.append("Build do sistema obtido apenas do snapshot de vulnerabilidades; confirme pelo inventário ou coleta.")
    alternative = {"kind": "update_package", "kind_label": "Instalar a atualização de segurança do Windows",
                   "package": context.get("product_name"), "target_version": kb,
                   "fixed_build": fixed, "category": out["classification"], "validated": bool(validated),
                   "evidence_ids": [r["id"] for r in rows], "update_id": selection.get("update_id"),
                   "supersedence_chain": selection["chain"], "proof": selection["proof"],
                   "rationale": (f"A Microsoft publicou {kb} (build {fixed}) para {', '.join(out['matched_products'])}."
                                 if selection["proof"] == "msrc_listed" else
                                 f"{kb} é oferecida pelo canal do ativo e substitui {' → '.join(selection['chain'][1:])}, "
                                 f"que a Microsoft lista para esta CVE em {', '.join(out['matched_products'])}."
                                 if selection["proof"] == "channel_supersedence" else
                                 f"{kb} é oferecida pelo canal do ativo e os metadados do Windows Update a associam a esta CVE.")}
    if templates and offered is not False:
        alternative.update(templates)
    out["alternatives"].append(alternative)
    catalog = next((r.get("catalog_url") for r in rows if r.get("catalog_url")), None)
    if catalog:
        out["alternatives"].append({
            "kind": "other_manual", "package": context.get("product_name"), "target_version": kb, "category": "manual_review",
            "validated": False, "evidence_ids": [r["id"] for r in rows], "catalog_url": catalog,
            "rationale": f"Pacote oficial no Microsoft Update Catalog ({catalog}); instale o .msu correspondente a "
                         f"{context['architecture']} com wusa.exe <arquivo>.msu /quiet /norestart.",
            "terminal": "PowerShell (Executar como administrador)", "privilege": "Administrador local",
            "reboot": REBOOT.get(str(reboot or "").lower(), "não informado pela Microsoft")})
    return out
