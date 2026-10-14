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


def ps_quote(value):
    """PowerShell single-quoted literal (doubling quotes); parameters are validated before this."""
    return "'" + str(value).replace("'", "''") + "'"


def commands(kb, fixed_build, reboot):
    """PowerShell (administrator) through the Windows Update Agent API: installs the KB only if the
    asset's own channel (Windows Update/WSUS) offers it; never downloads from other sources."""
    if not KB.fullmatch(kb or "") or not parse_windows_build(fixed_build or ""):
        return None
    number = ps_quote(kb[2:])
    search = (f"$kb={number}; $s=New-Object -ComObject Microsoft.Update.Session; "
              "$u=@($s.CreateUpdateSearcher().Search(\"IsInstalled=0 and Type='Software'\").Updates | "
              "Where-Object { $_.KBArticleIDs -contains $kb })")
    ubr = parse_windows_build(fixed_build)[3]
    return {
        "terminal": "PowerShell (Executar como administrador)",
        "shell": "powershell",
        "privilege": "Administrador local",
        "reboot": REBOOT.get(str(reboot or "").lower(), "não informado pela Microsoft"),
        "command": ("$ErrorActionPreference='Stop'; " + search + "; if ($u.Count -eq 0) { throw \"KB$kb não é oferecida "
                    "pelo canal de atualização deste servidor (Windows Update/WSUS).\" }; "
                    "$c=New-Object -ComObject Microsoft.Update.UpdateColl; foreach ($x in $u) { [void]$c.Add($x) }; "
                    "$d=$s.CreateUpdateDownloader(); $d.Updates=$c; [void]$d.Download(); "
                    "$i=$s.CreateUpdateInstaller(); $i.Updates=$c; $r=$i.Install(); "
                    "\"ResultCode=$($r.ResultCode) RebootRequired=$($r.RebootRequired)\""),
        "simulation": (search + "; if ($u.Count) { 'Oferecida pelo canal: ' + $u[0].Title } "
                       "else { \"KB$kb não oferecida pelo canal deste servidor\" }"),
        "prerequisites": ["PowerShell aberto como Administrador.",
                          "Janela de manutenção aprovada (a atualização pode exigir reinício).",
                          "Pré-requisitos (ex.: SSU) indicados na página da KB devem estar instalados."],
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
    by_kb = {}
    for e in matched:
        by_kb.setdefault(e["kb"], []).append(e)
    primary = [kb for kb, rows in by_kb.items() if any(r.get("download_name") == "Security Update" for r in rows)] or list(by_kb)
    builds = {r.get("fixed_build") for kb in primary for r in by_kb[kb] if r.get("fixed_build")}
    if len(primary) > 1 or len(builds) > 1:
        out["conflict"] = True
        pending.append("A Microsoft lista mais de uma atualização principal ou builds divergentes para este produto; "
                       "confirme na página da KB qual se aplica.")
    kb = sorted(primary)[0]
    rows = by_kb[kb]
    fixed = sorted(builds)[0] if builds else None
    reboot = next((r.get("reboot") for r in rows if r.get("reboot")), None)
    out.update(kb=kb, fixed_build=fixed, distribution_fixed_version=fixed, distribution_status="fixed",
               evidence_used=[r["id"] for r in rows], reboot=REBOOT.get(str(reboot or "").lower()))
    hotfixes = context.get("hotfixes")
    installed_branch_cmp = None
    if fixed and _branch(fixed) == _branch(context["os_build"]):
        installed_branch_cmp = (_ubr(context["os_build"]) or 0) - (_ubr(fixed) or 0)
    superseded = sorted({r["supersedes"] for r in rows if r.get("supersedes")})
    if hotfixes is not None and kb in hotfixes:
        out["installed"] = "kb_installed"
    elif installed_branch_cmp is not None and installed_branch_cmp >= 0:
        out["installed"] = "build_at_or_after_fix"
    if superseded and hotfixes and set(superseded) & set(hotfixes) and not out.get("installed"):
        notes.append(f"Instalada a {', '.join(sorted(set(superseded) & set(hotfixes)))}, substituída por {kb}; "
                     "a correção desta CVE está na atualização mais recente.")
    if hotfixes is None:
        pending.append("Lista de hotfixes instalados não coletada: não é possível confirmar se a KB já está instalada.")
    offered = (context.get("channel") or {}).get(kb)
    out["repository_status"] = ("candidate_fixes" if offered is True else "candidate_not_fixed" if offered is False
                                else "not_observed")
    out["candidate_version"] = kb if offered is True else None
    stale = any(e.get("stale") for e in rows) or now_expired
    if stale:
        pending.append("Evidência da Microsoft antiga ou expirada; a análise será refeita.")
    templates = commands(kb, fixed, reboot) if fixed else None
    if out.get("installed"):
        out["classification"] = "requires_verification"
        pending.append({"kb_installed": f"{kb} já consta como instalada; o achado pode estar desatualizado — aguarde nova coleta.",
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
                   "evidence_ids": [r["id"] for r in rows],
                   "rationale": f"A Microsoft publicou {kb} (build {fixed}) para {', '.join(out['matched_products'])}."}
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
