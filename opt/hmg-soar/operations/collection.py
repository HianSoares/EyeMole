"""Automatic read-only collection of installation context through the authorized agent.

Flow (no shell for the model, no free commands):
1. The worker decides which fixed actions are missing for one installation
   (plan_actions) and sends a signed request through Wazuh active response
   ("!eyemole-collect"). Parameters are validated here and again by the agent.
2. The agent receiver (agents/eyemole-collect.py or .ps1) verifies the HMAC,
   expiry and its own agent ID, runs only the fixed read-only actions and
   uploads the outputs to /soar-api/agent-context/<agent_id> with its token.
3. receive() checks the pending request (project, agent, expiry, requested
   actions), parses the outputs with the strict diagnostic parsers and stores
   a diagnostic of origin "agent" for that installation. Every use re-validates
   it (identity, coherence, expiry) like an imported one.

Missing integration, key or agent support is reported with the exact data that
is missing and the manual diagnostic that provides it; manual import remains.
"""
import base64
import datetime as dt
import hashlib
import hmac
import json
import re
import uuid

from . import diagnostics
from .connectors import Wazuh
from .security import OperationError

PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}")
ACTIONS = {
    "os_release": ("linux", ()),
    "dpkg_source": ("linux", ("package",)),
    "apt_policy": ("linux", ("package",)),
    "windows_build": ("windows", ()),
    "windows_hotfixes": ("windows", ()),
    # Windows Update metadata of the asset's own channel for the CVE and the KBs listed by MSRC
    # (UpdateID, KBs, CVE IDs, SupersededUpdateIDs): proves which successor is offered.
    "wu_updates": ("windows", ("cve", "kbs")),
    "windows_feature": ("windows", ("name",)),
}
PARAM = {"package": PACKAGE, "name": re.compile(r"[A-Za-z0-9-]{1,64}"), "cve": re.compile(r"CVE-\d{4}-\d{4,7}"),
         "kbs": re.compile(r"KB\d{6,8}(,KB\d{6,8}){0,9}")}
GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
MAX_UPDATES = 50
LABELS = {
    "os_release": ("release do sistema (/etc/os-release)", "grep -E '^(ID|VERSION_ID|VERSION_CODENAME)=' /etc/os-release"),
    "dpkg_source": ("pacote fonte e versão instalada",
                    "dpkg-query -W -f='${binary:Package} ${Version} ${source:Package} ${source:Version}\\n' {package}"),
    "apt_policy": ("Candidate e suítes do repositório", "apt-cache policy {package}"),
    "windows_build": ("build e edição do Windows",
                      "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' | "
                      "Select-Object ProductName,EditionID,InstallationType,CurrentBuild,UBR"),
    "windows_hotfixes": ("hotfixes instalados", "Get-HotFix | Select-Object -ExpandProperty HotFixID"),
    "wu_updates": ("atualizações oferecidas pelo canal do ativo (Windows Update/WSUS) para {cve} ({kbs})",
                   "$s=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); "
                   "$s.IncludePotentiallySupersededUpdates=$true; $s.Search(\"IsInstalled=0 and IsHidden=0 and "
                   "Type='Software'\").Updates | Select-Object Title,@{n='UpdateID';e={$_.Identity.UpdateID}},"
                   "KBArticleIDs,CveIDs,SupersededUpdateIDs"),
    "windows_feature": ("estado do recurso {name}", "Get-WindowsFeature -Name {name} | Select-Object Name,InstallState"),
}
MAX_OUTPUT = 32 * 1024


def _now():
    return dt.datetime.now(dt.timezone.utc)


def action_key(item):
    kind = item["action"]
    if kind == "wu_updates":
        return f"wu_updates:{item['cve']}"
    if kind == "windows_feature":
        return f"windows_feature:{item['name']}"
    return kind


def validate_action(item):
    if not isinstance(item, dict) or item.get("action") not in ACTIONS:
        raise OperationError("Ação de coleta não permitida.")
    params = ACTIONS[item["action"]][1]
    if set(item) != {"action", *params} or any(not PARAM[p].fullmatch(str(item[p])) for p in params):
        raise OperationError("Parâmetros de coleta inválidos.")
    return dict(item)


def describe(item):
    """Exact missing datum and the manual read-only diagnostic that provides it."""
    label, script = LABELS[item["action"]]
    values = {"package": item.get("package", ""), "name": item.get("name", ""), "cve": item.get("cve", ""),
              "kbs": item.get("kbs", "")}
    for key, value in values.items():
        label, script = label.replace("{" + key + "}", value), script.replace("{" + key + "}", value)
    return {"key": action_key(item), "missing": label, "diagnostic": script,
            "shell": "powershell" if ACTIONS[item["action"]][0] == "windows" else "bash"}


def plan_actions(context, assessment=None, requirement_checks=()):
    """Fixed read-only actions that would complete the context of this installation."""
    actions = []
    usable = bool((context.get("diagnostic") or {}).get("used"))  # a valid (re-validated) import or collection
    missing = set(context.get("missing") or [])
    if context.get("distribution") in ("debian", "ubuntu") and context.get("package_manager") == "apt":
        package = context.get("binary_package")
        if PACKAGE.fullmatch(package or "") and (not usable or missing & {"release", "source_package", "repository_candidate"}):
            actions = [{"action": "os_release"}, {"action": "dpkg_source", "package": package},
                       {"action": "apt_policy", "package": package}]
    elif context.get("distribution") == "windows":
        if not usable or {"os_build", "architecture", "hotfixes"} & set(context.get("missing") or []):
            actions = [{"action": "windows_build"}, {"action": "windows_hotfixes"}]
        listed = [k for k in (assessment or {}).get("listed_kbs") or [] if PARAM["kbs"].fullmatch(k)][:10]
        if listed and context.get("channel_updates") is None and not (assessment or {}).get("installed") \
                and PARAM["cve"].fullmatch(str(context.get("cve") or "")):
            actions.append({"action": "wu_updates", "cve": context["cve"], "kbs": ",".join(listed)})
        for check in requirement_checks:
            if check["action"] == "windows_feature":
                actions.append({"action": "windows_feature", "name": check["name"]})
        if actions and not any(a["action"] == "windows_build" for a in actions):
            actions = [{"action": "windows_build"}, {"action": "windows_hotfixes"}] + actions
    return [validate_action(a) for a in actions]


def _b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def sign(payload, key):
    """The agent verifies HMAC-SHA256 over the exact payload text (no JSON canonicalization)."""
    if not isinstance(key, str) or len(key) < 32:
        raise OperationError("Chave de coleta do agente ausente ou curta (mínimo 32 caracteres).", 503)
    text = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    packet = {"p": text, "s": hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()}
    return _b64(json.dumps(packet, separators=(",", ":")).encode())


def settings_of(cfg):
    block = (cfg.get("integrations") or {}).get("collection") if isinstance(cfg, dict) else None
    return block if isinstance(block, dict) and block.get("enabled") else None


def request(store, project, cfg, secrets, installation, actions, actor, now=None, wazuh=None):
    """Send (or reuse) a collection request. Returns its public state; never raises for missing setup."""
    now = now or _now()
    wazuh = wazuh or Wazuh  # resolved at call time (replaceable in tests)
    agent, finding_id = installation["agent_id"], installation["finding_id"]
    pending_key = hashlib.sha256(f"collect:{agent}:{finding_id}".encode()).hexdigest()
    wanted = sorted(action_key(a) for a in actions)
    try:
        current = _public_view(store, project, store.get(project, "collection_pending", pending_key))
    except OperationError:
        current = None
    if current and current.get("actions") == wanted and dt.datetime.fromisoformat(current["expires_at"]) > now:
        return dict(current, reused=True)  # same actions still pending (or failed recently): no new dispatch
    collection = settings_of(cfg)
    reason = None
    if not collection:
        reason = "Coleta automática pelo agente desabilitada (integrations.collection)."
    elif not (cfg.get("integrations") or {}).get("wazuh", {}).get("enabled"):
        reason = "Integração Wazuh desabilitada: não há canal para solicitar a coleta ao agente."
    key = None
    if not reason:
        try:
            key = json.loads(secrets.get("EYEMOLE_COLLECTOR_KEYS", "{}")).get(agent)
        except ValueError:
            key = None
        if not key:
            reason = f"Chave de coleta do agente {agent} não configurada (EYEMOLE_COLLECTOR_KEYS)."
    expiry = dt.timedelta(minutes=min(max(int((collection or {}).get("expiry_minutes", 10)), 2), 60))
    state = {"agent_id": agent, "finding_id": finding_id, "actions": wanted, "requested_at": now.isoformat(timespec="seconds"),
             "expires_at": (now + expiry).isoformat(timespec="seconds"),
             "missing": [describe(a) for a in actions]}
    if reason:
        state.update(state="unavailable", reason=reason)
        return state
    request_id = uuid.uuid4().hex
    payload = {"id": request_id, "project": project, "agent_id": agent, "finding_id": finding_id, "actions": actions,
               "issued_at": int(now.timestamp()), "expires_at": int((now + expiry).timestamp())}
    try:
        argument = sign(payload, key)
    except OperationError as exc:
        state.update(state="unavailable", reason=str(exc))
        return state
    # Persisted BEFORE dispatch: an agent answering while collect() is still running finds the request.
    state.update(state="dispatching", request_id=request_id)
    record = dict(state, project=project, installation={k: installation.get(k) for k in (
        "package", "version", "architecture", "distribution", "release", "os_version")}, request_payload=payload)
    with store.transaction() as conn:
        store.put(project, "collection_request", request_id, record, actor, "collection.requested", conn=conn)
        store.put(project, "collection_pending", pending_key, state, actor, "collection.requested", conn=conn)
    try:
        client = wazuh((cfg.get("integrations") or {})["wazuh"], secrets)
        client.login()
        client.collect(agent, argument, windows=installation.get("distribution") == "windows")
        outcome = {"state": "pending"}
    except (OperationError, KeyError) as exc:
        outcome = {"state": "failed", "reason": f"Falha ao solicitar a coleta ao agente: {exc}"}
    return _settle(store, project, request_id, pending_key, outcome, actor)


PUBLIC = ("agent_id", "finding_id", "actions", "requested_at", "expires_at", "missing", "request_id", "state", "reason",
          "received_at")
FINAL = ("received", "rejected", "failed")


def _data(record):
    return {k: v for k, v in record.items() if k not in ("id", "project", "version", "updated_at")}


def _sync_public(store, project, pending_key, record, actor, conn):
    """Mirror the canonical request into collection_pending, inside the caller's transaction (write lock held).

    The mirror is rewritten from the request just re-read under the same lock, so it can never
    regress a final state; a newer request for the same finding is left untouched."""
    public = {k: record.get(k) for k in PUBLIC}
    try:
        mirror = store.get(project, "collection_pending", pending_key, conn)
    except OperationError:
        mirror = None
    if mirror is None or (mirror.get("request_id") == record["id"] and
                          {k: mirror.get(k) for k in PUBLIC} != public):
        store.put(project, "collection_pending", pending_key, public, actor, "collection." + record["state"], conn=conn)
    return {k: v for k, v in public.items() if v is not None}


def _settle(store, project, request_id, pending_key, outcome, actor):
    """dispatching → pending/failed, unless the agent already answered (received/rejected are final).

    Re-read, transition and public synchronization run in one SQLite transaction (BEGIN IMMEDIATE):
    an upload either completes before (and is kept) or waits until this one commits."""
    with store.transaction() as conn:
        current = store.get(project, "collection_request", request_id, conn)
        if current.get("state") == "dispatching":
            current = store.put(project, "collection_request", request_id, dict(_data(current), **outcome, project=project),
                                actor, "collection.dispatched" if outcome["state"] == "pending"
                                else "collection.dispatch_failed", current["version"], conn)
        return _sync_public(store, project, pending_key, current, actor, conn)


def _output(results, key):
    item = results.get(key)
    if item is None:
        return None
    if not isinstance(item, dict) or set(item) - {"ok", "output", "error"} or not isinstance(item.get("ok"), bool):
        raise OperationError("Resultado de coleta fora do contrato.")
    text = item.get("output") or ""
    if not isinstance(text, str) or len(text.encode()) > MAX_OUTPUT:
        raise OperationError("Saída de coleta inválida ou acima do limite.")
    return text if item["ok"] else None


def _windows(results, wanted):
    parsed = {}
    build = _output(results, "windows_build")
    if build:
        data = json.loads(build)
        product = str(data.get("ProductName") or "")[:160]
        current, ubr = str(data.get("CurrentBuild") or ""), data.get("UBR")
        if not re.fullmatch(r"\d{4,6}", current) or not isinstance(ubr, int) or not 0 <= ubr < 10 ** 6:
            raise OperationError("Build do Windows coletado em formato inválido.")
        parsed["windows"] = {"product_name": product, "edition_id": str(data.get("EditionID") or "")[:64],
                             "installation_type": str(data.get("InstallationType") or "")[:32],
                             "current_build": current, "ubr": ubr, "architecture": str(data.get("Architecture") or "")[:16]}
    hotfixes = _output(results, "windows_hotfixes")
    if hotfixes is not None:
        items = json.loads(hotfixes) if hotfixes.strip() else []
        if not isinstance(items, list) or any(not re.fullmatch(r"KB\d{6,8}", str(i).upper()) for i in items):
            raise OperationError("Lista de hotfixes coletada em formato inválido.")
        parsed["hotfixes"] = sorted({str(i).upper() for i in items})
    for key in wanted:
        if key.startswith("wu_updates:"):
            text = _output(results, key)
            if text:
                parsed["wu_updates"] = _wu_updates(json.loads(text), key.split(":", 1)[1])
                offered = {f"KB{k}" for u in parsed["wu_updates"]["updates"] for k in u["kb_ids"]}
                parsed["wu_offered"] = {kb: kb in offered for kb in parsed["wu_updates"]["kbs"]} | {kb: True for kb in offered}
        if key.startswith("windows_feature:"):
            text = _output(results, key)
            if text:
                data = json.loads(text)
                state = str(data.get("InstallState") or data.get("State") or "")
                if not re.fullmatch(r"[A-Za-z]{1,32}", state):
                    raise OperationError("Estado de recurso do Windows em formato inválido.")
                parsed.setdefault("features", {})[key.split(":", 1)[1]] = state
    return parsed


def _wu_updates(data, cve):
    """Strict schema of the Windows Update metadata collected by the agent."""
    if not isinstance(data, dict) or data.get("cve") != cve or not isinstance(data.get("updates"), list):
        raise OperationError("Metadados do Windows Update em formato inválido.")
    kbs = data.get("kbs") if isinstance(data.get("kbs"), list) else []
    if any(not re.fullmatch(r"KB\d{6,8}", str(k)) for k in kbs) or len(data["updates"]) > MAX_UPDATES:
        raise OperationError("Metadados do Windows Update em formato inválido.")
    updates = []
    for item in data["updates"]:
        if not isinstance(item, dict) or not GUID.fullmatch(str(item.get("update_id") or "")):
            raise OperationError("Atualização sem UpdateID válido nos metadados do Windows Update.")
        lists = {}
        for field, pattern in (("kb_ids", r"\d{6,8}"), ("cve_ids", r"CVE-\d{4}-\d{4,7}"), ("superseded_update_ids", GUID.pattern)):
            values = item.get(field) or []
            if not isinstance(values, list) or len(values) > 200 or any(not re.fullmatch(pattern, str(v)) for v in values):
                raise OperationError(f"Campo {field} inválido nos metadados do Windows Update.")
            lists[field] = [str(v) for v in values]
        updates.append({"update_id": str(item["update_id"]).lower(), "title": str(item.get("title") or "")[:200],
                        **{k: ([v.lower() for v in vals] if k == "superseded_update_ids" else vals) for k, vals in lists.items()},
                        "is_downloaded": bool(item.get("is_downloaded")), "eula_accepted": bool(item.get("eula_accepted"))})
    return {"cve": cve, "kbs": [str(k) for k in kbs], "updates": updates}


def receive(store, project, agent_id, body, now=None):
    """Store the agent upload for the pending request. Raises OperationError for anything unexpected."""
    now = now or _now()
    if not isinstance(body, dict) or set(body) != {"request_id", "agent_id", "collected_at", "results"}:
        raise OperationError("Envio do agente fora do contrato.")
    if body["agent_id"] != agent_id or not re.fullmatch(r"[a-f0-9]{32}", str(body["request_id"])):
        raise OperationError("Envio do agente com identificação inválida.", 403)
    try:
        request_record = store.get(project, "collection_request", body["request_id"])
    except OperationError:
        raise OperationError("Pedido de coleta desconhecido.", 404)
    _check_open(request_record, agent_id, project, now)
    results = body["results"]
    if not isinstance(results, dict) or not set(results) <= set(request_record["actions"]):
        raise OperationError("O agente enviou ações não solicitadas.", 400)
    installation = dict(request_record["installation"], finding_id=request_record["finding_id"], agent_id=agent_id)
    collected_at = str(body["collected_at"])
    try:
        if installation.get("distribution") == "windows":
            parsed = _windows(results, request_record["actions"])
            record = diagnostics.build_collected(parsed, installation, collected_at, now)
        else:
            outputs = {"collected_at": collected_at}
            for key, field in (("dpkg_source", "dpkg_query"), ("apt_policy", "apt_cache_policy"), ("os_release", "os_release")):
                text = _output(results, key)
                if text:
                    outputs[field] = text
            record = diagnostics.build_import(outputs, installation, f"agent:{agent_id}", now)
            record.update(origin="agent", confidence="collected_by_agent")
    except (ValueError, OperationError) as exc:
        record, refusal = None, exc
    else:
        refusal = None
    actor = f"agent:{agent_id}"
    pending_key = hashlib.sha256(f"collect:{agent_id}:{installation['finding_id']}".encode()).hexdigest()
    # Single use and all-or-nothing: under the write lock, re-check the request, conclude it, persist the
    # diagnostic and mirror the public state in one transaction. A failure leaves the request open.
    with store.transaction() as conn:
        current = store.get(project, "collection_request", body["request_id"], conn)
        _check_open(current, agent_id, project, now)
        if refusal is None:
            current = store.put(project, "collection_request", current["id"], dict(
                _data(current), state="received", received_at=now.isoformat(timespec="seconds"), project=project),
                actor, "collection.received", current["version"], conn)
            record["request_id"] = body["request_id"]
            key = hashlib.sha256(f"diag:{agent_id}:{installation['finding_id']}".encode()).hexdigest()
            store.put(project, "diagnostic_import", key, record, actor, "diagnostic.collected", conn=conn)
            store.put(project, "diagnostic_history", hashlib.sha256(
                f"diag:{record['revision']}:{record['imported_at']}:{agent_id}:{installation['finding_id']}".encode()
            ).hexdigest(), record, actor, "diagnostic.archived", conn=conn)
        else:
            current = store.put(project, "collection_request", current["id"], dict(
                _data(current), state="rejected", reason=f"Coleta recebida, mas recusada: {refusal}", project=project),
                actor, "collection.rejected", current["version"], conn)
        _sync_public(store, project, pending_key, current, actor, conn)
    if refusal is not None:
        raise OperationError(f"Coleta recusada: {refusal}", 409)
    return {"status": "accepted", "request_id": body["request_id"]}


def _check_open(request_record, agent_id, project, now):
    if request_record.get("agent_id") != agent_id or request_record.get("project") != project:
        raise OperationError("Pedido de coleta de outro agente ou projeto.", 403)
    if request_record.get("state") not in ("pending", "dispatching"):
        # received/rejected/failed: single use (replay protection); a failed dispatch is not trusted later.
        raise OperationError("Pedido de coleta já concluído ou não enviado.", 409)
    if now > dt.datetime.fromisoformat(request_record["expires_at"]):
        raise OperationError("Pedido de coleta expirado.", 409)


def receive_upload(agent_id, body, store=None, config=None, now=None):
    """Entry point of POST /agent-context/<agent_id> (agent token already verified by the API)."""
    from .security import load_config
    from .store import Store
    store = store or Store()
    config = config or load_config()
    request_id = body.get("request_id") if isinstance(body, dict) else None
    if not isinstance(request_id, str) or not re.fullmatch(r"[a-f0-9]{32}", request_id):
        raise OperationError("Envio do agente sem pedido válido.")
    for project in (config.get("projects") or {}):
        try:
            store.get(project, "collection_request", request_id)
        except OperationError:
            continue
        return receive(store, project, agent_id, body, now)
    raise OperationError("Pedido de coleta desconhecido.", 404)


def _public_view(store, project, mirror):
    """Public state derived from the canonical request (collection_request); the mirror only points to it."""
    state = dict(mirror)
    if state.get("request_id"):
        try:
            canonical = store.get(project, "collection_request", state["request_id"])
        except OperationError:
            return state
        for k in PUBLIC:
            if canonical.get(k) is None:
                state.pop(k, None)
            else:
                state[k] = canonical[k]
    return state


def pending_state(store, project, agent, finding_id, now=None):
    now = now or _now()
    key = hashlib.sha256(f"collect:{agent}:{finding_id}".encode()).hexdigest()
    try:
        state = _public_view(store, project, store.get(project, "collection_pending", key))
    except OperationError:
        return None
    if state.get("state") in ("pending", "dispatching") and now > dt.datetime.fromisoformat(state["expires_at"]):
        state.update(state="expired", reason="O agente não respondeu dentro do prazo (coleta automática indisponível?).")
    return state
