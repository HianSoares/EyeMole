"""Single-worker durable queue. Remote integrations and execution are explicit jobs."""
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import signal
import time
import uuid
import re
import shlex
from pathlib import Path

from remediation.versioning import ecosystem_for_package_manager
from .connectors import GLPI, QRadar, VisionOne, Wazuh, vendor_evidence
from . import ai
from .kiro import explain
from .planning import engine_for, source_revision
from .security import load_config, project_config, principal, OperationError
from .service import Operations, read_snapshot, quality, stamp
from .store import Store, now, encode

logger = logging.getLogger("eyemole-worker")


def settings(cfg, name):
    value = cfg.get("integrations", {}).get(name, {})
    if not value.get("enabled"):
        raise OperationError("Integração " + name + " desabilitada.", 503)
    return value


def generate_plans(campaign, cfg):
    metadata, _, before = read_snapshot(cfg)
    if not quality(metadata, [], cfg)["fresh"]:
        raise OperationError("Snapshot desatualizado; colete antes de gerar planos.", 409)
    engine = engine_for(cfg)
    sources_before = source_revision(engine)
    plans = []
    for member in campaign["members"]:
        guidance = engine.generate_guidance(member["finding_id"]).to_dict()
        guidance["source_revision"] = sources_before
        guidance["package"] = guidance.get("package_name", member["package"])
        guidance["ecosystem"] = ecosystem_for_package_manager(guidance.get("package_manager"))
        execution = execution_action(guidance)
        if execution:
            guidance["execution_action"] = execution
            guidance["execution_preview"] = shlex.join(execution["argv"])
        plans.append(guidance)
    _, _, after = read_snapshot(cfg)
    if before != after or source_revision(engine) != sources_before:
        raise OperationError("Snapshot mudou durante os planos; gere novamente.", 409)
    return plans, after


def execution_action(plan):
    package, fixed = plan.get("package", ""), plan.get("fixed_version", "")
    if (plan.get("confidence") != "high" or not plan.get("command") or not fixed or
            not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9+_.:-]{0,127}", package) or
            not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.+:~_-]{0,127}", fixed) or
            any("agrupad" in str(a).lower() or "relacionad" in str(a).lower() for a in plan.get("assumptions", []))):
        return None
    manager = plan.get("package_manager")
    if manager == "apt":
        argv = ["/usr/bin/apt-get", "-y", "--only-upgrade", "install", "--", package + "=" + fixed]
    elif manager in {"dnf", "yum"}:
        argv = ["/usr/bin/" + manager, "-y", "upgrade", "--", package + "-" + fixed]
    else:
        return None
    return {"package": package, "package_manager": manager, "fixed_version": fixed,
            "installed_version": plan.get("installed_version"), "argv": argv}


def correlate(incidents, asset_map, allowed_agents):
    output = []
    for incident in incidents:
        agents = sorted({str(asset_map[o]) for o in incident["observables"] if o in asset_map})
        agents = [a for a in agents if a in allowed_agents]
        if agents:
            output.append(dict(incident, agent_ids=agents, match_basis="explicit_asset_map", exploitation_confirmed=False))
    return output


def signed_argument(payload, key):
    if len(key) < 32:
        raise OperationError("Chave do agente deve ter pelo menos 32 caracteres.")
    raw = encode(payload).encode()
    packet = {"payload": payload, "signature": hmac.new(key.encode(), raw, hashlib.sha256).hexdigest()}
    return base64.urlsafe_b64encode(encode(packet).encode()).decode()


def execute_campaign(campaign, project, config, actor, pilot, secrets, receipt=None):
    if campaign.get("status") != "planned":
        raise OperationError("Execução exige campanha planejada.", 409)
    cfg = project_config(config, project)
    policy = cfg.get("execution", {})
    if not policy.get("enabled"):
        raise OperationError("Execução de correções desabilitada neste projeto.", 403)
    principal(config, actor).require("execute", project, pilot)
    window = campaign.get("maintenance_window") or {}
    current = dt.datetime.now(dt.timezone.utc)
    if not stamp(window.get("start")) <= current < stamp(window.get("end")):
        raise OperationError("Fora da janela de manutenção.", 409)
    metadata, _, revision = read_snapshot(cfg)
    if not quality(metadata, [], cfg)["fresh"] or not quality(metadata, [], cfg)["collection_complete"]:
        raise OperationError("Coleta recente e completa necessária para execução.", 409)
    approval = campaign.get("approval") or {}
    approver = principal(config, approval.get("approved_by", ""))
    approver.require("approve", project, pilot)
    if approval.get("revision") != revision or approval.get("plans_hash") != hashlib.sha256(json.dumps(campaign["plans"], sort_keys=True).encode()).hexdigest():
        raise OperationError("Aprovação não corresponde ao plano/revisão atual.", 409)
    sources = source_revision(engine_for(cfg))
    if any(p.get("source_revision") != sources for p in campaign["plans"]):
        raise OperationError("Fontes de remediação mudaram; gere e aprove novamente.", 409)
    if not set(pilot) <= set(policy.get("agent_ids", [])) or "000" in pilot:
        raise OperationError("Piloto fora da allowlist de execução.", 403)
    keys = json.loads(secrets.get("EYEMOLE_AGENT_KEYS", "{}"))
    results, seen, actions = [], {}, []
    for plan in campaign["plans"]:
        agent = plan.get("agent_id")
        if agent not in pilot:
            continue
        if plan.get("confidence") != "high" or not plan.get("fixed_version") or not plan.get("command"):
            raise OperationError("Execução exige comando aplicável e versão corrigida de alta confiança.", 409)
        manager = plan.get("package_manager")
        if manager not in {"apt", "dnf", "yum"}:
            raise OperationError("Executor disponível para apt/dnf/yum; demais plataformas usam procedimento manual.", 409)
        # Dependencies/grouped commands must be reviewed manually; never parse a shell command into execution.
        if plan.get("package_names") and plan["package_names"] != [plan["package"]]:
            raise OperationError("Atualização agrupada exige revisão manual; executor aceita um pacote por ação.")
        if plan.get("execution_action") != execution_action(plan) or not plan.get("execution_action"):
            raise OperationError("Plano não contém ação nativa revisada; gere e aprove novamente.", 409)
        key = (agent, plan["package"])
        if key in seen:
            if seen[key] != (plan["fixed_version"], plan["installed_version"]):
                raise OperationError("Pacote tem versões/ações conflitantes; separe a campanha.", 409)
            continue
        seen[key] = (plan["fixed_version"], plan["installed_version"])
        if len(seen) > min(int(policy.get("max_actions", 10)), 20):
            raise OperationError("Campanha excedeu limite de ações do piloto.")
        payload = {"id": uuid.uuid4().hex, "agent_id": agent, "package": plan["package"],
                   "package_manager": manager, "installed_version": plan["installed_version"],
                   "fixed_version": plan["fixed_version"], "issued_at": int(time.time()),
                   "expires_at": min(int(time.time()) + 300, int(stamp(window["end"]).timestamp()))}
        actions.append((agent, payload, signed_argument(payload, keys.get(agent, ""))))
    if not actions:
        raise OperationError("Nenhum plano executável no piloto.")
    # Validate the entire pilot before the first mutating API request.
    client = Wazuh(settings(cfg, "wazuh"), secrets)
    client.login()
    for agent, payload, argument in actions:
        record = {"action_id": payload["id"], "agent_ids": [agent], "package": payload["package"],
                  "state": "dispatch_pending", "correction_confirmed": False, "created_at": now()}
        if receipt:
            receipt(record)
        result = client.dispatch(agent, argument)
        affected = result.get("data", {}).get("affected_items", [])
        matches = [str(a.get("id")) if isinstance(a, dict) else str(a) for a in affected]
        if result.get("error", 0) != 0 or result.get("data", {}).get("failed_items") or agent not in matches:
            raise OperationError("Wazuh não confirmou o envio; verifique o agente antes de repetir.", 502)
        record["state"] = "dispatched"
        if receipt:
            receipt(record)
        results.append({"action_id": payload["id"], "agent_id": agent, "package": payload["package"], "state": "dispatched"})
    return {"actions": results, "state": "dispatched", "correction_confirmed": False}


def explain_campaign(store, service, project, cfg, c, secrets, actor):
    """Explain the campaign's current plans; reject if plans/evidence/sources change meanwhile."""
    if not c.get("plans"):
        raise OperationError("Gere os planos antes de solicitar a explicação por IA.", 409)
    identifier = c["id"]
    evidence = [e for e in store.list(project, "evidence") if e.get("campaign_id") == identifier]
    plans_hash, evidence_hash = ai.digest(c["plans"]), service.evidence_hash(project, identifier)
    sources_before = source_revision(engine_for(cfg))
    kind, provider_settings = ai.selection(cfg)
    if kind == "kiro":
        result = explain(c, evidence, provider_settings, secrets)
        result.update(provider="kiro", provider_label="Kiro (legado)", model="kiro-cli", served_model="kiro-cli")
    else:
        result = ai.explain_plans(c["plans"], cfg, secrets, extra_evidence=evidence)
    # Revalidate after the (slow) provider call: never store an outdated explanation.
    current = store.get(project, "campaign", identifier)
    if (current["version"] != c["version"] or ai.digest(current.get("plans", [])) != plans_hash
            or service.evidence_hash(project, identifier) != evidence_hash
            or source_revision(engine_for(cfg)) != sources_before):
        raise OperationError("Planos, evidências ou fontes mudaram durante a geração; solicite novamente.", 409)
    current["ai_explanation"] = dict(result, generated_at=now(), plan_revision=c.get("plan_revision"),
                                     plans_hash=plans_hash, evidence_hash=evidence_hash, source_revision=sources_before)
    # Optimistic version check: a concurrent change aborts instead of overwriting.
    store.put(project, "campaign", identifier, current, actor, "ai.explained", current["version"])
    return {"provider": result["provider"], "model": result["model"], "recommendations": len(result["recommendations"])}


def explain_finding(store, service, project, cfg, job, payload, secrets):
    """Explain one installation's deterministic guidance ("Ver correção")."""
    finding_id, agent = payload["finding_id"], payload["agent_id"]
    service.user.require("write", project, [agent])
    if ai.provider_key(cfg) != payload.get("provider_key"):
        raise OperationError("Provedor ou modelo de IA mudou após o pedido; solicite novamente.", 409)

    def snapshot_state():
        _, rows, revision = read_snapshot(cfg)
        row = rows.get(finding_id)
        if row is None or str(row.get("agent_id")) != agent:
            raise OperationError("Instância não está mais no snapshot atual.", 409)
        guidance = engine_for(cfg).generate_guidance(finding_id).to_dict()
        return revision, guidance

    revision, guidance = snapshot_state()
    if revision != payload["snapshot_revision"] or guidance.get("snapshot_revision") != payload["guidance_revision"]:
        raise OperationError("Dados mudaram desde o pedido; solicite a explicação novamente.", 409)
    guidance["package"] = guidance.get("package_name")
    kind, provider_settings = ai.selection(cfg)
    if kind == "kiro":
        result = explain({"plans": [guidance]}, [], provider_settings, secrets)
        result.update(provider="kiro", provider_label="Kiro (legado)", model="kiro-cli", served_model="kiro-cli")
    else:
        result = ai.explain_plans([guidance], cfg, secrets)
    after_revision, after = snapshot_state()
    if after_revision != revision or after.get("snapshot_revision") != guidance.get("snapshot_revision"):
        raise OperationError("Dados mudaram durante a geração; explicação descartada.", 409)
    object_id = job["object_id"]
    data = {"finding_id": finding_id, "agent_ids": [agent], "cve": guidance.get("cve"),
            "package": guidance.get("package_name"), "installed_version": guidance.get("installed_version"),
            "snapshot_revision": revision, "guidance_revision": guidance.get("snapshot_revision"),
            "provider": result["provider"], "provider_label": result["provider_label"], "model": result["model"],
            "served_model": result.get("served_model"), "summary": result["summary"],
            "recommendations": result["recommendations"],
            "evidence": [{"id": e["id"], "label": e.get("label") or e.get("description"), "url": e.get("url")}
                         for e in ai.plan_evidence(guidance)],
            "generated_at": now()}
    key = hashlib.sha256(object_id.encode()).hexdigest()
    store.put(project, "ai_finding", key, data, job["actor"], "ai.finding_explained")
    return {"provider": result["provider"], "model": result["model"], "recommendations": len(result["recommendations"])}


def process(store, config, job, secrets):
    payload = json.loads(job["payload"])
    actor = principal(config, job["actor"])
    service = Operations(store, config, actor)
    project = job["project"]
    cfg = project_config(config, project)
    secrets = ai.scoped_secrets(cfg, secrets)
    if job["kind"] == "ai_finding":
        return explain_finding(store, service, project, cfg, job, payload, secrets)
    identifier = payload["campaign_id"]
    permission = "execute" if job["kind"] == "execute" else "integrate" if job["kind"] in {"ticket", "sync", "evidence"} else "write"
    c = service.get_campaign(project, identifier, permission)
    if c["version"] != payload["campaign_version"]:
        raise OperationError("Campanha mudou enquanto o trabalho aguardava; solicite novamente.", 409)
    if job["kind"] == "plans":
        plans, revision = generate_plans(c, cfg)
        service.save_plans(project, identifier, plans, revision, job["actor"])
        return {"plans": len(plans), "revision": revision}
    if job["kind"] in {"ai", "kiro"}:
        return explain_campaign(store, service, project, cfg, c, secrets, job["actor"])
    if job["kind"] == "ticket":
        ticket = GLPI(settings(cfg, "glpi"), secrets).create(c)
        c["ticket"] = ticket
        store.put(project, "campaign", identifier, c, job["actor"], "ticket.created", c["version"])
        return ticket
    if job["kind"] == "evidence":
        evidence = []
        pairs = {(m["cve"], m.get("operating_system", "")) for m in c["members"]}
        if len(pairs) > 30:
            raise OperationError("Provider limitado a 30 pares CVE/produto; divida a campanha.")
        for cve, product in sorted(pairs):
            item = vendor_evidence(cve, product, cfg.get("evidence_month"))
            item.update(campaign_id=identifier, agent_ids=c["agent_ids"])
            key = hashlib.sha256((identifier + cve + product + item["content_sha256"]).encode()).hexdigest()
            evidence.append(store.put(project, "evidence", key, item, job["actor"], "evidence.collected"))
        return {"count": len(evidence), "applicability": "needs_review"}
    if job["kind"] == "sync":
        output = {"providers": {}}
        for name, provider in (("qradar", QRadar), ("vision_one", VisionOne)):
            if cfg.get("integrations", {}).get(name, {}).get("enabled"):
                incidents, complete = provider(settings(cfg, name), secrets).incidents()
                matches = correlate(incidents, cfg.get("asset_map", {}), set(c["agent_ids"]))
                for incident in matches:
                    incident["campaign_id"] = identifier
                    key = hashlib.sha256((identifier + name + incident["external_id"]).encode()).hexdigest()
                    store.put(project, "incident", key, incident, job["actor"], "incident.correlated")
                output["providers"][name] = {"count": len(matches), "complete": complete, "checked_at": now()}
        if cfg.get("integrations", {}).get("wazuh", {}).get("enabled"):
            client = Wazuh(settings(cfg, "wazuh"), secrets)
            client.login()
            for agent in c["agent_ids"]:
                inv = client.inventory(agent)
                store.put(project, "inventory", agent, inv, job["actor"], "inventory.collected")
            output["providers"]["wazuh"] = {"count": len(c["agent_ids"])}
        if c.get("ticket") and cfg.get("integrations", {}).get("glpi", {}).get("enabled"):
            ticket = GLPI(settings(cfg, "glpi"), secrets).read(c["ticket"]["ticket_id"])
            c["ticket"]["remote_status"] = ticket.get("status")
            c["ticket"]["checked_at"] = now()
            store.put(project, "campaign", identifier, c, job["actor"], "ticket.synced", c["version"])
        if not output["providers"] and not c.get("ticket"):
            raise OperationError("Nenhum conector habilitado para sincronizar.")
        return output
    if job["kind"] == "execute":
        def record_receipt(data):
            data.update(campaign_id=identifier, job_id=job["id"])
            store.put(project, "execution", data["action_id"], data, job["actor"], "execution." + data["state"])
        result = execute_campaign(c, project, config, job["actor"], payload["pilot_agents"], secrets, record_receipt)
        c["execution"] = dict(result, dispatched_at=now(), job_id=job["id"])
        store.put(project, "campaign", identifier, c, job["actor"], "campaign.dispatched", c["version"])
        return result
    raise OperationError("Tipo de trabalho inválido.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    import fcntl  # Linux-only; imported here so the module stays importable for tests
    store = Store()
    lock_path = store.path.parent / "worker.lock"
    with lock_path.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 1
        store.recover_interrupted()
        while True:
            if Path("/run/eyemole-maintenance").exists():
                if args.once:
                    return 0
                time.sleep(2)
                continue
            job = store.claim()
            if job:
                def timeout(signum, frame):
                    raise OperationError("Trabalho excedeu prazo global; confira o destino antes de repetir.", 504)
                signal.signal(signal.SIGALRM, timeout)
                signal.alarm(600)
                try:
                    result = process(store, load_config(), job, dict(os.environ))
                    store.finish(job["id"], result=result)
                except OperationError as exc:
                    store.finish(job["id"], error=str(exc))
                    logger.warning("Job %s falhou: %s", job["id"], type(exc).__name__)
                except Exception as exc:
                    # Secrets, remote bodies and raw exceptions never reach API or logs.
                    store.finish(job["id"], error="Integração falhou; verifique configuração e disponibilidade.")
                    logger.warning("Job %s falhou: %s", job["id"], type(exc).__name__)
                finally:
                    signal.alarm(0)
            if args.once:
                return 0
            if not job:
                time.sleep(2)


if __name__ == "__main__":
    raise SystemExit(main())
