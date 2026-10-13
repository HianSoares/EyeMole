"""Campaigns and evidence-based verification over project-specific snapshots."""
import datetime as dt
import hashlib
import json
import re
import uuid
from pathlib import Path
from zoneinfo import ZoneInfo

from remediation.models import finding_id_for_snapshot_record
from remediation.versioning import compare_versions
from .security import OperationError, project_config, PERMISSIONS
from .store import now
from .planning import engine_for, source_revision
from . import ai as ai_support, ai_facts, diagnostics, research as research_support, research_sources

INVALIDATED_AI = ("Explicação gerada antes da verificação de consistência com o motor; invalidada e não exibida "
                  "(registro e auditoria preservados). Solicite novamente.")

FINDING_ID = re.compile(r"[a-f0-9]{64}")


def research_settings(cfg):
    """integrations.research block when enabled (administrative configuration only)."""
    block = (cfg.get("integrations") or {}).get("research") if isinstance(cfg, dict) else None
    return block if isinstance(block, dict) and block.get("enabled") else None

TRANSITIONS = {
    "identified": {"analyzing"}, "analyzing": {"planned"},
    "planned": {"analyzing", "applied"}, "applied": {"awaiting_validation"},
    "awaiting_validation": {"analyzing"}, "confirmed": {"analyzing"},
}
SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def stamp(value, timezone="UTC"):
    try:
        result = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result.replace(tzinfo=ZoneInfo(timezone)) if result.tzinfo is None else result
    except (ValueError, TypeError):
        raise OperationError("Data inválida.")


def text(value, maximum=1000):
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise OperationError("Texto inválido ou acima do limite.")
    return value.strip()


def exposure(row):
    return (str(row.get("agent_id", "")), str(row.get("cve", "")), str(row.get("package", "")))


def read_snapshot(config):
    path = Path(config.get("snapshot_path", "/var/www/wazuh-soar/data/latest.json"))
    try:
        with path.open("rb") as stream:
            raw = stream.read(128 * 1024 * 1024 + 1)
        if len(raw) > 128 * 1024 * 1024:
            raise ValueError()
        data = json.loads(raw)
        rows = data["vulnerabilities"]
        if not isinstance(rows, list) or len(rows) > 500000 or not isinstance(data.get("metadata"), dict):
            raise ValueError()
        # Reject malformed coverage rather than silently removing bad records.
        if any(not isinstance(r, dict) or not all(r.get(k) for k in ("agent_id", "cve", "package")) for r in rows):
            raise ValueError()
    except (OSError, ValueError, KeyError, TypeError):
        raise OperationError("Snapshot ausente ou inválido; coleta necessária.", 503)
    revision = hashlib.sha256(raw).hexdigest()
    instances = {finding_id_for_snapshot_record(r): dict(r) for r in rows}
    return data["metadata"], instances, revision


def quality(metadata, rows, config):
    try:
        generated = stamp(metadata.get("generated_at"), config.get("timezone", "UTC"))
        age = (dt.datetime.now(dt.timezone.utc) - generated).total_seconds()
    except OperationError:
        age = None
    sources = metadata.get("source_status", {})
    return {"generated_at": metadata.get("generated_at"), "age_seconds": age,
            "fresh": age is not None and 0 <= age <= config.get("snapshot_max_age_seconds", 86400),
            "collection_complete": metadata.get("collection", {}).get("complete") is True,
            "missing_epss": sum(r.get("epss", r.get("epss_score")) is None for r in rows),
            "missing_fixed_version": sum(not r.get("fixed_version") or r.get("fixed_version") == "N/D" for r in rows),
            "missing_architecture": sum(not r.get("package_architecture", r.get("architecture")) for r in rows),
            "sources": sources}


class Operations:
    def __init__(self, store, config, principal):
        self.store, self.config, self.user = store, config, principal

    def context(self, project, permission="read"):
        self.user.require(permission, project)
        return project_config(self.config, project)

    def visible(self, obj):
        if not self.user.agents:
            return True
        return all(a in self.user.agents for a in obj.get("agent_ids", []))

    def get_campaign(self, project, identifier, permission="read"):
        self.context(project, permission)
        campaign = self.store.get(project, "campaign", identifier)
        self.user.require(permission, project, campaign["agent_ids"])
        return campaign

    def overview(self, project):
        cfg = self.context(project)
        metadata, rows, revision = read_snapshot(cfg)
        rows = {i: r for i, r in rows.items() if not self.user.agents or str(r["agent_id"]) in self.user.agents}
        exposures = {exposure(r) for r in rows.values()}
        campaigns = [self.present_campaign(project, c) for c in self.store.list(project, "campaign") if self.visible(c)]
        return {"project": project, "revision": revision, "instances": len(rows), "exposures": len(exposures),
                "quality": quality(metadata, rows.values(), cfg), "campaigns": campaigns,
                "permissions": sorted(PERMISSIONS[self.user.role])}

    def proposals(self, project):
        cfg = self.context(project)
        _, rows, revision = read_snapshot(cfg)
        groups = {}
        for identifier, r in rows.items():
            agent = str(r["agent_id"])
            if self.user.agents and agent not in self.user.agents:
                continue
            key = (str(r.get("operating_system", "unknown")), r["package"], str(r.get("fixed_version") or "unknown"),
                   str(r.get("package_type", "unknown")), str(r.get("package_architecture", "unknown")))
            g = groups.setdefault(key, {"package": key[1], "operating_system": key[0], "target_version": key[2],
                                        "architecture": key[4], "finding_ids": [], "agent_ids": set(), "cves": set(), "exposures": set(), "priority": 0})
            g["finding_ids"].append(identifier)
            g["agent_ids"].add(agent)
            g["cves"].add(r["cve"])
            g["exposures"].add(exposure(r))
            g["priority"] = max(g["priority"], SEVERITY.get(str(r.get("severity", "")).lower(), 0) + (5 if r.get("is_kev") else 0))
        output = []
        for g in groups.values():
            g["agent_ids"], g["cves"] = sorted(g["agent_ids"]), sorted(g["cves"])
            g["exposure_count"] = len(g.pop("exposures"))
            g["status"] = "needs_applicability_review"
            output.append(g)
        return {"revision": revision, "items": sorted(output, key=lambda g: (g["priority"], g["exposure_count"]), reverse=True)[:500],
                "total_groups": len(groups)}

    def create_campaign(self, project, body):
        cfg = self.context(project, "write")
        _, rows, revision = read_snapshot(cfg)
        ids = body.get("finding_ids")
        if not isinstance(ids, list) or not 1 <= len(ids) <= 500 or any(not isinstance(i, str) for i in ids):
            raise OperationError("Selecione de 1 a 500 instâncias.")
        if body.get("revision") != revision:
            raise OperationError("Snapshot alterado; atualize as propostas.", 409)
        if any(i not in rows for i in ids):
            raise OperationError("Instância ausente no snapshot.", 409)
        members = [dict(rows[i], finding_id=i) for i in dict.fromkeys(ids)]
        agents = sorted({str(r["agent_id"]) for r in members})
        self.user.require("write", project, agents)
        data = {"name": text(body.get("name", ""), 160), "owner": text(body.get("owner", ""), 160),
                "status": "identified", "agent_ids": agents, "members": members,
                "exposure_count": len({exposure(r) for r in members}), "baseline_revision": revision,
                "created_at": now(), "plans": [], "approval": None, "acceptance": None,
                "maintenance_window": None, "due_at": None}
        if not data["name"]:
            raise OperationError("Informe o nome da campanha.")
        return self.store.put(project, "campaign", uuid.uuid4().hex, data, self.user.name, "campaign.created", expected=0)

    def transition(self, project, identifier, body):
        c = self.get_campaign(project, identifier, "write")
        target = body.get("status")
        if target not in TRANSITIONS.get(c["status"], set()):
            raise OperationError("Transição inválida. Confirmação exige validação automática.", 409)
        reason = text(body.get("reason", ""))
        if not reason:
            raise OperationError("Registre a justificativa/evidência da alteração.")
        if target == "planned":
            window = body.get("maintenance_window", {})
            start, end = stamp(window.get("start")), stamp(window.get("end"))
            if end <= start or (end - start).total_seconds() > 86400:
                raise OperationError("Janela de manutenção inválida; máximo 24 horas.")
            c["maintenance_window"] = {"start": start.isoformat(), "end": end.isoformat()}
            c["owner"] = text(body.get("owner", c["owner"]), 160)
            if not c["owner"]:
                raise OperationError("Planejamento exige responsável.")
            if body.get("due_at"):
                c["due_at"] = stamp(body["due_at"]).isoformat()
        if target == "applied":
            c["applied_at"], c["application_evidence"] = now(), reason
        if target == "analyzing":
            c["approval"] = None
        c["status"], c["last_reason"] = target, reason
        return self.store.put(project, "campaign", identifier, c, self.user.name, "campaign.transition", body.get("version", -1))

    def accept(self, project, identifier, body):
        c = self.get_campaign(project, identifier, "accept")
        expires = stamp(body.get("expires_at"))
        if expires <= dt.datetime.now(dt.timezone.utc):
            raise OperationError("Aceitação precisa ter vencimento futuro.")
        reason = text(body.get("reason", ""))
        if not reason:
            raise OperationError("Aceitação exige justificativa.")
        c["acceptance"] = {"reason": reason, "expires_at": expires.isoformat(), "approved_by": self.user.name, "approved_at": now()}
        return self.store.put(project, "campaign", identifier, c, self.user.name, "risk.accepted", body.get("version", -1))

    def inventory(self, project, agent, body):
        self.context(project, "write")
        self.user.require("write", project, [agent])
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", agent):
            raise OperationError("ID de ativo inválido.")
        permitted = {"os", "architecture", "ubr", "roles", "roles_collection_state", "reboot_pending", "update_channel", "packages", "hotfixes", "agent_status", "observed_at", "source"}
        if set(body) - permitted or len(json.dumps(body)) > 65536:
            raise OperationError("Inventário inválido ou acima do limite.")
        observed = stamp(body.get("observed_at"))
        if observed > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
            raise OperationError("Inventário com data futura.")
        if body.get("agent_status") not in {"active", "disconnected", "unknown"}:
            raise OperationError("Estado do agente inválido.")
        if not isinstance(body.get("packages", {}), dict):
            raise OperationError("packages deve relacionar pacote e versão instalada.")
        if any(not isinstance(k, str) or not isinstance(v, str) or not k or len(k) > 256 or len(v) > 256 for k, v in body.get("packages", {}).items()):
            raise OperationError("Pacotes e versões devem ser textos curtos.")
        body["agent_ids"] = [agent]
        body["source"] = "manual:" + self.user.name
        return self.store.put(project, "inventory", agent, body, self.user.name, "inventory.recorded")

    def verify(self, project, identifier, body):
        c = self.get_campaign(project, identifier, "write")
        if c["status"] not in {"applied", "awaiting_validation"}:
            raise OperationError("Aplique e registre a correção antes da validação.", 409)
        cfg = self.context(project)
        metadata, rows, revision = read_snapshot(cfg)
        q = quality(metadata, rows.values(), cfg)
        collected = {str(a) for a in metadata.get("agents_analyzed", [])}
        applied = stamp(c["applied_at"])
        generated = stamp(metadata.get("generated_at"), cfg.get("timezone", "UTC"))
        blocked = []
        if not q["fresh"] or not q["collection_complete"] or generated <= applied or revision == c["baseline_revision"]:
            blocked.append("Coleta completa, recente e posterior à aplicação é necessária.")
        current = {exposure(r) for r in rows.values()}
        residual = [r["finding_id"] for r in c["members"] if exposure(r) in current]
        for agent in c["agent_ids"]:
            if agent not in collected:
                blocked.append("Ativo não incluído na coleta: " + agent)
            try:
                inv = self.store.get(project, "inventory", agent)
                if inv.get("agent_status") != "active" or stamp(inv.get("observed_at")) <= applied:
                    blocked.append("Inventário/estado do agente precisa ser atualizado: " + agent)
            except OperationError:
                blocked.append("Inventário posterior ausente: " + agent)
        # Every applicable plan must have a verified installed version, independently of CVE absence.
        for plan in c.get("plans", []):
            try:
                inv = self.store.get(project, "inventory", plan["agent_id"])
                installed = inv.get("packages", {}).get(plan["package"])
                comparison = compare_versions(plan.get("ecosystem"), str(installed or ""), plan.get("fixed_version", ""))
                if comparison is None or comparison < 0:
                    blocked.append("Versão corrigida não confirmada: " + plan["package"])
            except OperationError:
                blocked.append("Inventário ausente para verificar versão.")
        if not c.get("plans") or len(c["plans"]) != len(c["members"]):
            blocked.append("Plano aplicável e versionado necessário para todas as instâncias.")
        c["validation"] = {"revision": revision, "checked_at": now(), "remaining_findings": residual, "blocked_reasons": blocked}
        c["status"] = "confirmed" if not residual and not blocked else "awaiting_validation"
        return self.store.put(project, "campaign", identifier, c, self.user.name, "campaign.verified", body.get("version", -1))

    def save_plans(self, project, identifier, plans, revision, actor):
        c = self.store.get(project, "campaign", identifier)
        c["plans"], c["plan_revision"], c["approval"] = plans, revision, None
        # An explanation belongs to the plans it explained; new plans invalidate it.
        c.pop("ai_explanation", None)
        return self.store.put(project, "campaign", identifier, c, actor, "campaign.plans_generated", c["version"])

    def approve(self, project, identifier, body):
        c = self.get_campaign(project, identifier, "approve")
        _, _, revision = read_snapshot(self.context(project))
        if c["status"] != "planned" or not c.get("plans") or c.get("plan_revision") != revision:
            raise OperationError("Planeje a campanha e gere planos sobre o snapshot atual.", 409)
        if len(c["plans"]) != len(c["members"]) or any(not p.get("command") for p in c["plans"]):
            raise OperationError("Todas as instâncias precisam de correção aplicável.", 409)
        sources = source_revision(engine_for(self.context(project)))
        if any(p.get("source_revision") != sources for p in c["plans"]):
            raise OperationError("Fontes mudaram; gere planos novamente antes de aprovar.", 409)
        digest = hashlib.sha256(json.dumps(c["plans"], sort_keys=True).encode()).hexdigest()
        c["approval"] = {"approved_by": self.user.name, "approved_at": now(), "plans_hash": digest, "revision": revision}
        return self.store.put(project, "campaign", identifier, c, self.user.name, "campaign.approved", body.get("version", -1))

    def queue(self, project, identifier, kind, body):
        kind = "ai" if kind == "kiro" else kind  # rota antiga preservada
        permission = "execute" if kind == "execute" else "integrate" if kind in {"ticket", "sync", "evidence"} else "write"
        c = self.get_campaign(project, identifier, permission)
        if kind not in {"plans", "ai", "ticket", "sync", "execute", "evidence"}:
            raise OperationError("Trabalho desconhecido.")
        if kind == "ai":
            if not ai_support.public_status(self.context(project)).get("enabled"):
                raise OperationError("Explicação por IA desabilitada pelo administrador.", 503)
            if not c.get("plans"):
                raise OperationError("Gere os planos antes de solicitar a explicação por IA.", 409)
        # The exact campaign version forms the idempotency key for revisable read jobs.
        key = identifier if kind == "ticket" else f"{identifier}:{c['version']}"
        payload = {"campaign_id": identifier, "campaign_version": c["version"]}
        if kind == "execute":
            pilot = body.get("pilot_agents", [])
            if not isinstance(pilot, list) or not pilot or len(pilot) > 5 or not set(pilot) <= set(c["agent_ids"]):
                raise OperationError("Selecione de 1 a 5 ativos da campanha para o piloto.")
            self.user.require("execute", project, pilot)
            payload["pilot_agents"] = pilot
            if not c.get("approval"):
                raise OperationError("Execução exige aprovação explícita do plano.", 409)
        return self.store.queue(project, kind, key, self.user.name, payload)

    # ------------------------------------------------------------------
    # Explicação por IA
    # ------------------------------------------------------------------

    def evidence_hash(self, project, campaign_id):
        items = [e for e in self.store.list(project, "evidence") if e.get("campaign_id") == campaign_id]
        return ai_support.digest(sorted((e["id"], e.get("content_sha256")) for e in items))

    def ai_status(self, project):
        return ai_support.public_status(self.context(project))

    def _installation(self, project, finding_id, permission):
        cfg = self.context(project, permission)
        if not isinstance(finding_id, str) or not FINDING_ID.fullmatch(finding_id):
            raise OperationError("finding_id inválido.")
        _, rows, revision = read_snapshot(cfg)
        row = rows.get(finding_id)
        if row is None:
            raise OperationError("Instância não encontrada no snapshot atual; atualize o painel.", 404)
        agent = str(row["agent_id"])
        self.user.require(permission, project, [agent])
        return cfg, row, agent, revision

    def _object(self, project, kind, key):
        try:
            return self.store.get(project, kind, key)
        except OperationError:
            return None

    @staticmethod
    def installation_key(prefix, agent, finding_id):
        """Records bound to exactly one installation (agent + instance identity)."""
        return hashlib.sha256(f"{prefix}:{agent}:{finding_id}".encode()).hexdigest()

    def _finding(self, project, finding_id, permission):
        cfg, row, agent, revision = self._installation(project, finding_id, permission)
        guidance = engine_for(cfg).generate_guidance(finding_id)
        if guidance.status in {"not_found", "provider_unavailable", "ambiguous_finding", "validation_error", "internal_error"}:
            raise OperationError("Orientação determinística indisponível para esta instância.", 409)
        status = ai_support.public_status(cfg)
        research_facts = self.research_facts(project, cfg, row, agent, finding_id, guidance.to_dict())
        # Instance, plan revision, provider/model, the facts contract and the
        # current research form the identity: an explanation is never reused for
        # another installation of the same CVE, nor across contracts or research.
        legacy_id = f"finding:{agent}:{finding_id}:{guidance.snapshot_revision}:{ai_support.provider_key(cfg)}"
        object_id = (f"{legacy_id}:facts{ai_facts.FACTS_VERSION}:"
                     f"{research_facts['revision'] if research_facts else 'none'}")
        previous = [legacy_id] + [f"{legacy_id}:facts{v}" for v in range(2, ai_facts.FACTS_VERSION)]
        # Facts v3 identities carried the research revision (or "none"); the stored research, even
        # if no longer current, tells which v3 identity may exist.
        stored_research = self._object(project, "ai_research", self.installation_key("research", agent, finding_id))
        previous += [f"{legacy_id}:facts3:none"] + (
            [f"{legacy_id}:facts3:{research_support.facts_summary(stored_research)['revision']}"] if stored_research else [])
        return cfg, row, agent, revision, guidance, status, object_id, previous, research_facts

    def _stored_ai(self, project, object_id):
        return self._object(project, "ai_finding", hashlib.sha256(object_id.encode()).hexdigest())

    # ------------------------------------------------------------------
    # Remediation research ("Pesquisar correção") and imported diagnostics
    # ------------------------------------------------------------------

    def research_inputs(self, project, row, agent, finding_id, plan, cfg=None):
        inventory = self._object(project, "inventory", agent)
        diagnostic = self._object(project, "diagnostic_import", self.installation_key("diag", agent, finding_id))
        if diagnostic and diagnostic.get("installed_version") != row["version"]:
            diagnostic = None  # imported for another installed version
        settings = research_settings(cfg if cfg is not None else self.context(project)) or {}
        # Time-dependent validity (diagnostic expiry) is evaluated here, without network access.
        context = research_support.resolve_context(dict(row, finding_id=finding_id), plan, inventory, diagnostic,
                                                   settings, research_support._now())
        return inventory, diagnostic, context

    def research_provider(self, cfg):
        status = ai_support.public_status(cfg)
        return ai_support.provider_key(cfg) if status.get("enabled") and status.get("provider") != "kiro" else "none"

    def current_research(self, project, cfg, row, agent, finding_id, plan, context=None):
        """(stored result, reasons it is no longer current). No reasons = current."""
        stored = self._object(project, "ai_research", self.installation_key("research", agent, finding_id))
        if not stored:
            return None, []
        if context is None:
            _, _, context = self.research_inputs(project, row, agent, finding_id, plan, cfg)
        reasons = []
        valid_until = stored.get("valid_until")
        if not valid_until or research_support._now() >= dt.datetime.fromisoformat(valid_until):
            # Time alone retires the classification and the validation seal (evidence/diagnostic expired);
            # detected without network, the refresh happens in the worker.
            reasons.append("A validade das evidências ou do diagnóstico expirou; pesquise novamente.")
        if stored.get("research_version") != research_support.RESEARCH_VERSION:
            reasons.append("O contrato da pesquisa mudou.")
        if stored.get("context_revision") != context["revision"]:
            reasons.append("O contexto da instalação mudou (orientação, inventário ou diagnóstico importado).")
        if stored.get("provider_key") != self.research_provider(cfg):
            reasons.append("O provedor ou modelo de IA mudou.")
        settings = research_settings(cfg) or {}
        for url, sha in stored.get("evidence_index", []):
            entry = research_sources.cached_entry(url, settings)
            if entry and entry.get("content") is not None and entry.get("content_sha256") != sha:
                reasons.append("As evidências das fontes mudaram desde a pesquisa.")
                break
        return stored, reasons

    def research_facts(self, project, cfg, row, agent, finding_id, plan):
        stored, reasons = self.current_research(project, cfg, row, agent, finding_id, plan)
        return research_support.facts_summary(stored) if stored and not reasons else None

    def research_state(self, project, finding_id):
        cfg, row, agent, revision = self._installation(project, finding_id, "read")
        plan = engine_for(cfg).generate_guidance(finding_id).to_dict()
        inventory, diagnostic, context = self.research_inputs(project, row, agent, finding_id, plan, cfg)
        settings = research_settings(cfg)
        out = {"finding_id": finding_id, "enabled": bool(settings), "state": "none",
               "context": {k: context.get(k) for k in ("distribution", "release", "binary_package", "source_package",
                                                       "installed_version", "architecture", "package_origin",
                                                       "repository", "origins", "missing")},
               "diagnostic": diagnostics.public(diagnostic, settings, research_support._now()),
               # Read-only diagnostics the analyst may run; never shown as collected results.
               "available_diagnostics": [{"label": d.get("label"), "script": d.get("script"), "executed": False}
                                         for d in plan.get("diagnostics", [])],
               "ai": ai_support.public_status(cfg)}
        if not settings:
            out["reason"] = "Pesquisa de correção desabilitada pelo administrador."
            return out
        stored, reasons = self.current_research(project, cfg, row, agent, finding_id, plan, context)
        job = self.store.job_for(project, "research", self.research_object(cfg, agent, finding_id, context))
        if job and job["state"] in {"queued", "running"}:
            out["state"] = job["state"]
        elif stored and not reasons:
            out.update(state="succeeded", result=stored)
        elif job and job["state"] in {"failed", "interrupted"}:
            out.update(state="failed", error=job.get("error") or "Pesquisa não concluída.")
        elif stored:
            # Outdated: reasons and provenance only; no proposal or command is shown as current.
            out.update(state="stale", stale_reasons=reasons, result={k: stored.get(k) for k in (
                "generated_at", "classification", "classification_label", "sources")})
        return out

    def research_object(self, cfg, agent, finding_id, context):
        return f"research:{agent}:{finding_id}:{context['revision'][:16]}:{self.research_provider(cfg)}"

    def queue_research(self, project, finding_id):
        cfg, row, agent, revision = self._installation(project, finding_id, "write")
        if not research_settings(cfg):
            raise OperationError("Pesquisa de correção desabilitada pelo administrador.", 503)
        plan = engine_for(cfg).generate_guidance(finding_id).to_dict()
        _, _, context = self.research_inputs(project, row, agent, finding_id, plan, cfg)
        payload = {"finding_id": finding_id, "agent_id": agent, "snapshot_revision": revision,
                   "context_revision": context["revision"]}
        return self.store.queue(project, "research", self.research_object(cfg, agent, finding_id, context),
                                self.user.name, payload)

    def import_diagnostics(self, project, finding_id, body):
        cfg, row, agent, revision = self._installation(project, finding_id, "write")
        plan = engine_for(cfg).generate_guidance(finding_id).to_dict()
        # The import is checked against the asset context known without diagnostics.
        asset = research_support.asset_context(row, plan, self._object(project, "inventory", agent))
        installation = {"finding_id": finding_id, "agent_id": agent, "package": row["package"], "version": row["version"],
                        "architecture": row.get("package_architecture") or row.get("architecture"), **asset}
        record = diagnostics.build_import(body, installation, self.user.name, research_support._now())
        # Latest import drives the research; every import is kept as history (and audited).
        self.store.put(project, "diagnostic_import", self.installation_key("diag", agent, finding_id), record,
                       self.user.name, "diagnostic.imported")
        self.store.put(project, "diagnostic_history",
                       self.installation_key(f"diag:{record['revision']}:{record['imported_at']}", agent, finding_id),
                       record, self.user.name, "diagnostic.archived")
        return diagnostics.public(record, research_settings(cfg) or {}, research_support._now())

    def finding_ai(self, project, finding_id):
        cfg, row, agent, revision, guidance, status, object_id, previous, research_facts = \
            self._finding(project, finding_id, "read")
        plan = guidance.to_dict()
        # Critical facts always come from the engine (and current research), whatever the AI state.
        result = {"finding_id": finding_id, "provider": status.get("provider"), "provider_label": status.get("provider_label"),
                  "model": status.get("model"), "enabled": bool(status.get("enabled")), "state": "none",
                  "engine_facts": ai_facts.engine_facts(plan, research_facts)}
        if not status.get("enabled"):
            result["reason"] = status.get("reason")
            return result
        stored = self._stored_ai(project, object_id)
        if stored and stored.get("snapshot_revision") == revision:
            result.update(state="succeeded", summary=stored["summary"], recommendations=stored["recommendations"],
                          evidence=stored.get("evidence", []), generated_at=stored.get("generated_at"),
                          served_model=stored.get("served_model"))
            return result
        job = self.store.job_for(project, "ai_finding", object_id)
        if job:
            result["state"] = {"queued": "queued", "running": "running"}.get(job["state"], "failed")
            if result["state"] == "failed":
                result["error"] = job.get("error") or "Geração não concluída."
            if job["state"] == "succeeded":
                # Job finished but its result no longer matches the current data.
                result.update(state="stale", error="Os dados mudaram depois da geração; solicite novamente.")
        elif any(self._stored_ai(project, old) is not None for old in previous):
            # Generated before the engine-consistency contract: kept for audit, never shown as valid.
            result.update(state="stale", invalidated=True, error=INVALIDATED_AI)
        return result

    def present_campaign(self, project, c):
        """Campaign as shown to users: AI explanation annotated, outdated contracts without text."""
        explanation = c.get("ai_explanation")
        if not explanation:
            return c
        c = dict(c)
        if explanation.get("facts_version") != ai_facts.FACTS_VERSION:
            c["ai_explanation"] = {key: explanation.get(key) for key in ("provider", "provider_label", "model", "generated_at")}
            c["ai_explanation"].update(current=False, invalidated=True, reason=INVALIDATED_AI)
            return c
        # Stale when plans or campaign evidence changed after the generation.
        c["ai_explanation"] = dict(explanation, current=(
            explanation.get("plans_hash") == ai_support.digest(c.get("plans", []))
            and explanation.get("evidence_hash") == self.evidence_hash(project, c["id"])))
        return c

    def queue_finding_ai(self, project, finding_id):
        cfg, row, agent, revision, guidance, status, object_id, _, research_facts = \
            self._finding(project, finding_id, "write")
        if not status.get("enabled"):
            raise OperationError(status.get("reason") or "Explicação por IA desabilitada.", 503)
        payload = {"finding_id": finding_id, "agent_id": agent, "snapshot_revision": revision,
                   "guidance_revision": guidance.snapshot_revision, "provider_key": ai_support.provider_key(cfg),
                   "research_revision": research_facts["revision"] if research_facts else None}
        return self.store.queue(project, "ai_finding", object_id, self.user.name, payload)
