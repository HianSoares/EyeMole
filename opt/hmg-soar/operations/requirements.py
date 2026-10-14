"""Exploitation requirements (affected component enabled, feature compiled, role installed...).

Requirements come from:
- the curated official-evidence catalog (remediation/data/vendor_evidence.json),
  with a fixed read-only check when one is supported (e.g. Windows feature
  state collected by the agent);
- the AI proposal, only when it cites evidence (always "not verified").

A requirement that is absent reduces exposure according to the source, but it
never means the package is updated and never closes the finding: the fix keeps
being recommended. Unknown requirements stay pending (and may trigger a
read-only collection).
"""
import re

from remediation.evidence import VendorEvidenceCatalog

CHECK_ACTIONS = {"windows_feature": re.compile(r"[A-Za-z0-9-]{1,64}")}
STATUS_LABELS = {"present": "presente", "absent": "ausente", "unknown": "desconhecido"}
EFFECTS = {
    "present": "Requisito presente: a exposição descrita pela fonte se aplica a este ativo.",
    "absent": "Requisito ausente segundo a coleta: a fonte indica exposição reduzida, mas o pacote não está atualizado "
              "e o achado não é encerrado; a correção continua recomendada.",
    "unknown": "Requisito não verificado: colete o estado indicado antes de concluir sobre a exposição.",
}


def _feature_state(features, name):
    state = str((features or {}).get(name) or "").lower()
    if state in {"installed", "enabled"}:
        return "present"
    if state in {"available", "removed", "notpresent", "disabled", "disabledwithpayloadremoved"}:
        return "absent"
    return "unknown"


def from_catalog(cve, product_name, installed_version, features=None, evidence_path=None):
    catalog = VendorEvidenceCatalog(evidence_path)
    entry = catalog.find_windows(cve, product_name, installed_version) if installed_version else None
    out = []
    for item in (entry or {}).get("requirements") or []:
        check = item.get("check") if isinstance(item.get("check"), dict) else None
        valid_check = bool(check and check.get("action") in CHECK_ACTIONS
                           and CHECK_ACTIONS[check["action"]].fullmatch(str(check.get("name") or "")))
        status = _feature_state(features, check["name"]) if valid_check else "unknown"
        out.append({"id": str(item.get("id") or "")[:64], "description": str(item.get("description") or "")[:300],
                    "status": status, "status_label": STATUS_LABELS[status], "effect": EFFECTS[status],
                    "check": check if valid_check else None, "origin": "catalogo_oficial_curado",
                    "sources": [{"label": s.get("label"), "url": s.get("url")} for s in entry.get("sources") or []
                                if isinstance(s, dict) and str(s.get("url", "")).startswith("https://")]})
    return out


def from_ai(items, evidence_ids):
    out = []
    for item in items or []:
        cited = [i for i in item.get("evidence_ids", []) if i in evidence_ids]
        if cited:
            out.append({"id": "ai-" + str(len(out)), "description": item["description"], "status": "unknown",
                        "status_label": STATUS_LABELS["unknown"], "effect": EFFECTS["unknown"], "check": None,
                        "origin": "ia_com_evidencias", "evidence_ids": cited})
    return out


def pending_checks(requirements):
    """Read-only collection actions needed to resolve unknown requirements."""
    return [{"action": r["check"]["action"], "name": r["check"]["name"]} for r in requirements
            if r["status"] == "unknown" and r.get("check")]
