"""Authoritative remediation facts for AI explanations, and consistency checks.

The remediation engine, not the model, decides whether a correction command
exists, which fixed version is known and what the correction state is. These
facts are:
- computed here from the deterministic plan (correction command, verification
  command and read-only diagnostics are separate; diagnostics never count as
  a correction);
- shown to the analyst as engine statements, independently of the AI text;
- sent to the model, which must copy them into structured ``claims``;
- enforced on the answer: claims that differ from the engine, or prose that
  contradicts it, discard the whole explanation.

Absence of a fixed version means the EyeMole sources did not report one
(insufficient data), never that the vendor or distribution has no published
fix. EyeMole does not observe the asset's package repository, so availability
there is always "not observed".
"""
import re

from .ai_contract import AIContractError

# Bump when the facts/claims contract changes: explanations generated under an
# older contract stop being current (records and audit entries are kept).
FACTS_VERSION = 2

FIX_STATES = ("validated_command", "fixed_version_without_command", "insufficient_data")
CLAIM_KEYS = frozenset({"correction_command_available", "fixed_version", "fix_state"})
MAX_DIAGNOSTIC_LABELS = 8


def _text(value, maximum=200):
    if value is None:
        return None
    text = "".join(c for c in str(value) if ord(c) >= 32).strip()
    return text[:maximum] or None


def correction_command_available(plan):
    """True only for an engine-validated correction (never for diagnostics)."""
    command = plan.get("command")
    if not isinstance(command, str) or not command.strip() or plan.get("status") != "success":
        return False
    kind = plan.get("guidance_kind")
    return kind == "command" if isinstance(kind, str) and kind else True  # v1 plans: status+command


def engine_facts(plan):
    """Facts for one installation, derived only from the deterministic plan."""
    correction = correction_command_available(plan)
    verification = correction and isinstance(plan.get("verification_command"), str) \
        and bool(plan["verification_command"].strip())
    fixed = _text(plan.get("fixed_version"), 128)
    diagnostics = [label for label in (_text(d.get("label"), 120) for d in plan.get("diagnostics") or []
                                       if isinstance(d, dict) and str(d.get("script") or "").strip()) if label]
    if correction:
        state = "validated_command"
    elif fixed:
        state = "fixed_version_without_command"
    else:
        state = "insufficient_data"
    missing = [_text(m, 80) for m in plan.get("missing_context") or [] if _text(m, 80)]
    if not fixed and "fixed_version" not in missing:
        missing.append("fixed_version")
    facts = {
        "finding_id": plan["finding_id"],
        "cve": _text(plan.get("cve"), 40),
        "package": _text(plan.get("package") or plan.get("package_name")),
        "installed_version": _text(plan.get("installed_version"), 128),
        "operating_system": _text(plan.get("operating_system"), 60),
        "os_version": _text(plan.get("os_version"), 60),
        "correction_command_available": correction,
        "verification_command_available": bool(verification),
        "read_only_diagnostics": diagnostics[:MAX_DIAGNOSTIC_LABELS],
        "fixed_version": fixed,
        "fix_state": state,
        # fixed_version comes from the engine's sources; its absence is not proof of "no fix".
        "fix_publication": "reported_by_sources" if fixed else "not_determined",
        "repository_availability": "not_observed",
        "missing_context": missing[:12],
    }
    facts["statements"] = statements(facts)
    return facts


def _subject(facts):
    package = facts.get("package") or "pacote"
    return f"{package} ({facts['cve']})" if facts.get("cve") else package


def statements(facts):
    """Fixed Portuguese sentences shown as engine facts (never model output)."""
    system = " ".join(v for v in (facts.get("operating_system"), facts.get("os_version")) if v) or "a distribuição do ativo"
    out = []
    if facts["correction_command_available"]:
        out.append("O motor do EyeMole gerou um comando de correção validado para esta instalação "
                   "(exibido na orientação; o EyeMole não o executa).")
    else:
        out.append("O motor do EyeMole não gerou comando de correção para esta instalação.")
    if facts["read_only_diagnostics"]:
        out.append("Diagnósticos somente leitura disponíveis (não corrigem a vulnerabilidade): "
                   + "; ".join(facts["read_only_diagnostics"]) + ".")
    if facts["fixed_version"]:
        out.append(f"Versão corrigida informada pelas fontes do EyeMole: {facts['fixed_version']}.")
    else:
        out.append("As fontes do EyeMole não informaram versão corrigida para esta instalação. "
                   "Isso indica dados insuficientes, não que a correção inexista.")
        out.append(f"Publicação de correção para {system}: não determinada pelo EyeMole.")
    out.append("Disponibilidade da correção no repositório configurado no ativo: não observada pelo EyeMole.")
    return out


# ----------------------------------------------------------------------
# Consistency of the model answer with the engine facts
# ----------------------------------------------------------------------

_SENTENCE_BREAK = re.compile(r"[.!?;]+(?:\s+|$)|\n")
_NEGATION = re.compile(r"\b(?:n[ãa]o|nenhum|nenhuma|sem|nem|inexist\w*|aus[êe]nci\w*|ausente)\b", re.IGNORECASE)
_CONDITIONAL = re.compile(r"\b(?:verifi\w*|confirm\w*|consult\w*|caso|checar|cheque)\b", re.IGNORECASE)
_COMMAND = re.compile(r"\bcomandos?\b", re.IGNORECASE)
_DENIES_COMMAND = re.compile(
    r"\bn[ãa]o\s+(?:h[áa]|existe|cont[ée]m|possui|inclui|apresenta|foi\s+gerad\w*|gerou)\b[^.]{0,30}\bcomando"
    r"|\b(?:nenhum|sem)\s+comando",
    re.IGNORECASE)
_NO_PUBLISHED_FIX = re.compile(
    r"\b(?:n[ãa]o|nenhuma)\s+(?:h[áa]\s+|existe\s+|foi\s+|est[áa]\s+)?(?:uma\s+)?corre[çc][ãa]o\s+"
    r"(?:\w+\s+)?(?:publicad|dispon[íi]ve|lan[çc]ad|liberad)"
    r"|\bsem\s+corre[çc][ãa]o\s+(?:\w+\s+)?(?:publicad|dispon[íi]ve|lan[çc]ad|liberad)"
    r"|\bcorre[çc][ãa]o\s+(?:ainda\s+)?n[ãa]o\s+(?:foi\s+|est[áa]\s+)?(?:publicad|lan[çc]ad|liberad|disponibilizad|dispon[íi]ve)"
    r"|\b(?:fornecedor|fabricante|mantenedor\w*|distribui[çc][ãa]o|debian|ubuntu|red\s*hat)\b[^.]{0,40}"
    r"\bn[ãa]o\s+(?:\w+\s+)?(?:publicou|lan[çc]ou|liberou|disponibilizou|corrigiu)",
    re.IGNORECASE)
_REPOSITORY_CLAIM = re.compile(
    r"\b(?:est[áa]|encontra-se|j[áa]\s+est[áa]|n[ãa]o\s+est[áa])\s+dispon[íi]vel\s+no\s+reposit[óo]rio"
    r"|\breposit[óo]rio\b[^.]{0,40}\b(?:oferece|fornece|cont[ée]m|disponibiliza|n[ãa]o\s+(?:oferece|fornece|cont[ée]m))\b"
    r"|\bcandidat[ao]\b[^.]{0,40}\b(?:[ée]|permanece|continua)\b",
    re.IGNORECASE)
_URL = re.compile(r"https?://\S+")
# Version-like tokens (1.0-2, 2:9.1.1230-2, 10.0.17763.1234); a sentence-final period is not part of them.
_VERSION = re.compile(r"(?<![\w.:~+-])(?:\d+:)?\d+(?:\.\d+)+(?:[-+~][0-9A-Za-z+~]+(?:\.[0-9A-Za-z+~]+)*)*(?![\w])")


def _sentences(text):
    # Breaks only at punctuation followed by space/end: versions (2:9.1.1230-2) stay whole.
    return [s.strip() for s in _SENTENCE_BREAK.split(text or "") if s.strip()]


def _contradiction(provider, detail):
    return AIContractError(f"{provider}: a resposta contradiz os fatos do motor ({detail}); explicação descartada.",
                           "contradicts_engine")


def check_text(text, facts_list, provider):
    """Reject prose that contradicts the engine facts of the installations it covers."""
    any_command = any(f["correction_command_available"] for f in facts_list)
    all_command = bool(facts_list) and all(f["correction_command_available"] for f in facts_list)
    allowed = [v for f in facts_list for v in (f.get("installed_version"), f.get("fixed_version"), f.get("os_version")) if v]
    for sentence in _sentences(text):
        if not any_command and _COMMAND.search(sentence) and not _NEGATION.search(sentence):
            raise _contradiction(provider, "afirma haver comando de correção, mas o motor não gerou nenhum")
        if all_command and _DENIES_COMMAND.search(sentence):
            raise _contradiction(provider, "nega o comando de correção validado pelo motor")
        if _NO_PUBLISHED_FIX.search(sentence):
            raise _contradiction(provider, "conclui que não há correção publicada, o que o EyeMole não determina")
        if _REPOSITORY_CLAIM.search(sentence) and not _CONDITIONAL.search(sentence):
            raise _contradiction(provider, "afirma a disponibilidade no repositório do ativo, que o EyeMole não observa")
    for token in _VERSION.findall(_URL.sub(" ", text or "")):
        if not any(token in version for version in allowed):
            raise _contradiction(provider, f"cita a versão {token}, ausente dos dados do motor")


def check_claims(claims, facts, provider):
    if not isinstance(claims, dict) or set(claims) != CLAIM_KEYS:
        raise AIContractError(f"{provider}: claims ausentes ou fora do contrato.")
    expected = {key: facts[key] for key in CLAIM_KEYS}
    if claims["fix_state"] not in FIX_STATES or claims != expected:
        raise _contradiction(provider, "claims diferentes de comando, versão corrigida ou estado da correção")


def enforce(result, plans, provider, require_claims):
    """Validate a contract-valid answer against the engine; returns a display-ready copy.

    Contradictions raise (nothing is stored or shown). Known finding IDs in the
    prose are replaced by "package (CVE)" so the hash is never the main text.
    """
    facts = {p["finding_id"]: engine_facts(p) for p in plans}
    covered = []
    recommendations = []
    for item in result["recommendations"]:
        f = facts[item["finding_id"]]
        covered.append(f)
        if require_claims or "claims" in item:
            check_claims(item.get("claims"), f, provider)
        check_text(item["explanation"], [f], provider)
        recommendations.append(dict(item, explanation=_humanize(item["explanation"], facts),
                                    subject={"package": f["package"], "cve": f["cve"],
                                             "installed_version": f["installed_version"]}))
    # The summary may speak about every installation of the request.
    check_text(result["summary"], list(facts.values()), provider)
    return dict(result, summary=_humanize(result["summary"], facts), recommendations=recommendations,
                engine_facts=list(facts.values()), facts_version=FACTS_VERSION)


def _humanize(text, facts):
    for fid, f in facts.items():
        text = text.replace(fid, _subject(f))
    return text
