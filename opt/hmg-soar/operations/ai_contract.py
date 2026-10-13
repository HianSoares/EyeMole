"""Response contract shared by every AI provider (NVIDIA, other OpenAI-compatible, Kiro).

The model only produces explanatory text tied to finding and evidence IDs that
the backend supplied. Commands always come from the deterministic remediation
engine; a response that adds fields, cites unknown IDs or carries command-like
content is rejected as a whole.
"""
import json
import re

from .security import OperationError

RESPONSE_KEYS = frozenset({"summary", "recommendations"})
RECOMMENDATION_KEYS = frozenset({"finding_id", "evidence_ids", "explanation"})
MAX_SUMMARY = 4000
MAX_EXPLANATION = 2000
MAX_RECOMMENDATIONS = 100
MAX_EVIDENCE_REFERENCES = 50

# Lines that read as shell / PowerShell / package-manager instructions. Prose
# that merely names a package manager ("gerenciador apt") is not matched.
_COMMAND_LINE = re.compile(
    r"^\s*(?:[-*>•]\s*|\d+[.)]\s*)?(?:[$#]\s*)?"
    r"(?:sudo|apt(?:-get)?|dnf|yum|zypper|apk|rpm|dpkg|snap|pip3?|npm|curl|wget|bash|sh|"
    r"powershell(?:\.exe)?|pwsh|msiexec(?:\.exe)?|wusa(?:\.exe)?|systemctl|chmod|chown|rm|"
    r"(?:Install|Get|Set|Invoke|Start|Remove|New|Add)-[A-Za-z]+)\b(?:\s|$)",
    re.IGNORECASE | re.MULTILINE,
)
_INLINE_COMMAND = re.compile(r"\bsudo\s+\S|\$\(|`[^`]*\b(?:apt-get|yum|dnf|zypper|wusa|msiexec|Install-\w+)\b[^`]*`",
                             re.IGNORECASE)


class AIContractError(OperationError):
    """The provider answered, but not within the contract. Never retried as success."""

    def __init__(self, message, code="invalid_response"):
        super().__init__(message, 502)
        self.code = code


def _check_text(value, maximum, label, provider):
    if not isinstance(value, str) or not value.strip():
        raise AIContractError(f"{provider}: {label} ausente ou inválido.")
    if len(value) > maximum:
        raise AIContractError(f"{provider}: {label} acima do limite.", "response_too_large")
    if any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise AIContractError(f"{provider}: {label} contém caracteres de controle.")
    if "```" in value or _COMMAND_LINE.search(value) or _INLINE_COMMAND.search(value):
        raise AIContractError(f"{provider} incluiu comando ou script na explicação; resposta descartada.",
                              "command_in_text")


def validate_response(response, evidence_ids, finding_ids, provider="IA"):
    """Validate a parsed response object. Returns a normalized copy."""
    if not isinstance(response, dict) or set(response) != RESPONSE_KEYS:
        raise AIContractError(f"Resposta {provider} fora do contrato.")
    _check_text(response["summary"], MAX_SUMMARY, "resumo", provider)
    recommendations = response["recommendations"]
    if not isinstance(recommendations, list) or len(recommendations) > MAX_RECOMMENDATIONS:
        raise AIContractError(f"Recomendações {provider} inválidas.")
    normalized = []
    for item in recommendations:
        if not isinstance(item, dict) or set(item) != RECOMMENDATION_KEYS:
            raise AIContractError(f"{provider} retornou campos não permitidos.")
        finding, cited = item["finding_id"], item["evidence_ids"]
        if not isinstance(finding, str) or finding not in finding_ids:
            raise AIContractError(f"{provider} citou evidência ou instância desconhecida.", "unknown_reference")
        if (not isinstance(cited, list) or len(cited) > MAX_EVIDENCE_REFERENCES
                or any(not isinstance(i, str) or i not in evidence_ids for i in cited)):
            raise AIContractError(f"{provider} citou evidência ou instância desconhecida.", "unknown_reference")
        if not isinstance(item["explanation"], str) or len(item["explanation"]) > MAX_EXPLANATION:
            raise AIContractError(f"Explicação {provider} acima do limite.", "response_too_large")
        _check_text(item["explanation"], MAX_EXPLANATION, "explicação", provider)
        normalized.append({"finding_id": finding, "evidence_ids": list(dict.fromkeys(cited)),
                           "explanation": item["explanation"].strip()})
    return {"summary": response["summary"].strip(), "recommendations": normalized}


_THINK_BLOCK = re.compile(r"^\s*<think>.*?</think>\s*", re.DOTALL)
_FENCE = re.compile(r"^```(?:json)?\s*\n(.*)\n```\s*$", re.DOTALL)


def parse_message_content(content, evidence_ids, finding_ids, provider="IA"):
    """Strict parser for chat-completion text: exactly one JSON object.

    A leading reasoning block (<think>…</think>) and a single surrounding
    ```json fence are tolerated; any other surrounding text is rejected.
    """
    if not isinstance(content, str):
        raise AIContractError(f"{provider} não retornou texto.")
    text = _THINK_BLOCK.sub("", content, count=1).strip()
    fenced = _FENCE.match(text)
    if fenced:
        text = fenced.group(1).strip()
    try:
        data = json.loads(text)
    except ValueError:
        raise AIContractError(f"{provider} retornou JSON inválido.", "invalid_json")
    return validate_response(data, evidence_ids, finding_ids, provider)
