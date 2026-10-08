"""
Modelos de dados para o módulo de Remediation Guidance.

GuidanceRecord é a estrutura principal de saída. O campo execution_allowed
é uma constante False em todo contexto — não pode ser alterado por nenhuma
configuração, variável de ambiente ou parâmetro de API.
"""

from __future__ import annotations

import uuid
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# Versão do contrato público de GuidanceRecord.
# v2: separa orientação textual, comando validado, diagnósticos, justificativa,
# fontes, pré-requisitos e dados faltantes. Campos v1 continuam presentes.
GUIDANCE_CONTRACT_VERSION = "2"

# Status válidos para GuidanceRecord
VALID_STATUSES = frozenset({
    "success",
    "textual_guidance",
    "no_guidance",
    "not_found",
    "ambiguous_finding",
    "validation_error",
    "insufficient_confidence",
    "internal_error",
    "provider_unavailable",
})

# Níveis de confiança válidos
VALID_CONFIDENCE_LEVELS = frozenset({"high", "medium", "low", "none"})

# Tipos de orientação
VALID_GUIDANCE_KINDS = frozenset({"command", "textual", "none"})

# Estados de reinício
VALID_REBOOT_STATES = frozenset({"yes", "no", "maybe", "unknown"})


@dataclass
class GuidanceRecord:
    """Registro completo de orientação de correção para uma vulnerabilidade.

    Invariantes:
    - execution_allowed é SEMPRE False (constante, sem override)
    - command e verification_command são None em estados sem sucesso
    - guidance_id é opaco (UUID4), não expõe CVE/agent/package
    - Não serializa campos de comando quando None ou whitespace-only
    """

    # Identity
    guidance_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""

    # Vulnerability context (resolvido do snapshot pelo backend)
    cve: str = ""
    package_name: str = ""
    installed_version: str = ""
    fixed_version: Optional[str] = None
    operating_system: str = ""
    package_manager: str = ""
    agent_id: str = ""
    agent_name: str = ""
    severity: str = ""

    # Contexto do ativo/pacote propagado do snapshot (vazio = desconhecido)
    os_version: str = ""
    package_type: str = ""
    architecture: str = ""

    # Guidance output
    status: str = "no_guidance"
    command: Optional[str] = None
    verification_command: Optional[str] = None
    reason: Optional[str] = None
    recommendation: Optional[str] = None

    # Contrato v2: orientação separada de comando
    guidance_kind: str = ""
    guidance_text: Optional[str] = None
    rationale: Optional[str] = None
    shell: Optional[str] = None
    # Diagnósticos SOMENTE LEITURA: [{"label", "script", "shell"}]
    diagnostics: List[Dict[str, str]] = field(default_factory=list)
    verification_steps: List[str] = field(default_factory=list)
    expected_result: Optional[str] = None
    prerequisites: List[str] = field(default_factory=list)
    missing_context: List[str] = field(default_factory=list)
    # Fontes: [{"label", "url"?, "kind"}]
    sources: List[Dict[str, str]] = field(default_factory=list)
    reboot_required: str = "unknown"
    snapshot_revision: str = ""

    # Metadata
    source: str = ""
    confidence: str = "none"
    generation_date: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    assumptions: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def execution_allowed(self) -> bool:
        """Constante False — não pode ser alterada."""
        return False

    @property
    def contract_version(self) -> str:
        return GUIDANCE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        """Valida invariantes no momento da criação."""
        # Garantir que status é válido
        if self.status not in VALID_STATUSES:
            self.status = "internal_error"

        # Garantir que confidence é válido
        if self.confidence not in VALID_CONFIDENCE_LEVELS:
            self.confidence = "none"

        if self.reboot_required not in VALID_REBOOT_STATES:
            self.reboot_required = "unknown"

        # Em estados sem sucesso, comandos DEVEM ser None
        if self.status != "success":
            self.command = None
            self.verification_command = None

        # Verificação sem correção é inválido
        if self.command is None:
            self.verification_command = None

        # Limpar comandos que são apenas whitespace
        if self.command is not None and not self.command.strip():
            self.command = None
            self.verification_command = None

        if self.verification_command is not None and not self.verification_command.strip():
            self.verification_command = None

        if self.guidance_text is not None and not self.guidance_text.strip():
            self.guidance_text = None

        # Diagnósticos: somente entradas bem formadas
        self.diagnostics = [
            {
                "label": str(d.get("label") or "").strip(),
                "script": str(d.get("script") or "").strip(),
                "shell": str(d.get("shell") or "").strip(),
            }
            for d in self.diagnostics
            if isinstance(d, dict) and str(d.get("script") or "").strip()
        ]

        # guidance_kind é derivado dos dados, nunca aceito de fora em contradição
        if self.command is not None:
            self.guidance_kind = "command"
        elif self.guidance_text or self.diagnostics:
            self.guidance_kind = "textual"
        else:
            self.guidance_kind = "none"

    def to_dict(self) -> dict:
        """Serializa para dicionário JSON-compatível.

        Invariantes de serialização:
        - execution_allowed é SEMPRE False
        - Campos de comando não são incluídos quando None/vazio
        - Não expõe caminhos internos
        """
        result = {
            "guidance_id": self.guidance_id,
            "finding_id": self.finding_id,
            "cve": self.cve,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "operating_system": self.operating_system,
            "package_manager": self.package_manager,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "severity": self.severity,
            "status": self.status,
            "execution_allowed": False,  # CONSTANTE
            "source": self.source,
            "confidence": self.confidence,
            "generation_date": self.generation_date,
        }

        # fixed_version incluída somente quando presente
        if self.fixed_version is not None:
            result["fixed_version"] = self.fixed_version

        # Comandos incluídos somente quando realmente disponíveis
        if self.command is not None and self.command.strip():
            result["command"] = self.command
        if self.verification_command is not None and self.verification_command.strip():
            result["verification_command"] = self.verification_command

        # Reason e recommendation incluídos quando presentes
        if self.reason:
            result["reason"] = self.reason
        if self.recommendation:
            result["recommendation"] = self.recommendation

        # Listas incluídas somente quando não vazias
        if self.assumptions:
            result["assumptions"] = list(self.assumptions)
        if self.warnings:
            result["warnings"] = list(self.warnings)

        # Contrato v2 (aditivo; consumidores v1 ignoram)
        result["contract_version"] = GUIDANCE_CONTRACT_VERSION
        result["guidance_kind"] = self.guidance_kind
        result["reboot_required"] = self.reboot_required
        for key in ("os_version", "package_type", "architecture", "snapshot_revision"):
            value = getattr(self, key)
            if value:
                result[key] = value
        for key in ("guidance_text", "rationale", "expected_result"):
            value = getattr(self, key)
            if value:
                result[key] = value
        if self.shell and (self.command is not None or self.diagnostics):
            result["shell"] = self.shell
        for key in ("diagnostics", "sources"):
            value = getattr(self, key)
            if value:
                result[key] = [dict(item) for item in value]
        for key in ("verification_steps", "prerequisites", "missing_context"):
            value = getattr(self, key)
            if value:
                result[key] = list(value)

        return result


@dataclass
class ProviderResult:
    """Resultado de consulta a um provider."""

    cve: str = ""
    package_name: str = ""
    installed_version: str = ""
    fixed_version: Optional[str] = None
    operating_system: str = ""
    package_manager: str = ""
    agent_id: str = ""
    agent_name: str = ""
    severity: str = ""
    confidence: str = "none"
    source: str = ""
    warnings: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    status: str = "unknown"
    # Contexto propagado (vazio = desconhecido)
    package_type: str = ""
    os_version: str = ""
    architecture: str = ""
    purl: str = ""
    # Confiança na existência da vulnerabilidade vs. na versão de correção
    fix_confidence: str = "none"
    # Divergência não resolvida entre fontes: bloqueia o comando específico
    blocking_reason: Optional[str] = None

    def __post_init__(self) -> None:
        if self.confidence not in VALID_CONFIDENCE_LEVELS:
            self.confidence = "none"
        if self.fix_confidence not in VALID_CONFIDENCE_LEVELS:
            self.fix_confidence = "none"


@dataclass
class RenderedCommand:
    """Par de comandos renderizados pelo TemplateRepository."""

    remediation: str = ""
    verification: str = ""

    def __post_init__(self) -> None:
        # Garantir que verificação não existe sem correção
        if not self.remediation or not self.remediation.strip():
            self.remediation = ""
            self.verification = ""
        if not self.verification or not self.verification.strip():
            self.verification = ""


@dataclass
class VulnRecord:
    """Registro de vulnerabilidade detectado no Wazuh Indexer.

    Utilizado como modelo compartilhado entre o analisador e a API.
    """
    agent_id: str
    agent_name: str
    cve: str
    package_name: str
    version: str
    severity: str
    cvss_score: Optional[float]
    is_kev: bool
    is_ransomware: bool
    epss_score: Optional[float]
    priority: str = "Priority 4"
    agent_os: str = "N/A"
    os_version: str = ""
    package_type: str = ""
    scanner_condition: str = ""
    package_architecture: str = ""
    package_path: str = ""

    @property
    def finding_id(self) -> str:
        """Identidade da instância (v2) — distingue versões/instalações."""
        return generate_finding_id(
            self.cve, self.agent_id, self.package_name, self.version,
            self.package_type, self.package_architecture, self.package_path,
        )

    def to_dict(self) -> dict:
        """Ponto único de serialização do VulnRecord para JSON/Snapshot."""
        return {
            "finding_id": self.finding_id,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "cve": self.cve,
            "priority": self.priority,
            "cvss": self.cvss_score,
            "severity": self.severity,
            "epss": self.epss_score,
            "package": self.package_name,
            "version": self.version,
            "is_kev": self.is_kev,
            "is_ransomware": self.is_ransomware,
            "operating_system": self.agent_os,
            "os_version": self.os_version,
            "package_type": self.package_type,
            "package_architecture": self.package_architecture,
            "package_path": self.package_path,
            "scanner_condition": self.scanner_condition,
        }


@dataclass
class GrypeVulnRecord:
    """Registro de vulnerabilidade detectado pelo Grype."""

    cve: str                             # CVE real extraído de relatedVulnerabilities
    advisory_id: str                     # ID do Advisory (ex: GHSA-...)
    agent_id: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str] = None  # Primeiro elemento de fix.versions
    fixed_versions: List[str] = field(default_factory=list) # Lista completa
    confidence: str = "none"             # Mapeado de match-type do Grype (high, medium, low)
    match_type: str = ""                 # exact-direct-match, exact-indirect-match, cpe-match
    purl: str = ""                       # Package URL para rastreabilidade
    source: str = "grype"
    db_version: str = "unknown"
    status: str = "unknown"              # fixed, not-fixed, wont-fix, unknown

    def to_dict(self) -> dict:
        """Ponto único de serialização do GrypeVulnRecord para JSON/Snapshot."""
        return {
            "cve": self.cve,
            "advisory_id": self.advisory_id,
            "agent_id": self.agent_id,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "fixed_versions": list(self.fixed_versions) if self.fixed_versions else [],
            "confidence": self.confidence,
            "match_type": self.match_type,
            "purl": self.purl,
            "source": self.source,
            "db_version": self.db_version,
            "status": self.status,
        }


def generate_vulnerability_key(
    cve: str, agent_id: str, package: str, severity: str
) -> str:
    """Gera chave SHA-256 estável para identificação de achados (finding_id).

    Mantém compatibilidade com os snapshots legados do Wazuh.

    ATENÇÃO: não distingue versões/instalações do mesmo pacote. Continua sendo
    a chave de agregação de risco/tendência; a identidade de instância usada
    pelo fluxo "Ver correção" é generate_finding_id().
    """
    raw_str = f"{cve or ''}|{agent_id or ''}|{package or ''}|{severity or ''}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()


def generate_finding_id(
    cve: str,
    agent_id: str,
    package: str,
    version: str,
    package_type: str = "",
    architecture: str = "",
    package_path: str = "",
) -> str:
    """Identidade de instância do achado (v2), SHA-256 hex.

    Inclui versão, ecossistema, arquitetura e caminho de instalação para que
    múltiplas versões/instalações do mesmo pacote não colidam. Não inclui
    severidade (mudança de score não muda a instância). O prefixo separa o
    espaço de chaves do legado.
    """
    parts = [
        "finding:v2",
        str(cve or "").strip().upper(),
        str(agent_id or "").strip(),
        str(package or "").strip(),
        str(version or "").strip(),
        str(package_type or "").strip().lower(),
        str(architecture or "").strip().lower(),
        str(package_path or "").strip(),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def finding_id_for_snapshot_record(record: Dict[str, Any]) -> str:
    """Calcula a identidade v2 a partir de um registro do snapshot (latest.json)."""
    return generate_finding_id(
        str(record.get("cve") or ""),
        str(record.get("agent_id") or ""),
        str(record.get("package") or ""),
        str(record.get("version") or ""),
        str(record.get("package_type") or ""),
        str(record.get("package_architecture") or ""),
        str(record.get("package_path") or ""),
    )


def legacy_key_for_snapshot_record(record: Dict[str, Any]) -> str:
    return generate_vulnerability_key(
        str(record.get("cve") or ""),
        str(record.get("agent_id") or ""),
        str(record.get("package") or ""),
        str(record.get("severity") or ""),
    )
