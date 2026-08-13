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
from typing import List, Optional


# Status válidos para GuidanceRecord
VALID_STATUSES = frozenset({
    "success",
    "no_guidance",
    "not_found",
    "validation_error",
    "insufficient_confidence",
    "internal_error",
    "provider_unavailable",
})

# Níveis de confiança válidos
VALID_CONFIDENCE_LEVELS = frozenset({"high", "medium", "low", "none"})


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

    # Guidance output
    status: str = "no_guidance"
    command: Optional[str] = None
    verification_command: Optional[str] = None
    reason: Optional[str] = None
    recommendation: Optional[str] = None

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

    def __post_init__(self) -> None:
        """Valida invariantes no momento da criação."""
        # Garantir que status é válido
        if self.status not in VALID_STATUSES:
            self.status = "internal_error"

        # Garantir que confidence é válido
        if self.confidence not in VALID_CONFIDENCE_LEVELS:
            self.confidence = "none"

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

    def __post_init__(self) -> None:
        if self.confidence not in VALID_CONFIDENCE_LEVELS:
            self.confidence = "none"


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

    def to_dict(self) -> dict:
        """Ponto único de serialização do VulnRecord para JSON/Snapshot."""
        return {
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
    """
    raw_str = f"{cve or ''}|{agent_id or ''}|{package or ''}|{severity or ''}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()
