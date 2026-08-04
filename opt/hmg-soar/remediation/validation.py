"""
Validador de parâmetros para o módulo de Remediation Guidance.

Implementa validação fail-fast: na primeira falha, interrompe, não consulta
templates, não tenta outro caminho, não produz comandos.

Invariantes:
- Rejeita metacaracteres de shell
- Rejeita quebras de linha e caracteres de controle
- Rejeita strings vazias
- Rejeita excesso de tamanho
- Rejeita valores fora da allowlist
- Não inclui o valor rejeitado integralmente em mensagens públicas
- Não importa subprocess, os.system, eval, exec
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Tuple


# ==========================================================================
# CONSTANTES DE VALIDAÇÃO
# ==========================================================================

# Padrões de caracteres permitidos
FINDING_ID_PATTERN = re.compile(r"^[A-Fa-f0-9]{64}$")
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
PACKAGE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]*$")
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~:-]*$")
OS_PATTERN = re.compile(r"^[A-Za-z0-9._/ -]+$")
PACKAGE_MANAGER_PATTERN = re.compile(r"^[a-z]{2,10}$")

# Metacaracteres de shell que DEVEM ser rejeitados
SHELL_METACHARACTERS = frozenset(";|&$`\\(){}[]!#*?<>")

# Caracteres de controle (exceto tab que é raramente perigoso mas rejeitamos mesmo assim)
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# Substituição de comando patterns
COMMAND_SUBSTITUTION_PATTERN = re.compile(r"\$\(|\$\{|`")

# Redirecionamento patterns
REDIRECT_PATTERN = re.compile(r"[<>]|>>|<<|2>|&>")

# Limites de tamanho
MAX_FINDING_ID_LEN = 128
MAX_CVE_LEN = 32
MAX_AGENT_ID_LEN = 64
MAX_PACKAGE_NAME_LEN = 256
MAX_VERSION_LEN = 256
MAX_OS_LEN = 128
MAX_PACKAGE_MANAGER_LEN = 10

# Confidence levels válidos
VALID_CONFIDENCE = frozenset({"high", "medium", "low", "none"})

# Status válidos
VALID_STATUS = frozenset({
    "success", "no_guidance", "not_found", "validation_error",
    "insufficient_confidence", "internal_error", "provider_unavailable",
})

# Ações válidas (para auditoria no núcleo, se aplicável)
VALID_ACTIONS = frozenset({"view", "copy"})


@dataclass
class ValidationError:
    """Erro de validação sanitizado — não expõe o valor rejeitado."""

    field: str
    reason_code: str
    message: str  # Mensagem segura para consumidor (sem valor raw)

    def to_dict(self) -> dict:
        return {
            "field": self.field,
            "reason_code": self.reason_code,
            "message": self.message,
        }


class ParameterValidator:
    """Validador fail-fast para parâmetros do módulo de remediação.

    Na primeira falha:
    - Interrompe imediatamente
    - Não consulta templates
    - Não tenta caminhos alternativos
    - Não produz comandos
    - Retorna erro sanitizado
    """

    @staticmethod
    def _has_shell_metacharacters(value: str) -> bool:
        """Verifica se valor contém metacaracteres de shell."""
        return any(c in SHELL_METACHARACTERS for c in value)

    @staticmethod
    def _has_control_characters(value: str) -> bool:
        """Verifica se valor contém caracteres de controle ou quebras de linha."""
        return bool(CONTROL_CHAR_PATTERN.search(value))

    @staticmethod
    def _has_command_substitution(value: str) -> bool:
        """Verifica se valor contém padrões de substituição de comando."""
        return bool(COMMAND_SUBSTITUTION_PATTERN.search(value))

    @staticmethod
    def _has_redirects(value: str) -> bool:
        """Verifica se valor contém redirecionamentos."""
        return bool(REDIRECT_PATTERN.search(value))

    @staticmethod
    def _check_common_rejections(
        value: str, field_name: str, max_len: int
    ) -> Optional[ValidationError]:
        """Verificações comuns a todos os campos: vazio, tamanho, controle, shell."""
        if not value:
            return ValidationError(
                field=field_name,
                reason_code="empty_value",
                message=f"Campo '{field_name}' não pode ser vazio.",
            )

        if len(value) > max_len:
            return ValidationError(
                field=field_name,
                reason_code="exceeds_max_length",
                message=f"Campo '{field_name}' excede o tamanho máximo permitido.",
            )

        if ParameterValidator._has_control_characters(value):
            return ValidationError(
                field=field_name,
                reason_code="control_characters",
                message=f"Campo '{field_name}' contém caracteres de controle não permitidos.",
            )

        if ParameterValidator._has_shell_metacharacters(value):
            return ValidationError(
                field=field_name,
                reason_code="shell_metacharacters",
                message=f"Campo '{field_name}' contém caracteres não permitidos.",
            )

        if ParameterValidator._has_command_substitution(value):
            return ValidationError(
                field=field_name,
                reason_code="command_substitution",
                message=f"Campo '{field_name}' contém padrão não permitido.",
            )

        if ParameterValidator._has_redirects(value):
            return ValidationError(
                field=field_name,
                reason_code="redirect_characters",
                message=f"Campo '{field_name}' contém caracteres de redirecionamento.",
            )

        return None

    @classmethod
    def validate_finding_id(cls, value: str) -> Optional[ValidationError]:
        """Valida finding_id (SHA-256 hex, 64 chars)."""
        err = cls._check_common_rejections(value, "finding_id", MAX_FINDING_ID_LEN)
        if err:
            return err

        if not FINDING_ID_PATTERN.match(value):
            return ValidationError(
                field="finding_id",
                reason_code="invalid_format",
                message="Campo 'finding_id' não corresponde ao formato esperado.",
            )
        return None

    @classmethod
    def validate_cve(cls, value: str) -> Optional[ValidationError]:
        """Valida CVE (formato CVE-YYYY-NNNN+)."""
        err = cls._check_common_rejections(value, "cve", MAX_CVE_LEN)
        if err:
            return err

        if not CVE_PATTERN.match(value):
            return ValidationError(
                field="cve",
                reason_code="invalid_format",
                message="Campo 'cve' não corresponde ao formato esperado.",
            )
        return None

    @classmethod
    def validate_agent_id(cls, value: str) -> Optional[ValidationError]:
        """Valida agent_id."""
        err = cls._check_common_rejections(value, "agent_id", MAX_AGENT_ID_LEN)
        if err:
            return err

        if not AGENT_ID_PATTERN.match(value):
            return ValidationError(
                field="agent_id",
                reason_code="invalid_format",
                message="Campo 'agent_id' não corresponde ao formato esperado.",
            )
        return None

    @classmethod
    def validate_package_name(cls, value: str) -> Optional[ValidationError]:
        """Valida nome de pacote."""
        err = cls._check_common_rejections(value, "package_name", MAX_PACKAGE_NAME_LEN)
        if err:
            return err

        if not PACKAGE_NAME_PATTERN.match(value):
            return ValidationError(
                field="package_name",
                reason_code="invalid_format",
                message="Campo 'package_name' contém caracteres não permitidos.",
            )
        return None

    @classmethod
    def validate_version(cls, value: str) -> Optional[ValidationError]:
        """Valida versão (installed ou fixed)."""
        err = cls._check_common_rejections(value, "version", MAX_VERSION_LEN)
        if err:
            return err

        if not VERSION_PATTERN.match(value):
            return ValidationError(
                field="version",
                reason_code="invalid_format",
                message="Campo 'version' contém caracteres não permitidos.",
            )
        return None

    @classmethod
    def validate_operating_system(cls, value: str) -> Optional[ValidationError]:
        """Valida sistema operacional."""
        err = cls._check_common_rejections(value, "operating_system", MAX_OS_LEN)
        if err:
            return err

        if not OS_PATTERN.match(value):
            return ValidationError(
                field="operating_system",
                reason_code="invalid_format",
                message="Campo 'operating_system' contém caracteres não permitidos.",
            )
        return None

    @classmethod
    def validate_package_manager(cls, value: str) -> Optional[ValidationError]:
        """Valida gerenciador de pacotes."""
        err = cls._check_common_rejections(value, "package_manager", MAX_PACKAGE_MANAGER_LEN)
        if err:
            return err

        if not PACKAGE_MANAGER_PATTERN.match(value):
            return ValidationError(
                field="package_manager",
                reason_code="invalid_format",
                message="Campo 'package_manager' contém caracteres não permitidos.",
            )
        return None

    @classmethod
    def validate_confidence(cls, value: str) -> Optional[ValidationError]:
        """Valida nível de confiança."""
        if not value:
            return ValidationError(
                field="confidence",
                reason_code="empty_value",
                message="Campo 'confidence' não pode ser vazio.",
            )
        if value not in VALID_CONFIDENCE:
            return ValidationError(
                field="confidence",
                reason_code="invalid_value",
                message="Campo 'confidence' possui valor não reconhecido.",
            )
        return None

    @classmethod
    def validate_status(cls, value: str) -> Optional[ValidationError]:
        """Valida status."""
        if not value:
            return ValidationError(
                field="status",
                reason_code="empty_value",
                message="Campo 'status' não pode ser vazio.",
            )
        if value not in VALID_STATUS:
            return ValidationError(
                field="status",
                reason_code="invalid_value",
                message="Campo 'status' possui valor não reconhecido.",
            )
        return None

    @classmethod
    def validate_action(cls, value: str) -> Optional[ValidationError]:
        """Valida ação (view, copy)."""
        if not value:
            return ValidationError(
                field="action",
                reason_code="empty_value",
                message="Campo 'action' não pode ser vazio.",
            )
        if value not in VALID_ACTIONS:
            return ValidationError(
                field="action",
                reason_code="invalid_value",
                message="Campo 'action' possui valor não reconhecido.",
            )
        return None

    @classmethod
    def validate_for_template_rendering(
        cls, package_name: str, installed_version: str,
        fixed_version: Optional[str], package_manager: str
    ) -> Optional[ValidationError]:
        """Validação completa antes de renderizar template.

        Fail-fast: retorna na PRIMEIRA falha encontrada.
        """
        err = cls.validate_package_name(package_name)
        if err:
            return err

        err = cls.validate_version(installed_version)
        if err:
            return err

        if fixed_version is not None:
            err = cls.validate_version(fixed_version)
            if err:
                return err

        err = cls.validate_package_manager(package_manager)
        if err:
            return err

        return None
