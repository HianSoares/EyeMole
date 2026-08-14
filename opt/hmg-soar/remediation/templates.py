"""
Template Repository para o módulo de Remediation Guidance.

Gera comandos de correção a partir de templates locais controlados em JSON.
Os templates são selecionados EXCLUSIVAMENTE pelo backend com base no
package_manager inferido do sistema operacional.

Invariantes:
- Templates vêm exclusivamente do arquivo local controlado
- Nunca do navegador ou do snapshot
- Usa apenas parâmetros previamente validados
- Gera correção e verificação como par
- Não gera verificação sem correção
- Rejeita template ausente ou inválido
- Falha fechada
- Nenhum eval, exec, shell, concatenação arbitrária
- Nenhum pipe, redirecionamento, download, serviço de sistema ou escalação
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional

from .models import RenderedCommand
from .validation import ParameterValidator, ValidationError

logger = logging.getLogger("hmg-soar-remediation.templates")

# Diretório de dados de templates
_DEFAULT_TEMPLATES_PATH = Path(__file__).parent / "data" / "remediation_templates.json"


class TemplateRepository:
    """Repositório de templates de comandos de correção.

    Carrega templates do arquivo JSON local. Nunca aceita templates
    de fontes externas (browser, rede, snapshot).
    """

    def __init__(self, templates_path: Optional[Path] = None) -> None:
        self._templates_path = templates_path or _DEFAULT_TEMPLATES_PATH
        self._templates: dict = {}
        self._allowlist: dict = {}
        self._loaded = False
        self._load_templates()

    def _load_templates(self) -> None:
        """Carrega templates do arquivo JSON local."""
        try:
            if not self._templates_path.is_file():
                logger.error(
                    "Arquivo de templates não encontrado: %s",
                    self._templates_path.name,
                )
                self._loaded = False
                return

            with open(self._templates_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                logger.error("Formato inválido no arquivo de templates.")
                self._loaded = False
                return

            self._templates = data.get("templates", {})
            self._allowlist = data.get("allowlist", {})
            self._loaded = True
            logger.info(
                "Templates carregados: %d gerenciadores de pacotes",
                len(self._templates),
            )

        except (json.JSONDecodeError, OSError) as e:
            logger.error("Erro ao carregar templates: %s", str(e))
            self._loaded = False

    def is_loaded(self) -> bool:
        """Verifica se templates foram carregados com sucesso."""
        return self._loaded

    def is_os_allowed(self, operating_system: str) -> bool:
        """Verifica se o sistema operacional está na allowlist."""
        if not self._loaded:
            return False
        os_lower = operating_system.lower().strip()
        return os_lower in self._allowlist.get("os_to_package_manager", {})

    def is_package_manager_allowed(self, package_manager: str) -> bool:
        """Verifica se o gerenciador de pacotes está na allowlist."""
        if not self._loaded:
            return False
        pm_lower = package_manager.lower().strip()
        return pm_lower in self._templates

    def get_package_manager_for_os(self, operating_system: str) -> Optional[str]:
        """Resolve o package manager a partir do OS via allowlist.

        Retorna None se o OS não estiver mapeado (fail-safe).
        """
        if not self._loaded:
            return None
        os_lower = operating_system.lower().strip()
        return self._allowlist.get("os_to_package_manager", {}).get(os_lower)

    def render_command(
        self,
        package_manager: str,
        package_name: str,
        installed_version: str,
        fixed_version: Optional[str],
        generic_policy_enabled: bool = False,
        package_names: Optional[List[str]] = None,
    ) -> Optional[RenderedCommand]:
        """Renderiza comandos de correção e verificação.

        Retorna None (fail-closed) quando:
        - Templates não carregados
        - Package manager não reconhecido
        - Parâmetros inválidos
        - Template ausente ou malformado
        - fixed_version ausente E generic_policy desabilitada
        - fixed_version igual a installed_version

        Args:
            package_manager: Gerenciador de pacotes (ex: "apt")
            package_name: Nome do pacote validado
            installed_version: Versão instalada validada
            fixed_version: Versão corrigida (None se não confirmada)
            generic_policy_enabled: Se True e fixed_version ausente, gera update genérico

        Returns:
            RenderedCommand com par correção/verificação, ou None
        """
        # Fail-closed: templates não carregados
        if not self._loaded:
            return None

        # Validar parâmetros antes de qualquer operação (fail-fast)
        pm_lower = package_manager.lower().strip()
        if pm_lower == "windows":
            validation_err = self._validate_windows_template_rendering(
                installed_version, fixed_version, package_manager
            )
        else:
            validation_err = ParameterValidator.validate_for_template_rendering(
                package_name, installed_version, fixed_version, package_manager
            )
        if validation_err is not None:
            return None

        if pm_lower == "windows":
            grouped_package_names = [package_name]
        else:
            grouped_package_names = self._normalize_package_names(package_name, package_names)
            if not grouped_package_names:
                return None

        # Verificar allowlist
        if pm_lower not in self._templates:
            return None

        template_set = self._templates[pm_lower]
        if not isinstance(template_set, dict):
            return None

        remediation_templates = template_set.get("remediation")
        verification_templates = template_set.get("verification")

        if not isinstance(remediation_templates, dict):
            return None
        if not isinstance(verification_templates, dict):
            return None

        # Decidir qual template de remediação usar
        if fixed_version is not None and fixed_version.strip():
            # Versões iguais: não gerar comando (não é upgrade)
            if fixed_version.strip() == installed_version.strip():
                return None

            template_key = "with_version"
        elif generic_policy_enabled:
            template_key = "generic_update"
        else:
            # Sem fixed_version e sem política genérica → sem comando
            return None

        # Obter template de remediação
        remediation_tpl = remediation_templates.get(template_key)
        if not remediation_tpl or not isinstance(remediation_tpl, str):
            return None

        # Obter template de verificação
        verification_tpl = verification_templates.get("check_version")
        if not verification_tpl or not isinstance(verification_tpl, str):
            return None

        # Renderizar via substituição estrita (sem eval/exec/format arbitrário)
        try:
            rendered_remediation = self._safe_substitute(
                remediation_tpl,
                package_name,
                installed_version,
                fixed_version,
                grouped_package_names,
            )
            rendered_verification = self._safe_substitute(
                verification_tpl,
                package_name,
                installed_version,
                fixed_version,
                grouped_package_names,
            )
        except (KeyError, ValueError):
            # Template malformado → fail-closed
            return None

        if not rendered_remediation:
            return None

        return RenderedCommand(
            remediation=rendered_remediation,
            verification=rendered_verification or "",
        )

    @staticmethod
    def _validate_windows_template_rendering(
        installed_version: str,
        fixed_version: Optional[str],
        package_manager: str,
    ) -> Optional[ValidationError]:
        err = ParameterValidator.validate_version(installed_version)
        if err:
            return err

        if fixed_version is not None:
            err = ParameterValidator.validate_version(fixed_version)
            if err:
                return err

        return ParameterValidator.validate_package_manager(package_manager)

    @staticmethod
    def _normalize_package_names(
        package_name: str,
        package_names: Optional[List[str]],
    ) -> List[str]:
        """Normaliza e valida lista de pacotes para comandos agrupados."""
        candidates = package_names if package_names else [package_name]
        normalized: List[str] = []
        seen = set()

        for raw_name in candidates:
            name = str(raw_name or "").strip()
            if not name or name in seen:
                continue

            err = ParameterValidator.validate_package_name(name)
            if err is not None:
                continue

            normalized.append(name)
            seen.add(name)

        return normalized

    @staticmethod
    def _safe_substitute(
        template: str,
        package_name: str,
        installed_version: str,
        fixed_version: Optional[str],
        package_names: List[str],
    ) -> str:
        """Substituição segura de parâmetros no template.

        Usa APENAS str.replace com placeholders explícitos.
        Nunca usa eval, exec, format com chaves arbitrárias, ou f-strings com input.
        """
        result = template
        result = result.replace("{package_name}", package_name)
        result = result.replace("{package_names}", " ".join(package_names))
        result = result.replace("{installed_version}", installed_version)
        if fixed_version is not None:
            result = result.replace("{fixed_version}", fixed_version)

        # Verificar se sobrou algum placeholder não substituído
        if "{" in result and "}" in result:
            # Template malformado ou placeholder desconhecido → falha
            raise ValueError("Placeholder não resolvido no template")

        return result
