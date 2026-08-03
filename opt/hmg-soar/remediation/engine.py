"""
Remediation Engine — orquestrador principal do módulo de Remediation Guidance.

Fluxo:
1. Validar finding_id
2. Consultar providers (prioridade definida em config)
3. Avaliar confidence e fixed_version
4. Decidir: gerar comando (template) ou apenas textual
5. Retornar GuidanceRecord com execution_allowed=False SEMPRE

Invariantes:
- execution_allowed é SEMPRE False (constante, sem override)
- Nenhum import de execução de processos
- Nenhum import de privilégio ou serviço de sistema
- Nenhuma chamada de rede
- Nenhuma escrita no snapshot
- Falha fechada: qualquer erro → sem comando
- Sem comparação lexicográfica de versões
- guidance_id é opaco (UUID4, sem CVE/agent/version em cleartext)
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional

from .models import GuidanceRecord, ProviderResult, RenderedCommand
from .providers.wazuh_provider import WazuhProvider
from .templates import TemplateRepository
from .validation import ParameterValidator

logger = logging.getLogger("hmg-soar-remediation.engine")

# Caminhos padrão
_DEFAULT_CONFIG_DIR = Path("/opt/hmg-soar/config")
_DEFAULT_SNAPSHOT_PATH = Path("/var/www/wazuh-soar/data/latest.json")


class SnapshotCache:
    """Cache em memória do snapshot com invalidação por mtime.

    TTL de 5 minutos. Reload automático se o arquivo mudar.
    """

    def __init__(self, snapshot_path: Path, max_age_seconds: int = 300) -> None:
        self._path = snapshot_path
        self._max_age_seconds = max_age_seconds
        self._data: Optional[dict] = None
        self._mtime: float = 0.0
        self._last_check: float = 0.0

    def get_data(self) -> Optional[dict]:
        """Retorna dados do snapshot, recarregando se necessário."""
        now = time.time()

        # Se nunca carregou, carregar
        if self._data is None:
            return self._reload()

        # Se TTL expirou, verificar mtime
        if now - self._last_check > self._max_age_seconds:
            return self._reload()

        return self._data

    def _reload(self) -> Optional[dict]:
        """Recarrega o snapshot do disco."""
        try:
            if not self._path.is_file():
                logger.warning("Snapshot não encontrado: %s", self._path)
                return None

            current_mtime = self._path.stat().st_mtime
            if self._data is not None and current_mtime == self._mtime:
                self._last_check = time.time()
                return self._data

            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                logger.error("Snapshot com formato inválido.")
                return None

            self._data = data
            self._mtime = current_mtime
            self._last_check = time.time()
            return self._data

        except (json.JSONDecodeError, OSError) as e:
            logger.error("Erro ao carregar snapshot: %s", str(e))
            return None

    def invalidate(self) -> None:
        """Força recarga na próxima leitura."""
        self._data = None
        self._mtime = 0.0
        self._last_check = 0.0


class RemediationEngine:
    """Orquestrador principal de geração de orientação de remediação.

    Invariantes:
    - execution_allowed é SEMPRE False
    - Fail-closed: qualquer exceção → sem comando
    - Não compara versões (não implementa version comparator)
    - Não executa subprocess, os.system, eval, exec
    - guidance_id é opaco (UUID4)
    """

    def __init__(
        self,
        config_dir: Optional[Path] = None,
        snapshot_path: Optional[Path] = None,
        templates_path: Optional[Path] = None,
    ) -> None:
        self._config_dir = config_dir or _DEFAULT_CONFIG_DIR
        self._snapshot_path = snapshot_path or _DEFAULT_SNAPSHOT_PATH

        # Carregar configuração de providers
        self._providers_config = self._load_providers_config()

        # Carregar política de atualização genérica
        self._generic_policy = self._load_generic_policy()

        # Instanciar TemplateRepository
        self._template_repo = TemplateRepository(templates_path=templates_path)

        # Instanciar WazuhProvider
        self._wazuh_provider = WazuhProvider(
            snapshot_path=self._snapshot_path,
            assets_context_path=self._config_dir / "assets_context.json",
        )

        # Snapshot cache
        self._snapshot_cache = SnapshotCache(self._snapshot_path)

    def _load_providers_config(self) -> dict:
        """Carrega configuração de providers."""
        config_path = self._config_dir / "remediation_providers.json"
        try:
            if not config_path.is_file():
                logger.warning("Config de providers não encontrada, usando padrão.")
                return {"providers": [{"name": "wazuh_snapshot", "enabled": True, "priority": 1}]}

            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                return data
            return {"providers": [{"name": "wazuh_snapshot", "enabled": True, "priority": 1}]}

        except (json.JSONDecodeError, OSError) as e:
            logger.error("Erro ao carregar config de providers: %s", str(e))
            return {"providers": [{"name": "wazuh_snapshot", "enabled": True, "priority": 1}]}

    def _load_generic_policy(self) -> dict:
        """Carrega política de atualização genérica (desabilitada por padrão)."""
        policy_path = self._config_dir / "generic_update_policy.json"
        try:
            if not policy_path.is_file():
                return {"enabled": False, "allowed_combinations": []}

            with open(policy_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                return data
            return {"enabled": False, "allowed_combinations": []}

        except (json.JSONDecodeError, OSError) as e:
            logger.error("Erro ao carregar generic_update_policy: %s", str(e))
            return {"enabled": False, "allowed_combinations": []}

    def _is_generic_update_allowed(self, operating_system: str, package_manager: str) -> bool:
        """Verifica se a política de atualização genérica permite para o par OS/PM.

        Desabilitada por padrão. Requer enabled=true E par na allowed_combinations.
        """
        if not self._generic_policy.get("enabled", False):
            return False

        allowed = self._generic_policy.get("allowed_combinations", [])
        if not isinstance(allowed, list):
            return False

        os_lower = operating_system.lower().strip()
        pm_lower = package_manager.lower().strip()

        for combo in allowed:
            if not isinstance(combo, dict):
                continue
            if (combo.get("os", "").lower() == os_lower and
                    combo.get("package_manager", "").lower() == pm_lower):
                return True

        return False

    def generate_guidance(self, finding_id: str) -> GuidanceRecord:
        """Ponto de entrada principal. Gera orientação para um finding_id.

        Invariantes:
        - execution_allowed é SEMPRE False no resultado
        - Fail-closed: qualquer exceção → sem comando
        - Não compara versões lexicograficamente
        """
        try:
            return self._generate_guidance_internal(finding_id)
        except Exception as e:
            # Fail-closed: qualquer exceção inesperada → sem comando
            logger.error("Erro inesperado na geração de guidance: %s", str(e))
            return GuidanceRecord(
                finding_id=finding_id,
                status="internal_error",
                reason="Erro interno na geração de orientação.",
                recommendation="Tente novamente mais tarde ou consulte o administrador.",
                confidence="none",
            )

    def _generate_guidance_internal(self, finding_id: str) -> GuidanceRecord:
        """Implementação interna (sem try/except externo)."""
        # 1. Validar finding_id
        err = ParameterValidator.validate_finding_id(finding_id)
        if err is not None:
            return GuidanceRecord(
                finding_id=finding_id,
                status="validation_error",
                reason=err.message,
                confidence="none",
            )

        # 2. Consultar providers
        provider_result = self._query_providers(finding_id)
        if provider_result is None:
            return GuidanceRecord(
                finding_id=finding_id,
                status="not_found",
                reason="Achado não encontrado no snapshot atual.",
                recommendation="Verifique se o finding_id é válido e se o snapshot está atualizado.",
                confidence="none",
            )

        # 3. Avaliar confidence e elegibilidade
        confidence = provider_result.confidence
        fixed_version = provider_result.fixed_version
        package_manager = provider_result.package_manager
        operating_system = provider_result.operating_system

        # Se confidence é "none" → sem comando independente de tudo
        if confidence == "none":
            return GuidanceRecord(
                finding_id=finding_id,
                cve=provider_result.cve,
                package_name=provider_result.package_name,
                installed_version=provider_result.installed_version,
                fixed_version=None,
                operating_system=operating_system,
                package_manager=package_manager,
                agent_id=provider_result.agent_id,
                agent_name=provider_result.agent_name,
                severity=provider_result.severity,
                status="insufficient_confidence",
                reason="Nível de confiança insuficiente para gerar comando.",
                recommendation="Consulte o canal oficial do fornecedor.",
                source=provider_result.source,
                confidence="none",
                warnings=list(provider_result.warnings),
                assumptions=list(provider_result.assumptions),
            )

        # 4. Verificar se fixed_version é igual à installed_version
        #    Não usar comparação lexicográfica genérica — apenas igualdade literal
        if (fixed_version is not None and
                fixed_version.strip() == provider_result.installed_version.strip()):
            return GuidanceRecord(
                finding_id=finding_id,
                cve=provider_result.cve,
                package_name=provider_result.package_name,
                installed_version=provider_result.installed_version,
                fixed_version=fixed_version,
                operating_system=operating_system,
                package_manager=package_manager,
                agent_id=provider_result.agent_id,
                agent_name=provider_result.agent_name,
                severity=provider_result.severity,
                status="no_guidance",
                reason="Versão instalada já corresponde à versão corrigida.",
                recommendation="Nenhuma ação necessária para este pacote.",
                source=provider_result.source,
                confidence=confidence,
                warnings=list(provider_result.warnings),
                assumptions=list(provider_result.assumptions),
            )

        # 5. Verificar elegibilidade para comando
        #    - confidence "low" sem fixed_version → sem comando
        #    - confidence "low" com fixed_version → ainda "low" → sem comando
        if confidence == "low":
            # Sem fixed_version confirmada → apenas textual
            return GuidanceRecord(
                finding_id=finding_id,
                cve=provider_result.cve,
                package_name=provider_result.package_name,
                installed_version=provider_result.installed_version,
                fixed_version=fixed_version,
                operating_system=operating_system,
                package_manager=package_manager,
                agent_id=provider_result.agent_id,
                agent_name=provider_result.agent_name,
                severity=provider_result.severity,
                status="no_guidance",
                reason="Nenhum provider confirmou fixed_version. "
                       + ("Política de atualização genérica desabilitada."
                          if not self._is_generic_update_allowed(operating_system, package_manager)
                          else ""),
                recommendation="Consulte o canal oficial do fornecedor para obter a versão corrigida.",
                source=provider_result.source,
                confidence="low",
                warnings=list(provider_result.warnings),
                assumptions=list(provider_result.assumptions),
            )

        # 6. Confidence "medium" ou "high" → tentar gerar comando
        generic_policy_enabled = False
        if fixed_version is None:
            # Sem fixed_version mas confidence >= medium → checar política genérica
            generic_policy_enabled = self._is_generic_update_allowed(
                operating_system, package_manager
            )
            if not generic_policy_enabled:
                return GuidanceRecord(
                    finding_id=finding_id,
                    cve=provider_result.cve,
                    package_name=provider_result.package_name,
                    installed_version=provider_result.installed_version,
                    fixed_version=None,
                    operating_system=operating_system,
                    package_manager=package_manager,
                    agent_id=provider_result.agent_id,
                    agent_name=provider_result.agent_name,
                    severity=provider_result.severity,
                    status="no_guidance",
                    reason="Nenhum provider confirmou fixed_version. Política de atualização genérica desabilitada.",
                    recommendation="Consulte o canal oficial do fornecedor para obter a versão corrigida.",
                    source=provider_result.source,
                    confidence=confidence,
                    warnings=list(provider_result.warnings),
                    assumptions=list(provider_result.assumptions),
                )

        # 7. Renderizar comando via TemplateRepository
        if not package_manager:
            return GuidanceRecord(
                finding_id=finding_id,
                cve=provider_result.cve,
                package_name=provider_result.package_name,
                installed_version=provider_result.installed_version,
                fixed_version=fixed_version,
                operating_system=operating_system,
                package_manager="",
                agent_id=provider_result.agent_id,
                agent_name=provider_result.agent_name,
                severity=provider_result.severity,
                status="no_guidance",
                reason="Gerenciador de pacotes não identificado para o sistema operacional.",
                recommendation="Consulte o canal oficial do fornecedor.",
                source=provider_result.source,
                confidence=confidence,
                warnings=list(provider_result.warnings),
                assumptions=list(provider_result.assumptions),
            )

        rendered = self._template_repo.render_command(
            package_manager=package_manager,
            package_name=provider_result.package_name,
            installed_version=provider_result.installed_version,
            fixed_version=fixed_version,
            generic_policy_enabled=generic_policy_enabled,
        )

        if rendered is None:
            # Template não disponível ou validação falhou → fail-closed
            return GuidanceRecord(
                finding_id=finding_id,
                cve=provider_result.cve,
                package_name=provider_result.package_name,
                installed_version=provider_result.installed_version,
                fixed_version=fixed_version,
                operating_system=operating_system,
                package_manager=package_manager,
                agent_id=provider_result.agent_id,
                agent_name=provider_result.agent_name,
                severity=provider_result.severity,
                status="no_guidance",
                reason="Template de remediação não disponível para a combinação OS/gerenciador.",
                recommendation="Consulte o canal oficial do fornecedor.",
                source=provider_result.source,
                confidence=confidence,
                warnings=list(provider_result.warnings),
                assumptions=list(provider_result.assumptions),
            )

        # 8. Sucesso: gerar GuidanceRecord com comando
        warnings = list(provider_result.warnings)
        if generic_policy_enabled and fixed_version is None:
            warnings.append(
                "Comando gerado via política genérica (sem fixed_version confirmada)."
            )
            confidence = "medium"

        return GuidanceRecord(
            finding_id=finding_id,
            cve=provider_result.cve,
            package_name=provider_result.package_name,
            installed_version=provider_result.installed_version,
            fixed_version=fixed_version,
            operating_system=operating_system,
            package_manager=package_manager,
            agent_id=provider_result.agent_id,
            agent_name=provider_result.agent_name,
            severity=provider_result.severity,
            status="success",
            command=rendered.remediation,
            verification_command=rendered.verification,
            source=provider_result.source,
            confidence=confidence,
            warnings=warnings,
            assumptions=list(provider_result.assumptions),
        )

    def _query_providers(self, finding_id: str) -> Optional[ProviderResult]:
        """Consulta providers em ordem de prioridade.

        Retorna o primeiro resultado com confidence >= "medium",
        ou o melhor resultado disponível (incluindo "low").
        """
        providers_cfg = self._providers_config.get("providers", [])
        if not isinstance(providers_cfg, list):
            providers_cfg = []

        # Ordenar por prioridade
        sorted_providers = sorted(
            [p for p in providers_cfg if isinstance(p, dict) and p.get("enabled", False)],
            key=lambda p: p.get("priority", 999),
        )

        best_result: Optional[ProviderResult] = None

        for pcfg in sorted_providers:
            name = pcfg.get("name", "")

            try:
                result = self._invoke_provider(name, finding_id)
            except Exception as e:
                logger.warning("Provider '%s' falhou: %s", name, str(e))
                continue

            if result is None:
                continue

            # Se confidence >= medium, retornar imediatamente
            if result.confidence in ("high", "medium"):
                return result

            # Guardar melhor resultado low/none como fallback
            if best_result is None:
                best_result = result
            elif _confidence_rank(result.confidence) > _confidence_rank(best_result.confidence):
                best_result = result

        return best_result

    def _invoke_provider(self, name: str, finding_id: str) -> Optional[ProviderResult]:
        """Invoca um provider pelo nome."""
        if name == "wazuh_snapshot":
            return self._wazuh_provider.query(finding_id)

        # Providers futuros retornam None (não implementados no MVP)
        logger.info("Provider '%s' não implementado no MVP.", name)
        return None


def _confidence_rank(confidence: str) -> int:
    """Retorna rank numérico para comparação de confidence."""
    return {"high": 4, "medium": 3, "low": 2, "none": 1}.get(confidence, 0)
