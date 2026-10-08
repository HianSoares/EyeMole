"""
Remediation Engine — orquestrador principal do módulo de Remediation Guidance.

Fluxo:
1. Validar finding_id
2. Fixar UMA revisão do snapshot (consulta, agrupamento e orientação usam a mesma)
3. Resolver a instância do achado (rejeitar IDs legados ambíguos)
4. Consultar providers (prioridade definida em config) e reconciliar as fontes
5. Validar semanticamente a versão alvo pelas regras do ecossistema
6. Decidir: comando validado (template), orientação textual ou nenhuma
7. Retornar GuidanceRecord com execution_allowed=False SEMPRE

Invariantes:
- execution_allowed é SEMPRE False (constante, sem override)
- Nenhum import de execução de processos
- Nenhum import de privilégio ou serviço de sistema
- Nenhuma chamada de rede
- Nenhuma escrita no snapshot
- Falha fechada: qualquer erro → sem comando
- Sem comparação lexicográfica de versões (comparadores por ecossistema)
- guidance_id é opaco (UUID4, sem CVE/agent/version em cleartext)
- Texto de orientação nunca é publicado no campo de comando
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .evidence import VendorEvidenceCatalog
from .models import GuidanceRecord, ProviderResult, RenderedCommand
from .providers.grype_provider import (
    DEFAULT_MAX_SCAN_AGE_HOURS,
    GrypeProvider,
    GrypeView,
    normalize_package_type,
)
from .providers.wazuh_provider import SnapshotView, WazuhProvider
from .snapshot import FileSignature, file_signature, revision_of
from .templates import TemplateRepository
from .validation import CVE_PATTERN, ParameterValidator
from .versioning import compare_versions, ecosystem_for_package_manager, parse_windows_build

logger = logging.getLogger("hmg-soar-remediation.engine")

# Caminhos padrão
_DEFAULT_CONFIG_DIR = Path("/opt/hmg-soar/config")
_DEFAULT_SNAPSHOT_PATH = Path("/var/www/wazuh-soar/data/latest.json")
MAX_GROUPED_PACKAGES = 10

# Tentativas de gerar uma orientação com todas as fontes estáveis. Se alguma
# fonte mudar a cada tentativa, a resposta é "indisponível" (falha fechada).
MAX_GENERATION_ATTEMPTS = 3

_NOT_FIXED_STATES = ("not-fixed", "wont-fix", "unknown")

_SOURCE_LABELS = {
    "wazuh_snapshot": "O Wazuh",
    "grype_snapshot": "O Grype",
    "fusion_consensus": "Wazuh e Grype",
}

_ECOSYSTEM_LABELS = {
    "dpkg": "regras dpkg (Debian/Ubuntu)",
    "rpm": "regras rpm (epoch:versão-release)",
    "windows": "build/UBR do Windows",
}


class SnapshotCache:
    """Cache em memória do snapshot com invalidação por assinatura do arquivo.

    A assinatura (mtime_ns, size, inode) é verificada em toda leitura: um
    arquivo substituído é recarregado imediatamente e um arquivo removido ou
    inválido não é servido. Mantido por compatibilidade; o motor usa a visão
    do WazuhProvider para manter consulta e agrupamento na mesma revisão.
    """

    def __init__(self, snapshot_path: Path, max_age_seconds: int = 300) -> None:
        self._path = snapshot_path
        self._max_age_seconds = max_age_seconds  # mantido por compatibilidade
        self._data: Optional[dict] = None
        self._sig: FileSignature = None

    def get_data(self) -> Optional[dict]:
        """Retorna dados da revisão atual do snapshot, recarregando se necessário."""
        sig = file_signature(self._path)
        if sig is None:
            if self._data is not None:
                logger.warning("Snapshot removido/inacessível; cache descartado.")
            self.invalidate()
            return None
        if self._data is not None and sig == self._sig:
            return self._data
        return self._reload(sig)

    def _reload(self, sig: FileSignature) -> Optional[dict]:
        """Recarrega o snapshot do disco."""
        self.invalidate()
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            logger.error("Erro ao carregar snapshot: %s", type(e).__name__)
            return None

        if not isinstance(data, dict):
            logger.error("Snapshot com formato inválido.")
            return None

        self._data = data
        self._sig = sig
        return self._data

    def invalidate(self) -> None:
        """Força recarga na próxima leitura."""
        self._data = None
        self._sig = None


def _confidence_rank(confidence: str) -> int:
    """Retorna rank numérico para comparação de confidence."""
    return {"high": 4, "medium": 3, "low": 2, "none": 1}.get(confidence, 0)


def _min_confidence(*levels: str) -> str:
    return min(levels, key=_confidence_rank)


def _max_confidence(*levels: str) -> str:
    return max(levels, key=_confidence_rank)


class RemediationEngine:
    """Orquestrador principal de geração de orientação de remediação.

    Invariantes:
    - execution_allowed é SEMPRE False
    - Fail-closed: qualquer exceção → sem comando
    - Versões comparadas apenas por regras do ecossistema
    - Não executa subprocess, os.system, eval, exec
    - guidance_id é opaco (UUID4)
    """

    def __init__(
        self,
        config_dir: Optional[Path] = None,
        snapshot_path: Optional[Path] = None,
        templates_path: Optional[Path] = None,
        grype_snapshot_path: Optional[Path] = None,
        evidence_path: Optional[Path] = None,
    ) -> None:
        self._config_dir = config_dir or _DEFAULT_CONFIG_DIR
        self._snapshot_path = snapshot_path or _DEFAULT_SNAPSHOT_PATH
        self._providers_config_path = self._config_dir / "remediation_providers.json"
        self._generic_policy_path = self._config_dir / "generic_update_policy.json"

        # Configuração recarregada por assinatura (sem reinício do serviço)
        self._providers_config_sig: FileSignature = file_signature(self._providers_config_path)
        self._providers_config = self._load_providers_config()
        self._generic_policy_sig: FileSignature = file_signature(self._generic_policy_path)
        self._generic_policy = self._load_generic_policy()

        # Instanciar TemplateRepository
        self._template_repo = TemplateRepository(templates_path=templates_path)

        # Instanciar WazuhProvider
        self._wazuh_provider = WazuhProvider(
            snapshot_path=self._snapshot_path,
            assets_context_path=self._config_dir / "assets_context.json",
            allowlist_path=self._config_dir / "remediation_allowlist.json",
        )

        # Instanciar GrypeProvider repassando o wazuh_provider (evita duplo I/O)
        self._grype_provider = GrypeProvider(
            wazuh_provider=self._wazuh_provider,
            grype_snapshot_path=grype_snapshot_path
            or self._config_dir.parent / "output" / "grype_latest.json",
            max_scan_age_hours=self._grype_max_age_hours(),
        )

        self._evidence = VendorEvidenceCatalog(evidence_path)

        # Snapshot cache legado (compatibilidade); não usado no agrupamento
        self._snapshot_cache = SnapshotCache(self._snapshot_path)

        # Revisões efetivamente usadas pela geração em curso: nome → (caminho, assinatura)
        self._generation_lock = threading.Lock()
        self._pins: Dict[str, Tuple[Path, FileSignature]] = {}
        self._grype_view: Optional[GrypeView] = None

    # ------------------------------------------------------------------
    # Configuração e dependências
    # ------------------------------------------------------------------

    def dependency_paths(self) -> List[Path]:
        """Arquivos dos quais uma orientação depende (para invalidar caches)."""
        return [
            self._snapshot_path,
            self._grype_provider.snapshot_path,
            *self._wazuh_provider.dependency_paths[1:],
            self._providers_config_path,
            self._generic_policy_path,
            self._template_repo.path,
            self._evidence.path,
        ]

    # ------------------------------------------------------------------
    # Consistência entre fontes durante a geração
    # ------------------------------------------------------------------

    def _pin(self, name: str, path: Path, signature: FileSignature) -> None:
        """Registra a revisão de uma fonte efetivamente lida nesta geração."""
        self._pins[name] = (path, signature)

    def _pin_static_sources(self) -> None:
        """Fixa configuração, templates e evidências no início da geração."""
        self._evidence.refresh()
        self._pin("providers_config", self._providers_config_path, self._providers_config_sig)
        self._pin("generic_policy", self._generic_policy_path, self._generic_policy_sig)
        self._pin("templates", self._template_repo.path, self._template_repo.loaded_signature)
        self._pin("evidence", self._evidence.path, self._evidence.loaded_signature)

    def _pin_wazuh(self, view: Optional[SnapshotView]) -> None:
        signature = view.signature if view is not None else file_signature(self._snapshot_path)
        self._pin("wazuh", self._snapshot_path, signature)
        loaded = self._wazuh_provider.loaded_signatures()
        paths = self._wazuh_provider.dependency_paths
        self._pin("assets_context", paths[1], loaded["assets_context"])
        self._pin("allowlist", paths[2], loaded["allowlist"])

    def _pins_are_current(self) -> bool:
        """True se nenhuma fonte usada mudou desde que foi lida."""
        return all(file_signature(path) == sig for path, sig in self._pins.values())

    def _pinned_revision(self) -> str:
        """Revisão opaca exata das fontes usadas (ordem estável por nome)."""
        if not self._pins:
            return ""
        return revision_of([self._pins[name][1] for name in sorted(self._pins)])

    def _refresh_config(self) -> None:
        sig = file_signature(self._providers_config_path)
        if sig != self._providers_config_sig:
            self._providers_config_sig = sig
            self._providers_config = self._load_providers_config()
        sig = file_signature(self._generic_policy_path)
        if sig != self._generic_policy_sig:
            self._generic_policy_sig = sig
            self._generic_policy = self._load_generic_policy()
        self._template_repo.refresh()

    def _grype_max_age_hours(self) -> int:
        for provider in self._providers_config.get("providers", []) or []:
            if isinstance(provider, dict) and provider.get("name") == "grype_snapshot":
                try:
                    value = int(provider.get("max_scan_age_hours", DEFAULT_MAX_SCAN_AGE_HOURS))
                    return value if value > 0 else DEFAULT_MAX_SCAN_AGE_HOURS
                except (TypeError, ValueError):
                    break
        return DEFAULT_MAX_SCAN_AGE_HOURS

    def _load_providers_config(self) -> dict:
        """Carrega configuração de providers."""
        config_path = self._providers_config_path
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
        policy_path = self._generic_policy_path
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

    # ------------------------------------------------------------------
    # Ponto de entrada
    # ------------------------------------------------------------------

    def generate_guidance(self, finding_id: str) -> GuidanceRecord:
        """Ponto de entrada principal. Gera orientação para um finding_id.

        Invariantes:
        - execution_allowed é SEMPRE False no resultado
        - Fail-closed: qualquer exceção → sem comando
        - Não compara versões lexicograficamente
        - O resultado corresponde a UM conjunto estável de revisões das fontes;
          se alguma mudar durante a geração, a orientação é regenerada
        """
        try:
            with self._generation_lock:
                return self._generate_consistent(finding_id)
        except Exception as e:
            # Fail-closed: qualquer exceção inesperada → sem comando
            logger.error("Erro inesperado na geração de guidance: %s", type(e).__name__)
            return GuidanceRecord(
                finding_id=finding_id,
                status="internal_error",
                reason="Erro interno na geração de orientação.",
                recommendation="Tente novamente mais tarde ou consulte o administrador.",
                confidence="none",
            )

    def _generate_consistent(self, finding_id: str) -> GuidanceRecord:
        """Gera e confirma que todas as fontes lidas continuam na mesma revisão.

        Consulta, agrupamento e orientação usam visões fixadas (Wazuh, Grype)
        e configurações carregadas uma vez por tentativa. Ao final, cada fonte
        lida é comparada com o disco: se qualquer uma mudou, o resultado pode
        misturar revisões (ou já estar superado) e é descartado. Após
        MAX_GENERATION_ATTEMPTS tentativas instáveis, nada é apresentado.
        """
        for attempt in range(1, MAX_GENERATION_ATTEMPTS + 1):
            self._pins = {}
            self._grype_view = None
            record = self._generate_guidance_internal(finding_id)
            if record.status == "validation_error":
                return record
            if self._pins_are_current():
                record.snapshot_revision = self._pinned_revision()
                return record
            logger.info(
                "Fontes alteradas durante a geração da orientação (tentativa %d/%d); regenerando.",
                attempt, MAX_GENERATION_ATTEMPTS,
            )

        logger.warning("Fontes instáveis durante a geração; orientação não apresentada.")
        return GuidanceRecord(
            finding_id=finding_id,
            status="provider_unavailable",
            reason="As fontes de dados mudaram durante a geração da orientação; "
                   "nenhum resultado parcial é apresentado.",
            recommendation="Tente novamente em instantes.",
            confidence="none",
        )

    def _generate_guidance_internal(self, finding_id: str) -> GuidanceRecord:
        """Uma tentativa de geração (sem try/except externo).

        snapshot_revision é preenchido por _generate_consistent com as revisões
        efetivamente lidas; aqui fica vazio.
        """
        # 1. Validar finding_id
        err = ParameterValidator.validate_finding_id(finding_id)
        if err is not None:
            return GuidanceRecord(
                finding_id=finding_id,
                status="validation_error",
                reason=err.message,
                confidence="none",
            )

        self._refresh_config()
        self._pin_static_sources()

        # 2. Fixar a revisão do snapshot para toda a requisição
        view = self._wazuh_provider.current_view()
        self._pin_wazuh(view)
        if view is None:
            return GuidanceRecord(
                finding_id=finding_id,
                status="provider_unavailable",
                reason="Snapshot de vulnerabilidades indisponível ou inválido; "
                       "nenhum dado anterior é apresentado como atual.",
                recommendation="Aguarde a próxima publicação do relatório.",
                confidence="none",
            )
        revision = ""  # definido ao final, a partir das revisões fixadas

        # 3. Resolver a instância
        lookup = self._wazuh_provider.lookup(finding_id, view)
        if lookup.status == "ambiguous":
            return GuidanceRecord(
                finding_id=finding_id,
                status="ambiguous_finding",
                reason=(
                    f"O identificador corresponde a {lookup.matches} instâncias distintas do pacote "
                    "(versões ou instalações diferentes). Nenhuma delas é escolhida automaticamente."
                ),
                recommendation=(
                    "Atualize o painel após a próxima coleta para usar o identificador por instância."
                    if lookup.legacy else
                    "Verifique o snapshot: há registros conflitantes para a mesma instância."
                ),
                confidence="none",
                snapshot_revision=revision,
            )
        if lookup.status != "found" or lookup.record is None:
            return GuidanceRecord(
                finding_id=finding_id,
                status="not_found",
                reason="Achado não encontrado no snapshot atual.",
                recommendation="Verifique se o finding_id é válido e se o snapshot está atualizado.",
                confidence="none",
                snapshot_revision=revision,
            )

        # 4. Consultar providers
        provider_result = self._query_providers(finding_id, view, lookup.record)
        if provider_result is None:
            return GuidanceRecord(
                finding_id=finding_id,
                status="not_found",
                reason="Achado não encontrado no snapshot atual.",
                recommendation="Verifique se o finding_id é válido e se o snapshot está atualizado.",
                confidence="none",
                snapshot_revision=revision,
            )
        if lookup.legacy:
            provider_result.assumptions.append(
                "Achado resolvido por identificador legado (sem versão); correspondência única nesta revisão."
            )

        return self._decide(finding_id, provider_result, view, revision)

    # ------------------------------------------------------------------
    # Decisão
    # ------------------------------------------------------------------

    def _record(self, finding_id: str, pr: ProviderResult, revision: str, **kwargs) -> GuidanceRecord:
        """Constrói o GuidanceRecord com o contexto propagado do provider."""
        warnings = list(pr.warnings) + list(kwargs.pop("extra_warnings", []))
        assumptions = list(pr.assumptions) + list(kwargs.pop("extra_assumptions", []))
        fields = dict(
            finding_id=finding_id,
            cve=pr.cve,
            package_name=pr.package_name,
            installed_version=pr.installed_version,
            fixed_version=pr.fixed_version,
            operating_system=pr.operating_system,
            package_manager=pr.package_manager,
            agent_id=pr.agent_id,
            agent_name=pr.agent_name,
            severity=pr.severity,
            os_version=pr.os_version,
            package_type=pr.package_type,
            architecture=pr.architecture,
            source=pr.source,
            confidence=pr.confidence,
            snapshot_revision=revision,
            warnings=warnings,
            assumptions=assumptions,
        )
        fields.update(kwargs)
        return GuidanceRecord(**fields)

    def _text_values(self, pr: ProviderResult) -> Dict[str, str]:
        """Valores pré-validados para textos/diagnósticos dos templates."""
        values: Dict[str, str] = {}
        if pr.cve and CVE_PATTERN.match(pr.cve):
            values["cve"] = pr.cve
        if pr.fixed_version and ParameterValidator.validate_version(pr.fixed_version) is None:
            values["fixed_version"] = pr.fixed_version
        if pr.installed_version and ParameterValidator.validate_version(pr.installed_version) is None:
            values["installed_version"] = pr.installed_version
        parsed = parse_windows_build(pr.fixed_version or "")
        if parsed is not None:
            values["fixed_build"] = str(parsed[2])
            values["fixed_ubr"] = str(parsed[3])
        return values

    def _textual_context(self, pr: ProviderResult) -> dict:
        """Orientação textual e diagnósticos de leitura (sem comando de instalação)."""
        pm = pr.package_manager
        context: dict = {}
        if pm and not self._template_repo.is_textual_only(pm):
            diagnostics = self._template_repo.render_diagnostics(pm, pr.package_name)
            if diagnostics:
                context["diagnostics"] = diagnostics
                context["shell"] = self._template_repo.shell_for(pm)
        if pr.fixed_version:
            context["guidance_text"] = (
                f"Atualize o pacote {pr.package_name} para a versão {pr.fixed_version} ou posterior "
                "pelo repositório oficial ou canal de atualização aprovado do sistema."
            )
        return context

    def _decide(
        self,
        finding_id: str,
        provider_result: ProviderResult,
        view: SnapshotView,
        revision: str,
    ) -> GuidanceRecord:
        pr = provider_result
        confidence = pr.confidence
        fixed_version = pr.fixed_version
        package_manager = pr.package_manager
        operating_system = pr.operating_system

        # Se confidence é "none" → sem comando independente de tudo
        if confidence == "none":
            ctx = self._textual_context(pr)
            if pr.status in _NOT_FIXED_STATES and pr.source in ("grype_snapshot", "fusion_consensus"):
                ctx["guidance_text"] = (
                    f"O scanner informa estado de correção '{pr.status}' para {pr.cve}: não há versão "
                    "corrigida confirmada. Acompanhe o advisory do fornecedor e avalie mitigações."
                )
            return self._record(
                finding_id, pr, revision,
                fixed_version=None,
                status="insufficient_confidence",
                reason="Nível de confiança insuficiente para gerar comando.",
                recommendation="Consulte o canal oficial do fornecedor.",
                rationale="As fontes não confirmam uma correção aplicável para esta instância.",
                confidence="none",
                **ctx,
            )

        # Divergência não resolvida entre fontes → bloqueia o comando específico
        if pr.blocking_reason:
            return self._record(
                finding_id, pr, revision,
                fixed_version=None,
                status="no_guidance",
                reason=pr.blocking_reason,
                rationale=pr.blocking_reason,
                recommendation="Confirme a versão corrigida aplicável no advisory oficial do fornecedor.",
                missing_context=["vendor_fix_evidence"],
                **self._textual_context(pr),
            )

        ecosystem = ecosystem_for_package_manager(package_manager)
        version_cmp: Optional[int] = None
        if fixed_version is not None:
            version_cmp = compare_versions(ecosystem, pr.installed_version, fixed_version)
            literal_equal = fixed_version.strip() == pr.installed_version.strip()

            # Versão instalada igual ou posterior → nenhuma ação
            if literal_equal or version_cmp == 0:
                return self._record(
                    finding_id, pr, revision,
                    status="no_guidance",
                    reason="Versão instalada já corresponde à versão corrigida.",
                    recommendation="Nenhuma ação necessária para este pacote.",
                    rationale="A versão instalada é igual à versão corrigida informada pelas fontes.",
                )
            if version_cmp is not None and version_cmp > 0:
                return self._record(
                    finding_id, pr, revision,
                    status="no_guidance",
                    reason=(
                        f"Versão instalada ({pr.installed_version}) é posterior à versão corrigida "
                        f"informada ({fixed_version}) segundo {_ECOSYSTEM_LABELS.get(ecosystem, ecosystem)}. "
                        "Nenhum comando gerado: downgrade não é autorizado."
                    ),
                    recommendation="Revalide o achado: pode estar desatualizado ou pertencer a outro ramo.",
                    rationale="Aplicar a versão informada seria um downgrade.",
                    extra_warnings=["Versão corrigida anterior à instalada; possível dado de outro ramo."],
                )

        # Windows: somente orientação textual + diagnósticos (nunca comando)
        if package_manager and self._template_repo.is_textual_only(package_manager):
            return self._windows_guidance(finding_id, pr, revision, version_cmp)

        # Confidence "low" → apenas textual
        if confidence == "low":
            return self._record(
                finding_id, pr, revision,
                status="no_guidance",
                reason="Nenhum provider confirmou fixed_version. "
                       + ("Política de atualização genérica desabilitada."
                          if not self._is_generic_update_allowed(operating_system, package_manager)
                          else ""),
                recommendation="Consulte o canal oficial do fornecedor para obter a versão corrigida.",
                rationale="A evidência disponível é de baixa confiança; nenhum comando é gerado.",
                confidence="low",
                **self._textual_context(pr),
            )

        # Confidence "medium" ou "high" → tentar gerar comando
        generic_policy_enabled = False
        if fixed_version is None:
            generic_policy_enabled = self._is_generic_update_allowed(
                operating_system, package_manager
            )
            if not generic_policy_enabled:
                return self._record(
                    finding_id, pr, revision,
                    fixed_version=None,
                    status="no_guidance",
                    reason="Nenhum provider confirmou fixed_version. Política de atualização genérica desabilitada.",
                    recommendation="Consulte o canal oficial do fornecedor para obter a versão corrigida.",
                    rationale="Sem versão corrigida confirmada não há comando validável.",
                    **self._textual_context(pr),
                )

        if not package_manager:
            return self._record(
                finding_id, pr, revision,
                package_manager="",
                status="no_guidance",
                reason="Gerenciador de pacotes não identificado para o sistema operacional.",
                recommendation="Consulte o canal oficial do fornecedor.",
                rationale="Sem gerenciador aprovado para o ecossistema do pacote não há template validado.",
                **self._textual_context(pr),
            )

        # Versão alvo precisa ser comprovadamente posterior (regras do ecossistema)
        if fixed_version is not None and version_cmp is None:
            return self._record(
                finding_id, pr, revision,
                status="no_guidance",
                reason=(
                    f"Não foi possível validar que {fixed_version} é posterior a {pr.installed_version} "
                    "pelas regras do ecossistema; nenhum comando com versão é gerado."
                ),
                recommendation="Confirme a versão corrigida aplicável no canal oficial do fornecedor.",
                rationale="Sem comparador confiável para este ecossistema/formato de versão.",
                **self._textual_context(pr),
            )

        package_names = [pr.package_name]
        related_package_count = 1
        if package_manager == "apt":
            package_names, related_package_count = self._find_related_apt_packages(pr, view)

        rendered = self._template_repo.render_command(
            package_manager=package_manager,
            package_name=pr.package_name,
            installed_version=pr.installed_version,
            fixed_version=fixed_version,
            generic_policy_enabled=generic_policy_enabled,
            package_names=package_names,
        )

        if rendered is None:
            # Template não disponível ou validação falhou → fail-closed
            return self._record(
                finding_id, pr, revision,
                status="no_guidance",
                reason="Template de remediação não disponível para a combinação OS/gerenciador.",
                recommendation="Consulte o canal oficial do fornecedor.",
                rationale="Nenhum template aprovado passou na validação de parâmetros.",
                **self._textual_context(pr),
            )

        return self._success(
            finding_id, pr, revision, rendered, package_names, related_package_count,
            generic_policy_enabled, ecosystem,
        )

    def _success(
        self,
        finding_id: str,
        pr: ProviderResult,
        revision: str,
        rendered: RenderedCommand,
        package_names: List[str],
        related_package_count: int,
        generic_policy_enabled: bool,
        ecosystem: Optional[str],
    ) -> GuidanceRecord:
        package_manager = pr.package_manager
        fixed_version = pr.fixed_version
        confidence = pr.confidence
        warnings: List[str] = []
        assumptions: List[str] = []
        if package_manager == "apt" and len(package_names) > 1:
            assumptions.append(
                "Comando agrupado com pacotes relacionados do mesmo CVE/agente para reduzir conflito de dependências co-versionadas."
            )
        if package_manager == "apt" and related_package_count > len(package_names):
            warnings.append(
                f"Encontrados {related_package_count} pacotes relacionados ao mesmo CVE/agente; "
                f"comando limitado aos primeiros {MAX_GROUPED_PACKAGES}. "
                "Revise manualmente os demais pacotes afetados antes de aplicar."
            )
        if generic_policy_enabled and fixed_version is None:
            warnings.append(
                "Comando gerado via política genérica (sem fixed_version confirmada)."
            )
            confidence = "medium"

        source_label = _SOURCE_LABELS.get(pr.source, "A fonte")
        if fixed_version:
            rationale = (
                f"{source_label} reporta {pr.package_name} {pr.installed_version} afetado por {pr.cve}, "
                f"corrigido em {fixed_version}. Pelas {_ECOSYSTEM_LABELS.get(ecosystem, ecosystem)}, "
                f"{pr.installed_version} é anterior a {fixed_version}; o template aprovado de "
                f"{package_manager} gera a atualização."
            )
            if package_manager == "apt":
                rationale += (
                    " O apt instala a Candidate do repositório (sem fixar versão): confirme pelo "
                    "diagnóstico que a Candidate corrige a CVE antes de aplicar."
                )
        else:
            rationale = (
                f"Política de atualização genérica aprovada para {pr.operating_system}/{package_manager}; "
                "não há versão corrigida confirmada, portanto o comando atualiza para a versão disponível."
            )

        values = self._text_values(pr)
        return self._record(
            finding_id, pr, revision,
            status="success",
            command=rendered.remediation,
            verification_command=rendered.verification,
            shell=self._template_repo.shell_for(package_manager),
            rationale=rationale,
            recommendation="Aplicar pelo processo de mudança aprovado; o EyeMole não executa comandos.",
            diagnostics=self._template_repo.render_diagnostics(
                package_manager, pr.package_name, package_names
            ),
            verification_steps=self._template_repo.render_profile_list(
                package_manager, "verification_steps", values
            ),
            expected_result=self._template_repo.render_profile_text(
                package_manager, "expected_result", values
            ),
            prerequisites=self._template_repo.render_profile_list(
                package_manager, "prerequisites", values
            ),
            confidence=confidence,
            extra_warnings=warnings,
            extra_assumptions=assumptions,
        )

    def _windows_guidance(
        self,
        finding_id: str,
        pr: ProviderResult,
        revision: str,
        version_cmp: Optional[int],
    ) -> GuidanceRecord:
        """Orientação textual para Windows: sem KB/URL/arquivo inventado no comando."""
        repo = self._template_repo
        values = self._text_values(pr)
        warnings: List[str] = []
        assumptions: List[str] = []
        prerequisites = repo.render_profile_list("windows", "prerequisites", values)
        diagnostics = repo.render_diagnostics("windows", pr.package_name)
        sources: List[Dict[str, str]] = []
        missing: List[str] = []
        reboot = "unknown"

        if not pr.architecture:
            missing.append("architecture")
        missing.extend(["approved_update_channel", "pending_reboot_state", "installed_updates_inventory"])

        update_needed = pr.fixed_version is not None and version_cmp is not None and version_cmp < 0
        installed = parse_windows_build(pr.installed_version)
        fixed = parse_windows_build(pr.fixed_version or "")

        if pr.fixed_version and version_cmp is None:
            warnings.append(
                "Build alvo informada não pertence ao mesmo ramo da build instalada (ou formato não "
                "reconhecido); a comparação de UBR não é aplicável."
            )

        guidance_key = "guidance.with_version" if update_needed else "guidance.generic"
        guidance_text = repo.render_profile_text("windows", guidance_key, values)

        evidence = self._evidence.find_windows(pr.cve, pr.package_name, pr.installed_version)
        evidence_sentence = ""
        if evidence:
            evidence_build = str(evidence.get("fixed_build") or "")
            for src in evidence.get("sources") or []:
                if isinstance(src, dict) and src.get("label"):
                    sources.append({
                        "label": str(src.get("label")),
                        "url": str(src.get("url") or ""),
                        "kind": str(src.get("kind") or "vendor_advisory"),
                    })
            prerequisites.extend(str(p) for p in evidence.get("prerequisites") or [])
            reboot = str(evidence.get("reboot_required") or "unknown")
            component = str(evidence.get("affected_component") or "")
            if evidence.get("applicability"):
                warnings.append(f"Aplicabilidade: {evidence['applicability']}")
            diag = evidence.get("component_diagnostic")
            if isinstance(diag, dict) and diag.get("script"):
                diagnostics.append({
                    "label": str(diag.get("label") or ""),
                    "script": str(diag.get("script")),
                    "shell": repo.shell_for("windows") or "",
                })
            if component:
                missing.append("affected_component_state")
            if pr.fixed_version and evidence_build and evidence_build != pr.fixed_version:
                warnings.append(
                    f"A evidência do fabricante indica build {evidence_build}, mas o scanner indica "
                    f"{pr.fixed_version}; confirme o ramo aplicável no advisory."
                )
            evidence_sentence = (
                f" Referência oficial verificada em {evidence.get('verified_at')}: "
                f"{evidence.get('kb')} ({evidence.get('release_type')}, {evidence.get('release_date')}) "
                f"leva o produto à build {evidence_build}"
                + (f" e corrige o componente {component}" if component else "")
                + f". {evidence.get('historical_note') or ''}"
            ).rstrip()
            if guidance_text:
                guidance_text += evidence_sentence
        else:
            sources.append({
                "label": f"Microsoft Security Update Guide — {pr.cve}",
                "url": "",
                "kind": "lookup_required",
            })
            missing.append("vendor_fix_evidence")

        if update_needed and installed and fixed:
            rationale = (
                f"O Wazuh reporta {pr.package_name} na build {pr.installed_version}, afetado por {pr.cve} "
                f"abaixo de {pr.fixed_version}. Mesmo ramo (build {installed[2]}): UBR instalado "
                f"{installed[3]} é anterior ao UBR corrigido {fixed[3]}. O Windows não recebe comando de "
                "instalação gerado: a atualização depende do canal aprovado, da edição, da arquitetura e "
                "de pré-requisitos, por isso a orientação é textual com diagnósticos de leitura."
            )
        else:
            rationale = (
                f"O snapshot não fornece uma build corrigida comparável para {pr.cve} neste produto; "
                "consulte o advisory oficial e use os diagnósticos para confirmar build, UBR e aplicabilidade."
            )
        rationale += evidence_sentence

        # Confiança: limiar de versão do scanner sem evidência do fabricante → no máximo "medium"
        confidence = pr.confidence if evidence else _min_confidence(pr.confidence, "medium")
        assumptions.append(
            "A confiança refere-se à evidência técnica do limiar de build, não à escolha de um KB específico."
        )

        return self._record(
            finding_id, pr, revision,
            status="textual_guidance" if update_needed else "no_guidance",
            reason=(
                "Orientação textual: o Windows não recebe comando de instalação gerado automaticamente."
                if update_needed else
                "Não há build corrigida comparável para gerar orientação específica."
            ),
            recommendation=(
                "Aplicar a atualização aplicável pelo canal aprovado e validar com os diagnósticos."
            ),
            guidance_text=guidance_text,
            rationale=rationale,
            shell=repo.shell_for("windows"),
            diagnostics=diagnostics,
            verification_steps=repo.render_profile_list("windows", "verification_steps", values),
            expected_result=repo.render_profile_text("windows", "expected_result", values),
            prerequisites=prerequisites,
            missing_context=missing,
            sources=sources,
            reboot_required=reboot,
            confidence=confidence,
            extra_warnings=warnings,
            extra_assumptions=assumptions,
        )

    def _find_related_apt_packages(
        self, provider_result: ProviderResult, view: SnapshotView
    ) -> Tuple[List[str], int]:
        """Encontra pacotes apt relacionados ao mesmo CVE/agente NA MESMA revisão."""
        package_names = [provider_result.package_name]
        seen = {provider_result.package_name}

        for vuln in view.vulnerabilities:
            if str(vuln.get("cve", "")).strip() != provider_result.cve:
                continue
            if str(vuln.get("agent_id", "")).strip() != provider_result.agent_id:
                continue

            related_name = str(vuln.get("package", "")).strip()
            if not related_name or related_name in seen:
                continue
            if ParameterValidator.validate_package_name(related_name) is not None:
                continue

            snapshot_os = vuln.get("operating_system")
            related_os = self._wazuh_provider._resolve_os(
                provider_result.agent_id,
                str(vuln.get("agent_name", "")).strip(),
                snapshot_os,
            )
            package_type = str(vuln.get("package_type", "")).strip().lower()
            related_pm = self._wazuh_provider._resolve_package_manager(
                operating_system=related_os,
                package_type=package_type,
            )
            if related_pm != "apt":
                continue

            package_names.append(related_name)
            seen.add(related_name)

        return package_names[:MAX_GROUPED_PACKAGES], len(package_names)

    # ------------------------------------------------------------------
    # Providers e fusão
    # ------------------------------------------------------------------

    def _query_providers(
        self,
        finding_id: str,
        view: Optional[SnapshotView] = None,
        wazuh_record: Optional[dict] = None,
    ) -> Optional[ProviderResult]:
        """Consulta providers habilitados e realiza a fusão/consenso das fontes."""
        providers_cfg = self._providers_config.get("providers", [])
        if not isinstance(providers_cfg, list):
            providers_cfg = []

        enabled_names = [p.get("name") for p in providers_cfg if isinstance(p, dict) and p.get("enabled", False)]

        wazuh_enabled = "wazuh_snapshot" in enabled_names
        grype_enabled = "grype_snapshot" in enabled_names

        if wazuh_record is None:
            wazuh_record = self._wazuh_provider.resolve_finding(finding_id, view)

        wazuh_res = None
        if wazuh_enabled:
            try:
                wazuh_res = self._wazuh_provider.query(finding_id, view=view)
            except Exception as e:
                logger.warning("Wazuh provider falhou: %s", type(e).__name__)

        grype_res = None
        if grype_enabled and wazuh_record is not None:
            try:
                # Visão do Grype fixada para correlação E ramos de correção
                grype_view = self._grype_provider.current_view()
                self._grype_view = grype_view
                self._pin(
                    "grype",
                    self._grype_provider.snapshot_path,
                    grype_view.signature if grype_view is not None
                    else file_signature(self._grype_provider.snapshot_path),
                )
                grype_res = self._grype_provider.query_record(wazuh_record, view=grype_view)
            except Exception as e:
                logger.warning("Grype provider falhou: %s", type(e).__name__)

        # Cenário 1: Fusão dos dois resultados se ambos estiverem disponíveis
        if wazuh_res and grype_res:
            return self._fuse_results(wazuh_res, grype_res, wazuh_record)

        # Cenário 2: Apenas Wazuh disponível
        if wazuh_res:
            if grype_enabled:
                # Confiança degradada por falta de consenso positivo com o Grype
                new_confidence = "medium" if wazuh_res.confidence == "high" else wazuh_res.confidence
                wazuh_res.confidence = new_confidence
                wazuh_res.warnings.append("Vulnerabilidade não confirmada pelo scanner Grype (achado único Wazuh).")
            return wazuh_res

        # Cenário 3: Apenas Grype disponível
        if grype_res:
            if wazuh_record:
                agent_name = str(wazuh_record.get("agent_name") or "")
                snapshot_os = wazuh_record.get("operating_system")
                operating_system = self._wazuh_provider._resolve_os(grype_res.agent_id, agent_name, snapshot_os)
                # package.type do snapshot (ou do PURL do Grype) decide o gerenciador:
                # um pacote npm NUNCA recebe apt só porque o host é Ubuntu.
                package_type = (
                    str(wazuh_record.get("package_type") or "").strip().lower()
                    or grype_res.package_type
                )
                package_manager = self._wazuh_provider._resolve_package_manager(
                    operating_system, package_type
                )

                grype_res.operating_system = operating_system
                grype_res.package_manager = package_manager
                grype_res.package_type = package_type
                grype_res.agent_name = agent_name
                grype_res.severity = str(wazuh_record.get("severity") or "")
                grype_res.os_version = str(wazuh_record.get("os_version") or "")
                grype_res.architecture = str(wazuh_record.get("package_architecture") or "")
                if package_type and not package_manager:
                    grype_res.warnings.append(
                        f"package.type '{package_type}' não está aprovado na allowlist de remediação"
                    )

            self._apply_fix_state_veto(grype_res)
            # Correspondência de baixa confiança nunca vira alta por ter fixed_version
            if grype_res.fixed_version is None and grype_res.confidence != "none":
                grype_res.confidence = _min_confidence(grype_res.confidence, "medium")

            if wazuh_enabled:
                new_confidence = "medium" if grype_res.confidence == "high" else grype_res.confidence
                grype_res.confidence = new_confidence
                grype_res.warnings.append("Vulnerabilidade não confirmada pelo Wazuh (achado único Grype).")
            return grype_res

        return None

    @staticmethod
    def _apply_fix_state_veto(result: ProviderResult) -> None:
        """Veta a correção quando o scanner informa estado sem correção aplicável."""
        if result.status in _NOT_FIXED_STATES:
            result.warnings.append(
                f"Scanner Grype reportou status '{result.status}' para esta vulnerabilidade. "
                "Comando de remediação desabilitado."
            )
            result.fixed_version = None
            result.fix_confidence = "none"
            result.confidence = "none"

    def _fuse_results(
        self,
        wazuh_res: ProviderResult,
        grype_res: ProviderResult,
        wazuh_record: Optional[dict] = None,
    ) -> ProviderResult:
        """Fusão Wazuh + Grype separando confirmação da vulnerabilidade e da correção."""
        warnings = list(wazuh_res.warnings) + list(grype_res.warnings)
        assumptions = list(wazuh_res.assumptions)

        def result(fixed_version, confidence, status, blocking_reason=None, fix_confidence="none"):
            return ProviderResult(
                cve=wazuh_res.cve,
                package_name=wazuh_res.package_name,
                installed_version=wazuh_res.installed_version,
                fixed_version=fixed_version,
                operating_system=wazuh_res.operating_system,
                package_manager=wazuh_res.package_manager,
                agent_id=wazuh_res.agent_id,
                agent_name=wazuh_res.agent_name,
                severity=wazuh_res.severity,
                confidence=confidence,
                source="fusion_consensus",
                warnings=warnings,
                assumptions=assumptions,
                status=status,
                package_type=wazuh_res.package_type,
                os_version=wazuh_res.os_version,
                architecture=wazuh_res.architecture,
                purl=grype_res.purl,
                fix_confidence=fix_confidence,
                blocking_reason=blocking_reason,
            )

        # Regra Crítica: Estado do fix não-fixed (Fail-Closed)
        if grype_res.status in _NOT_FIXED_STATES:
            warnings.append(
                f"Scanner Grype reportou status '{grype_res.status}' para esta vulnerabilidade. "
                "Comando de remediação desabilitado."
            )
            return result(None, "none", grype_res.status)

        # Mesmo produto? Ecossistemas declarados precisam coincidir.
        w_type = normalize_package_type(wazuh_res.package_type)
        g_type = normalize_package_type(grype_res.package_type)
        if w_type and g_type and w_type != g_type:
            reason = (
                f"Wazuh classifica o pacote como '{w_type}' e o Grype como '{g_type}'; as fontes "
                "podem descrever produtos diferentes. Nenhum comando é gerado."
            )
            warnings.append(reason)
            return result(None, "low", "unknown", blocking_reason=reason)

        grype_match = grype_res.confidence
        vuln_confirmed = grype_match in ("high", "medium")
        if not vuln_confirmed:
            warnings.append(
                f"Correspondência Grype de confiança '{grype_match}' não confirma a vulnerabilidade de forma independente."
            )
        else:
            assumptions.append("Vulnerabilidade confirmada por Wazuh e Grype para a mesma instância.")

        ecosystem = ecosystem_for_package_manager(wazuh_res.package_manager)
        w_fix = wazuh_res.fixed_version
        g_fix = grype_res.fixed_version

        if w_fix and g_fix:
            cmp = compare_versions(ecosystem, w_fix, g_fix)
            if w_fix == g_fix or cmp == 0:
                assumptions.append("Wazuh e Grype concordam sobre a versão corrigida.")
                fix_conf = _max_confidence(wazuh_res.fix_confidence, grype_res.fix_confidence)
                return result(w_fix, fix_conf, "fixed", fix_confidence=fix_conf)

            grype_branches = ()
            if wazuh_record is not None:
                grype_branches = self._grype_provider.fixed_versions_for(
                    wazuh_record, view=self._grype_view
                )
            if w_fix in grype_branches:
                assumptions.append(
                    f"Grype lista correções em múltiplos ramos ({', '.join(grype_branches)}); "
                    f"o ramo do Wazuh ({w_fix}) consta na lista."
                )
                fix_conf = wazuh_res.fix_confidence
                if not vuln_confirmed:
                    fix_conf = _min_confidence(fix_conf, "medium")
                return result(w_fix, fix_conf, "fixed", fix_confidence=fix_conf)

            reason = (
                f"As fontes divergem sobre a versão corrigida: Wazuh indica {w_fix}; Grype indica {g_fix} "
                f"(correspondência '{grype_match}'). A diferença pode refletir ramos distintos; sem "
                "evidência do fabricante para reconciliá-la, nenhum comando é gerado."
            )
            warnings.append(reason)
            return result(None, "low", "unknown", blocking_reason=reason)

        if w_fix:
            fix_conf = wazuh_res.fix_confidence
            if not vuln_confirmed:
                fix_conf = _min_confidence(fix_conf, "medium")
            assumptions.append("Versão corrigida informada apenas pelo Wazuh.")
            return result(w_fix, fix_conf, "fixed", fix_confidence=fix_conf)

        if g_fix:
            warnings.append("fixed_version resolvida com sucesso através do scanner Grype.")
            # A confiança da correção é a do match Grype: cpe-match (low) permanece low.
            fix_conf = grype_res.fix_confidence
            return result(g_fix, fix_conf, "fixed", fix_confidence=fix_conf)

        # Ambos concordam sobre a falha, mas não há versão para remediar
        return result(None, "medium", "unknown")

    def _invoke_provider(self, name: str, finding_id: str) -> Optional[ProviderResult]:
        """Invoca um provider pelo nome."""
        if name == "wazuh_snapshot":
            return self._wazuh_provider.query(finding_id)
        elif name == "grype_snapshot":
            return self._grype_provider.query(finding_id)

        # Providers futuros retornam None (não implementados no MVP)
        logger.info("Provider '%s' não implementado no MVP.", name)
        return None
