"""
Wazuh Provider para o módulo de Remediation Guidance.

Lê dados EXCLUSIVAMENTE do snapshot publicado (latest.json) gerado pelo
Analyser. Não modifica o snapshot, não faz chamadas de rede, não executa
processos.

Invariantes:
- Somente leitura do snapshot existente
- Não aceita substituição de campos pelo chamador
- Não altera snapshot ou analyserV1.py
- Não inventa fixed_version
- Não infere package_manager sem regra explícita
- Retorna ausência segura quando dados insuficientes
- Nenhum subprocess, os.system, eval, exec, shell=True
- Nenhuma chamada de rede
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import (
    ProviderResult,
    finding_id_for_snapshot_record,
    generate_vulnerability_key,
    legacy_key_for_snapshot_record,
)
from ..scanner_condition import parse_scanner_condition
from ..snapshot import FileSignature, file_signature, revision_of
from ..validation import ParameterValidator

logger = logging.getLogger("hmg-soar-remediation.wazuh_provider")


def _generate_vulnerability_key(
    cve: str, agent_id: str, package: str, severity: str
) -> str:
    """Wrapper privado para manter retrocompatibilidade com chamadas internas."""
    return generate_vulnerability_key(cve, agent_id, package, severity)


def _record_fingerprint(record: dict) -> str:
    return json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)


def _unique_records(records: List[dict]) -> Tuple[dict, ...]:
    """Remove linhas idênticas (mesma instância repetida) preservando a ordem."""
    seen = set()
    unique = []
    for record in records:
        fp = _record_fingerprint(record)
        if fp in seen:
            continue
        seen.add(fp)
        unique.append(record)
    return tuple(unique)


@dataclass(frozen=True)
class SnapshotView:
    """Visão imutável de UMA revisão do snapshot.

    Consulta, agrupamento de pacotes e orientação de uma mesma requisição
    usam a mesma visão, mesmo que o arquivo seja substituído no meio dela.
    """

    signature: Tuple[int, int, int]
    revision: str
    vulnerabilities: Tuple[dict, ...]
    by_instance: Dict[str, Tuple[dict, ...]]
    by_legacy: Dict[str, Tuple[dict, ...]]


@dataclass(frozen=True)
class FindingLookup:
    """Resultado da resolução de um finding_id numa revisão do snapshot."""

    status: str  # found | not_found | ambiguous | unavailable
    record: Optional[dict] = None
    matches: int = 0
    legacy: bool = False


class WazuhProvider:
    """Provider que lê dados do snapshot de vulnerabilidades publicado.

    O estado normal do MVP é: orientação textual disponível,
    fixed_version ausente (campo é N/D nos dados atuais), command ausente.
    Isso NÃO é um erro — é o comportamento esperado.

    A cada consulta a assinatura do arquivo (mtime_ns, size, inode) é
    verificada. Arquivo substituído é recarregado; arquivo removido ou
    inválido descarta os dados anteriores (nunca serve dados antigos como
    atuais).
    """

    def __init__(
        self,
        snapshot_path: Optional[Path] = None,
        assets_context_path: Optional[Path] = None,
        allowlist_path: Optional[Path] = None,
    ) -> None:
        self._snapshot_path = snapshot_path or Path(
            "/var/www/wazuh-soar/data/latest.json"
        )
        self._assets_context_path = assets_context_path or Path(
            "/opt/hmg-soar/config/assets_context.json"
        )
        self._allowlist_path = allowlist_path or Path(
            "/opt/hmg-soar/config/remediation_allowlist.json"
        )
        self._lock = threading.Lock()
        self._allowlist_sig: FileSignature = file_signature(self._allowlist_path)
        self._allowlist = self._load_remediation_allowlist()
        self._view: Optional[SnapshotView] = None
        self._assets_context: dict = {}
        self._assets_context_sig: FileSignature = None
        self._assets_context_loaded = False

    @property
    def name(self) -> str:
        return "wazuh_snapshot"

    @property
    def dependency_paths(self) -> List[Path]:
        return [self._snapshot_path, self._assets_context_path, self._allowlist_path]

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def current_view(self) -> Optional[SnapshotView]:
        """Retorna a visão da revisão ATUAL do snapshot (recarrega se mudou).

        Retorna None — e descarta a visão anterior — quando o arquivo não
        existe, não pode ser lido ou tem formato inválido.
        """
        with self._lock:
            # Contexto de ativos e allowlist são reavaliados UMA vez por
            # requisição (aqui), e não a cada _resolve_os: todas as linhas de
            # uma orientação usam a mesma revisão dessas fontes.
            self._refresh_allowlist()
            self._refresh_assets_context()
            sig = file_signature(self._snapshot_path)
            if sig is None:
                if self._view is not None:
                    logger.warning("Snapshot removido/inacessível; dados anteriores descartados.")
                else:
                    logger.warning("Snapshot não encontrado: %s", self._snapshot_path)
                self._view = None
                return None

            if self._view is not None and self._view.signature == sig:
                return self._view

            # Troca atômica: a visão anterior só é substituída por uma visão
            # completa; em falha, nenhum dado antigo permanece servível.
            self._view = self._build_view(sig)
            return self._view

    def _build_view(self, sig: Tuple[int, int, int]) -> Optional[SnapshotView]:
        try:
            with open(self._snapshot_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            logger.error("Erro ao carregar snapshot: %s", type(e).__name__)
            return None

        if not isinstance(data, dict):
            logger.error("Snapshot com formato inválido (esperado dict).")
            return None

        vulnerabilities = data.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            logger.error("Campo 'vulnerabilities' ausente ou inválido no snapshot.")
            return None

        # O conteúdo lido precisa pertencer à revisão cujo stat foi observado.
        if file_signature(self._snapshot_path) != sig:
            logger.warning("Snapshot alterado durante a leitura; será recarregado na próxima consulta.")
            return None

        by_instance: Dict[str, List[dict]] = {}
        by_legacy: Dict[str, List[dict]] = {}
        valid: List[dict] = []
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            cve = str(vuln.get("cve", ""))
            agent_id = str(vuln.get("agent_id", ""))
            package = str(vuln.get("package", ""))
            if not cve or not agent_id or not package:
                continue
            valid.append(vuln)
            by_instance.setdefault(finding_id_for_snapshot_record(vuln), []).append(vuln)
            by_legacy.setdefault(legacy_key_for_snapshot_record(vuln), []).append(vuln)

        view = SnapshotView(
            signature=sig,
            revision=revision_of([sig]),
            vulnerabilities=tuple(valid),
            by_instance={k: _unique_records(v) for k, v in by_instance.items()},
            by_legacy={k: _unique_records(v) for k, v in by_legacy.items()},
        )
        logger.info(
            "Snapshot carregado: %d vulnerabilidades indexadas (revisão %s)",
            len(view.by_instance), view.revision,
        )
        return view

    def load_snapshot(self) -> bool:
        """Carrega (ou recarrega se a assinatura mudou) o snapshot publicado.

        Retorna True se a revisão atual foi carregada com sucesso.
        """
        return self.current_view() is not None

    def loaded_signatures(self) -> Dict[str, object]:
        """Assinaturas das fontes auxiliares efetivamente carregadas."""
        return {
            "assets_context": self._assets_context_sig,
            "allowlist": self._allowlist_sig,
        }

    @property
    def snapshot_revision(self) -> str:
        view = self._view
        return view.revision if view is not None else ""

    def lookup(self, finding_id: str, view: Optional[SnapshotView] = None) -> FindingLookup:
        """Resolve finding_id na revisão informada (ou atual).

        Ordem: identidade de instância (v2); depois chave legada. Uma chave
        legada que corresponde a mais de uma instância é rejeitada como
        ambígua — nunca escolhe silenciosamente um dos registros.
        """
        if view is None:
            view = self.current_view()
        if view is None:
            return FindingLookup(status="unavailable")

        matches = view.by_instance.get(finding_id)
        if matches:
            if len(matches) == 1:
                return FindingLookup(status="found", record=matches[0], matches=1)
            return FindingLookup(status="ambiguous", matches=len(matches))

        legacy_matches = view.by_legacy.get(finding_id)
        if legacy_matches:
            if len(legacy_matches) == 1:
                return FindingLookup(
                    status="found", record=legacy_matches[0], matches=1, legacy=True
                )
            return FindingLookup(status="ambiguous", matches=len(legacy_matches), legacy=True)

        return FindingLookup(status="not_found")

    def load_assets_context(self) -> bool:
        """Carrega o contexto de ativos para resolução de OS."""
        self._assets_context_sig = file_signature(self._assets_context_path)
        self._assets_context_loaded = True
        try:
            if not self._assets_context_path.is_file():
                logger.info("Arquivo de assets_context não encontrado (opcional).")
                self._assets_context = {}
                return True  # Não é erro crítico

            with open(self._assets_context_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                self._assets_context = data
                return True
            else:
                self._assets_context = {}
                return True

        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Erro ao carregar assets_context: %s", str(e))
            self._assets_context = {}
            return True  # Degradação graciosa

    def _refresh_assets_context(self) -> None:
        """Recarrega o contexto de ativos quando sua assinatura muda."""
        if (not self._assets_context_loaded
                or file_signature(self._assets_context_path) != self._assets_context_sig):
            self.load_assets_context()

    def _refresh_allowlist(self) -> None:
        sig = file_signature(self._allowlist_path)
        if sig != self._allowlist_sig:
            self._allowlist_sig = sig
            self._allowlist = self._load_remediation_allowlist()

    def resolve_finding(self, finding_id: str, view: Optional[SnapshotView] = None) -> Optional[dict]:
        """Resolve finding_id para o registro de vulnerabilidade no snapshot.

        Retorna None se não encontrado ou ambíguo (NÃO é erro interno).
        """
        result = self.lookup(finding_id, view)
        return result.record if result.status == "found" else None

    def query(self, finding_id: str, view: Optional[SnapshotView] = None) -> Optional[ProviderResult]:
        """Consulta dados de orientação para um finding_id.

        NÃO aceita substituição de campos pelo chamador.
        Resolve TODOS os dados internamente a partir do snapshot.

        Retorna None se o achado não existir, for ambíguo ou os dados forem
        insuficientes.
        """
        vuln_record = self.resolve_finding(finding_id, view)
        if vuln_record is None:
            return None
        return self.result_from_record(vuln_record)

    def result_from_record(self, vuln_record: dict) -> Optional[ProviderResult]:
        """Constrói o ProviderResult a partir de um registro já resolvido."""
        # Extrair campos do registro (não aceita substituição)
        cve = str(vuln_record.get("cve", "")).strip()
        package_name = str(vuln_record.get("package", "")).strip()
        installed_version = str(vuln_record.get("version", "")).strip()
        package_type = str(vuln_record.get("package_type", "")).strip().lower()
        agent_id = str(vuln_record.get("agent_id", "")).strip()
        agent_name = str(vuln_record.get("agent_name", "")).strip()
        severity = str(vuln_record.get("severity", "")).strip()
        os_version = str(vuln_record.get("os_version") or "").strip()
        architecture = str(vuln_record.get("package_architecture") or "").strip()

        # Validar campos mínimos necessários
        if not cve or not package_name or not agent_id:
            return None

        # Resolver fixed_version — APENAS quando campo real, verificável e não-N/D existe
        raw_fixed = vuln_record.get("fixed_version")
        fixed_version: Optional[str] = None
        confidence = "low"
        fix_from_condition = False

        if raw_fixed is not None:
            fixed_str = str(raw_fixed).strip()
            # Somente aceitar se for um valor real, não "N/D", não vazio
            if fixed_str and fixed_str.upper() not in ("N/D", "N/A", "", "NONE", "NULL"):
                # Validar que o valor é seguro
                err = ParameterValidator.validate_version(fixed_str)
                if err is None:
                    fixed_version = fixed_str
                    confidence = "high"

        parsed_condition = None
        if fixed_version is None:
            parsed_condition = parse_scanner_condition(
                str(vuln_record.get("scanner_condition") or "")
            )
            if parsed_condition.fixed_version:
                err = ParameterValidator.validate_version(parsed_condition.fixed_version)
                if err is None:
                    fixed_version = parsed_condition.fixed_version
                    confidence = parsed_condition.confidence
                    fix_from_condition = True
                else:
                    logger.warning(
                        "scanner.condition gerou fixed_version inválida para %s/%s/%s: %r",
                        cve,
                        agent_id,
                        package_name,
                        parsed_condition.fixed_version,
                    )

        # Resolver OS a partir do snapshot ou assets_context (não inventar)
        snapshot_os = vuln_record.get("operating_system")
        operating_system = self._resolve_os(agent_id, agent_name, snapshot_os)

        # Resolver package_manager preferindo package.type.
        # Se package.type existe e não está aprovado, falha fechada.
        package_manager = self._resolve_package_manager(
            operating_system=operating_system,
            package_type=package_type,
        )

        # Construir resultado
        warnings = []
        assumptions = []

        if not fixed_version:
            warnings.append("Campo fixed_version ausente no snapshot Wazuh")
        elif fix_from_condition:
            warnings.append("fixed_version extraída de vulnerability.scanner.condition")

        if operating_system == "unknown":
            warnings.append("Sistema operacional não identificado para o agente")
            assumptions.append("OS inferido como unknown — template pode não estar disponível")

        if package_type and not package_manager:
            warnings.append(
                f"package.type '{package_type}' não está aprovado na allowlist de remediação"
            )
        elif not package_type:
            assumptions.append("package.type ausente; fallback temporário por OS aplicado")

        if not package_manager:
            warnings.append("Gerenciador de pacotes não identificado para o pacote")
            package_manager = ""

        return ProviderResult(
            cve=cve,
            package_name=package_name,
            installed_version=installed_version,
            fixed_version=fixed_version,
            operating_system=operating_system,
            package_manager=package_manager,
            agent_id=agent_id,
            agent_name=agent_name,
            severity=severity,
            confidence=confidence,
            source=self.name,
            warnings=warnings,
            assumptions=assumptions,
            status="fixed" if fixed_version else "unknown",
            package_type=package_type,
            os_version=os_version,
            architecture=architecture,
            fix_confidence=confidence if fixed_version else "none",
        )

    def _resolve_os(self, agent_id: str, agent_name: str, snapshot_os: Optional[str] = None) -> str:
        """Resolve o sistema operacional a partir do snapshot ou assets_context.

        Não infere sem regra explícita. Retorna "unknown" se não encontrar.
        """
        if snapshot_os:
            os_lower = str(snapshot_os).lower().strip()
            if os_lower and os_lower not in ("n/a", "unknown", "none", "null", ""):
                if os_lower in _OS_TO_PACKAGE_MANAGER:
                    return os_lower
                for known_os in _OS_TO_PACKAGE_MANAGER:
                    if known_os in os_lower:
                        return known_os

        if not self._assets_context_loaded:
            self.load_assets_context()

        agents_map = self._assets_context.get("agents", {})

        # Busca por agent_id
        agent_data = agents_map.get(agent_id)
        if not agent_data and agent_name:
            agent_data = agents_map.get(agent_name)

        if agent_data and isinstance(agent_data, dict):
            # Tentar campo asset_type como hint de OS
            asset_type = str(agent_data.get("asset_type", "")).lower().strip()
            # Tentar campo hostname ou outros para inferir
            # Mas NÃO inventar — apenas retornar se explicitamente mapeável
            os_hint = agent_data.get("operating_system", "")
            if os_hint:
                return str(os_hint).lower().strip()

            # Usar asset_type apenas se for um OS reconhecível
            if asset_type in _ASSET_TYPE_TO_OS:
                return _ASSET_TYPE_TO_OS[asset_type]

        return "unknown"

    def _resolve_package_manager(self, operating_system: str, package_type: str = "") -> str:
        """Resolve package manager por package.type e fallback legado por OS.

        Retorna string vazia se não houver mapeamento (fail-safe).
        """
        os_lower = operating_system.lower().strip()
        type_lower = package_type.lower().strip()

        if type_lower:
            direct_rules = self._allowlist.get("package_type_to_package_manager", {})
            if type_lower in direct_rules:
                return str(direct_rules[type_lower]).strip()

            typed_os_rules = self._allowlist.get("package_type_os_to_package_manager", {})
            os_rules = typed_os_rules.get(type_lower, {})
            if isinstance(os_rules, dict):
                return str(os_rules.get(os_lower, "")).strip()

            return ""

        # Fallback legado/transicional: somente para snapshots antigos sem package.type.
        os_rules = self._allowlist.get("os_to_package_manager", {})
        if isinstance(os_rules, dict):
            return str(os_rules.get(os_lower, "")).strip()
        return _OS_TO_PACKAGE_MANAGER.get(os_lower, "")

    def _load_remediation_allowlist(self) -> dict:
        """Carrega allowlist local de remediação com defaults fail-closed."""
        defaults = {
            "os_to_package_manager": dict(_OS_TO_PACKAGE_MANAGER),
            "package_type_to_package_manager": {
                "deb": "apt",
                "windows": "windows",
            },
            "package_type_os_to_package_manager": {
                "rpm": {
                    "rocky": "dnf",
                },
            },
        }

        try:
            if not self._allowlist_path.is_file():
                logger.warning("Allowlist de remediação não encontrada: %s", self._allowlist_path)
                return defaults

            with open(self._allowlist_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                logger.warning("Allowlist de remediação com formato inválido; usando defaults.")
                return defaults

            merged = dict(defaults)
            for key in (
                "os_to_package_manager",
                "package_type_to_package_manager",
                "package_type_os_to_package_manager",
            ):
                value = data.get(key)
                if isinstance(value, dict):
                    merged[key] = value

            return merged

        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Erro ao carregar allowlist de remediação: %s", str(e))
            return defaults


# Mapeamento explícito de OS → package manager
# Apenas regras comprovadas e documentadas
_OS_TO_PACKAGE_MANAGER: Dict[str, str] = {
    "windows": "windows",
    "ubuntu": "apt",
    "debian": "apt",
    "raspbian": "apt",
    "rhel8": "dnf",
    "rhel9": "dnf",
    "rocky": "dnf",
    "alma": "dnf",
    "almalinux": "dnf",
    "fedora": "dnf",
    "rhel7": "yum",
    "centos7": "yum",
    "centos": "yum",
    "amazon_linux_2": "yum",
    "sles": "zypper",
    "opensuse": "zypper",
    "alpine": "apk",
}

# Mapeamento de asset_type → OS (apenas quando inequívoco)
_ASSET_TYPE_TO_OS: Dict[str, str] = {
    "ubuntu_server": "ubuntu",
    "debian_server": "debian",
    "rhel_server": "rhel8",
    "centos_server": "centos",
    "alpine_container": "alpine",
}
