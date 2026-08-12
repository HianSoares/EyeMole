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
from pathlib import Path
from typing import Dict, Optional

from ..models import ProviderResult, generate_vulnerability_key
from ..scanner_condition import parse_scanner_condition
from ..validation import ParameterValidator

logger = logging.getLogger("hmg-soar-remediation.wazuh_provider")


def _generate_vulnerability_key(
    cve: str, agent_id: str, package: str, severity: str
) -> str:
    """Wrapper privado para manter retrocompatibilidade com chamadas internas."""
    return generate_vulnerability_key(cve, agent_id, package, severity)


class WazuhProvider:
    """Provider que lê dados do snapshot de vulnerabilidades publicado.

    O estado normal do MVP é: orientação textual disponível,
    fixed_version ausente (campo é N/D nos dados atuais), command ausente.
    Isso NÃO é um erro — é o comportamento esperado.
    """

    def __init__(
        self,
        snapshot_path: Optional[Path] = None,
        assets_context_path: Optional[Path] = None,
    ) -> None:
        self._snapshot_path = snapshot_path or Path(
            "/var/www/wazuh-soar/data/latest.json"
        )
        self._assets_context_path = assets_context_path or Path(
            "/opt/hmg-soar/config/assets_context.json"
        )
        self._snapshot_data: Optional[dict] = None
        self._snapshot_index: Dict[str, dict] = {}
        self._assets_context: dict = {}
        self._snapshot_mtime: float = 0.0

    @property
    def name(self) -> str:
        return "wazuh_snapshot"

    def load_snapshot(self) -> bool:
        """Carrega (ou recarrega se mtime mudou) o snapshot publicado.

        Retorna True se o snapshot foi carregado com sucesso.
        """
        try:
            if not self._snapshot_path.is_file():
                logger.warning("Snapshot não encontrado: %s", self._snapshot_path)
                return False

            current_mtime = self._snapshot_path.stat().st_mtime
            if (
                self._snapshot_data is not None
                and current_mtime == self._snapshot_mtime
            ):
                return True  # Já carregado e atualizado

            with open(self._snapshot_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                logger.error("Snapshot com formato inválido (esperado dict).")
                return False

            # Construir índice finding_id → vuln record
            vulnerabilities = data.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                logger.error("Campo 'vulnerabilities' ausente ou inválido no snapshot.")
                return False

            index: Dict[str, dict] = {}
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                cve = str(vuln.get("cve", ""))
                agent_id = str(vuln.get("agent_id", ""))
                package = str(vuln.get("package", ""))
                severity = str(vuln.get("severity", ""))

                if not cve or not agent_id or not package:
                    continue

                key = _generate_vulnerability_key(cve, agent_id, package, severity)
                index[key] = vuln

            self._snapshot_data = data
            self._snapshot_index = index
            self._snapshot_mtime = current_mtime
            logger.info(
                "Snapshot carregado: %d vulnerabilidades indexadas", len(index)
            )
            return True

        except (json.JSONDecodeError, OSError) as e:
            logger.error("Erro ao carregar snapshot: %s", str(e))
            return False

    def load_assets_context(self) -> bool:
        """Carrega o contexto de ativos para resolução de OS."""
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

    def resolve_finding(self, finding_id: str) -> Optional[dict]:
        """Resolve finding_id para o registro de vulnerabilidade no snapshot.

        Retorna None se não encontrado (NÃO é erro interno).
        """
        if not self._snapshot_data:
            if not self.load_snapshot():
                return None

        return self._snapshot_index.get(finding_id)

    def query(self, finding_id: str) -> Optional[ProviderResult]:
        """Consulta dados de orientação para um finding_id.

        NÃO aceita substituição de campos pelo chamador.
        Resolve TODOS os dados internamente a partir do snapshot.

        Retorna None se o achado não existir ou dados forem insuficientes.
        """
        # Carregar snapshot se necessário
        if not self._snapshot_data:
            if not self.load_snapshot():
                return None

        # Resolver achado no índice
        vuln_record = self._snapshot_index.get(finding_id)
        if vuln_record is None:
            return None

        # Extrair campos do registro (não aceita substituição)
        cve = str(vuln_record.get("cve", "")).strip()
        package_name = str(vuln_record.get("package", "")).strip()
        installed_version = str(vuln_record.get("version", "")).strip()
        agent_id = str(vuln_record.get("agent_id", "")).strip()
        agent_name = str(vuln_record.get("agent_name", "")).strip()
        severity = str(vuln_record.get("severity", "")).strip()

        # Validar campos mínimos necessários
        if not cve or not package_name or not agent_id:
            return None

        # Resolver fixed_version — APENAS quando campo real, verificável e não-N/D existe
        raw_fixed = vuln_record.get("fixed_version")
        fixed_version: Optional[str] = None
        confidence = "low"

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

        # Resolver package_manager a partir do OS (regra explícita apenas)
        package_manager = self._resolve_package_manager(operating_system)

        # Construir resultado
        warnings = []
        assumptions = []

        if not fixed_version:
            warnings.append("Campo fixed_version ausente no snapshot Wazuh")
        elif raw_fixed is None and parsed_condition and parsed_condition.fixed_version:
            warnings.append("fixed_version extraída de vulnerability.scanner.condition")

        if operating_system == "unknown":
            warnings.append("Sistema operacional não identificado para o agente")
            assumptions.append("OS inferido como unknown — template pode não estar disponível")

        if not package_manager:
            warnings.append("Gerenciador de pacotes não identificado para o OS")
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

        if not self._assets_context:
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

    def _resolve_package_manager(self, operating_system: str) -> str:
        """Resolve package manager a partir do OS via mapeamento explícito.

        Retorna string vazia se não houver mapeamento (fail-safe).
        """
        os_lower = operating_system.lower().strip()
        return _OS_TO_PACKAGE_MANAGER.get(os_lower, "")


# Mapeamento explícito de OS → package manager
# Apenas regras comprovadas e documentadas
_OS_TO_PACKAGE_MANAGER: Dict[str, str] = {
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
