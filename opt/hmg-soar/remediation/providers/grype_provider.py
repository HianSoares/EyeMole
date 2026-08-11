"""
Grype Provider para o módulo de Remediation Guidance.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Optional

from ..models import ProviderResult
from .wazuh_provider import WazuhProvider

logger = logging.getLogger("hmg-soar-remediation.grype_provider")


class GrypeProvider:
    """Provider que lê dados do snapshot consolidado do Grype.

    Mapeia os resultados contra o snapshot do Wazuh para correlacionar finding_ids.
    """

    def __init__(
        self,
        wazuh_provider: WazuhProvider,
        grype_snapshot_path: Optional[Path] = None,
    ) -> None:
        self._grype_path = grype_snapshot_path or Path(
            "/opt/hmg-soar/output/grype_latest.json"
        )
        self._wazuh_provider = wazuh_provider
        self._grype_data: Optional[dict] = None
        self._grype_index: Dict[tuple, dict] = {}
        self._grype_mtime: float = 0.0

    @property
    def name(self) -> str:
        return "grype_snapshot"

    def load_grype_snapshot(self) -> bool:
        """Carrega e indexa o snapshot de vulnerabilidades do Grype."""
        try:
            if not self._grype_path.is_file():
                return False

            current_mtime = self._grype_path.stat().st_mtime
            if self._grype_data is not None and current_mtime == self._grype_mtime:
                return True

            with open(self._grype_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                logger.error("Snapshot do Grype com formato inválido.")
                return False

            vulnerabilities = data.get("vulnerabilities", []) or []
            index = {}
            for v in vulnerabilities:
                if not isinstance(v, dict):
                    continue
                cve = str(v.get("cve") or "").strip().upper()
                agent_id = str(v.get("agent_id") or "").strip()
                pkg = str(v.get("package_name") or "").strip().lower()
                ver = str(v.get("installed_version") or "").strip()

                if cve and agent_id and pkg:
                    # Chave de correlação exata
                    index[(cve, agent_id, pkg, ver)] = v

            self._grype_data = data
            self._grype_index = index
            self._grype_mtime = current_mtime
            logger.info("Snapshot do Grype carregado: %d registros indexados", len(index))
            return True

        except (json.JSONDecodeError, OSError) as e:
            logger.error("Erro ao carregar snapshot do Grype: %s", str(e))
            return False

    def query(self, finding_id: str) -> Optional[ProviderResult]:
        """Consulta dados de orientação a partir do snapshot do Grype."""
        if not self.load_grype_snapshot():
            return None

        # 1. Resolver o finding_id no snapshot do Wazuh para obter a chave de correlação
        wazuh_record = self._wazuh_provider.resolve_finding(finding_id)
        if wazuh_record is None:
            return None

        cve = str(wazuh_record.get("cve") or "").strip().upper()
        agent_id = str(wazuh_record.get("agent_id") or "").strip()
        pkg = str(wazuh_record.get("package") or "").strip().lower()
        ver = str(wazuh_record.get("version") or "").strip()

        # 2. Buscar correspondência no Grype index
        r = self._grype_index.get((cve, agent_id, pkg, ver))
        if r is None:
            return None

        fixed_version = r.get("fixed_version")
        if fixed_version:
            fixed_version = str(fixed_version).strip()

        return ProviderResult(
            cve=r.get("cve", ""),
            package_name=r.get("package_name", ""),
            installed_version=r.get("installed_version", ""),
            fixed_version=fixed_version,
            operating_system="",  # Resolvido no engine a partir do Wazuh
            package_manager="",   # Resolvido no engine a partir do Wazuh
            agent_id=r.get("agent_id", ""),
            agent_name="",
            severity="",
            confidence=r.get("confidence", "none"),
            source=self.name,
            warnings=[],
            assumptions=[],
            status=r.get("status", "unknown"),
        )
