"""
Grype Provider para o módulo de Remediation Guidance.

Lê o consolidado publicado pelo grype_runner. Assim como o WazuhProvider,
verifica a assinatura do arquivo a cada consulta: arquivo substituído é
recarregado; arquivo removido ou inválido descarta os dados anteriores.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import ProviderResult
from ..snapshot import FileSignature, file_signature
from .wazuh_provider import WazuhProvider

logger = logging.getLogger("hmg-soar-remediation.grype_provider")

# Idade máxima padrão de um scan antes de ser tratado como expirado (horas).
DEFAULT_MAX_SCAN_AGE_HOURS = 168

# Tipo do PURL → package.type equivalente do Wazuh
_PURL_TYPE_TO_PACKAGE_TYPE = {
    "deb": "deb",
    "rpm": "rpm",
    "apk": "apk",
    "npm": "npm",
    "pypi": "pypi",
    "maven": "maven",
    "golang": "golang",
    "gem": "gem",
    "nuget": "nuget",
    "cargo": "cargo",
    "composer": "composer",
}

# Aliases de package.type do Wazuh para comparação com o PURL
_PACKAGE_TYPE_ALIASES = {
    "python": "pypi",
    "pip": "pypi",
    "pypi": "pypi",
    "node": "npm",
    "npm": "npm",
    "deb": "deb",
    "rpm": "rpm",
    "apk": "apk",
}


def package_type_from_purl(purl: str) -> str:
    """Extrai o ecossistema de um Package URL (pkg:<type>/...). Vazio se ausente."""
    text = str(purl or "").strip().lower()
    if not text.startswith("pkg:"):
        return ""
    purl_type = text[4:].split("/", 1)[0]
    return _PURL_TYPE_TO_PACKAGE_TYPE.get(purl_type, purl_type)


def normalize_package_type(package_type: str) -> str:
    value = str(package_type or "").strip().lower()
    return _PACKAGE_TYPE_ALIASES.get(value, value)


def _parse_iso(value: str) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass(frozen=True)
class GrypeView:
    """Visão imutável de UMA revisão do consolidado do Grype.

    Todas as leituras de uma mesma orientação (correlação, ramos de correção,
    idade do scan) usam a mesma visão.
    """

    signature: tuple
    metadata: dict
    index: Dict[tuple, Tuple[dict, ...]]


class GrypeProvider:
    """Provider que lê dados do snapshot consolidado do Grype.

    Mapeia os resultados contra o snapshot do Wazuh para correlacionar finding_ids.
    """

    def __init__(
        self,
        wazuh_provider: WazuhProvider,
        grype_snapshot_path: Optional[Path] = None,
        max_scan_age_hours: int = DEFAULT_MAX_SCAN_AGE_HOURS,
    ) -> None:
        self._grype_path = grype_snapshot_path or Path(
            "/opt/hmg-soar/output/grype_latest.json"
        )
        self._wazuh_provider = wazuh_provider
        self._max_scan_age_hours = max_scan_age_hours
        self._lock = threading.Lock()
        self._view: Optional[GrypeView] = None

    @property
    def name(self) -> str:
        return "grype_snapshot"

    @property
    def snapshot_path(self) -> Path:
        return self._grype_path

    def set_max_scan_age_hours(self, hours: int) -> None:
        """Atualiza o limite de idade quando a configuração é recarregada."""
        self._max_scan_age_hours = hours

    def load_grype_snapshot(self) -> bool:
        """Carrega e indexa a revisão atual do snapshot do Grype."""
        return self.current_view() is not None

    def current_view(self) -> Optional[GrypeView]:
        """Visão da revisão ATUAL (recarrega se mudou; None se ausente/inválido)."""
        with self._lock:
            sig = file_signature(self._grype_path)
            if sig is None:
                self._view = None
                return None
            if self._view is not None and sig == self._view.signature:
                return self._view

            self._view = None
            try:
                with open(self._grype_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
                logger.error("Erro ao carregar snapshot do Grype: %s", type(e).__name__)
                return None

            if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities", []) or [], list):
                logger.error("Snapshot do Grype com formato inválido.")
                return None

            # O conteúdo lido precisa pertencer à revisão cujo stat foi observado.
            if file_signature(self._grype_path) != sig:
                logger.warning("Snapshot do Grype alterado durante a leitura.")
                return None

            index: Dict[tuple, List[dict]] = {}
            for v in data.get("vulnerabilities", []) or []:
                if not isinstance(v, dict):
                    continue
                cve = str(v.get("cve") or "").strip().upper()
                agent_id = str(v.get("agent_id") or "").strip()
                pkg = str(v.get("package_name") or "").strip().lower()
                ver = str(v.get("installed_version") or "").strip()

                if cve and agent_id and pkg:
                    # Chave de correlação exata (lista: pode haver várias localizações)
                    index.setdefault((cve, agent_id, pkg, ver), []).append(v)

            metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
            self._view = GrypeView(
                signature=sig,
                metadata=metadata,
                index={k: tuple(v) for k, v in index.items()},
            )
            logger.info("Snapshot do Grype carregado: %d registros indexados", len(index))
            return self._view

    def query(self, finding_id: str) -> Optional[ProviderResult]:
        """Consulta dados de orientação a partir do snapshot do Grype."""
        wazuh_record = self._wazuh_provider.resolve_finding(finding_id)
        if wazuh_record is None:
            return None
        return self.query_record(wazuh_record)

    def query_record(
        self, wazuh_record: dict, view: Optional[GrypeView] = None
    ) -> Optional[ProviderResult]:
        """Correlaciona um registro Wazuh já resolvido com o snapshot do Grype."""
        if view is None:
            view = self.current_view()
        if view is None:
            return None

        cve = str(wazuh_record.get("cve") or "").strip().upper()
        agent_id = str(wazuh_record.get("agent_id") or "").strip()
        pkg = str(wazuh_record.get("package") or "").strip().lower()
        ver = str(wazuh_record.get("version") or "").strip()

        candidates = list(view.index.get((cve, agent_id, pkg, ver), ()))
        if not candidates:
            return None

        warnings: List[str] = []
        wazuh_type = normalize_package_type(str(wazuh_record.get("package_type") or ""))
        if wazuh_type:
            same_type = [
                c for c in candidates
                if not package_type_from_purl(str(c.get("purl") or ""))
                or package_type_from_purl(str(c.get("purl") or "")) == wazuh_type
            ]
            if candidates and not same_type:
                # Mesmo nome/versão, ecossistema diferente: não é a mesma instância.
                logger.info("Correlação Grype descartada: ecossistema divergente.")
                return None
            candidates = same_type

        distinct = {
            (str(c.get("fixed_version") or ""), str(c.get("status") or ""), tuple(c.get("fixed_versions") or []))
            for c in candidates
        }
        r = candidates[0]
        if len(distinct) > 1:
            warnings.append(
                "Grype reportou múltiplas correspondências divergentes para o mesmo pacote/versão; "
                "versão corrigida do Grype desconsiderada."
            )

        agent_warnings, expired = self._scan_freshness(agent_id, view)
        warnings.extend(agent_warnings)
        if expired:
            return None

        status = str(r.get("status") or "unknown").strip().lower()
        fixed_version = r.get("fixed_version")
        fixed_version = str(fixed_version).strip() if fixed_version else None
        # Fail-closed: versão corrigida só vale com status "fixed" e sem divergência interna.
        if status != "fixed" or len(distinct) > 1:
            fixed_version = None

        confidence = str(r.get("confidence") or "none")
        return ProviderResult(
            cve=str(r.get("cve") or ""),
            package_name=str(r.get("package_name") or ""),
            installed_version=str(r.get("installed_version") or ""),
            fixed_version=fixed_version,
            operating_system="",  # Resolvido no engine a partir do Wazuh
            package_manager="",   # Resolvido no engine a partir do Wazuh
            agent_id=str(r.get("agent_id") or ""),
            agent_name="",
            severity="",
            confidence=confidence,
            source=self.name,
            warnings=warnings,
            assumptions=[],
            status=status,
            purl=str(r.get("purl") or ""),
            package_type=package_type_from_purl(str(r.get("purl") or "")),
            fix_confidence=confidence if fixed_version else "none",
        )

    def fixed_versions_for(
        self, wazuh_record: dict, view: Optional[GrypeView] = None
    ) -> Tuple[str, ...]:
        """Lista completa de versões corrigidas (ramos) informada pelo Grype."""
        if view is None:
            view = self.current_view()
        if view is None:
            return ()
        key = (
            str(wazuh_record.get("cve") or "").strip().upper(),
            str(wazuh_record.get("agent_id") or "").strip(),
            str(wazuh_record.get("package") or "").strip().lower(),
            str(wazuh_record.get("version") or "").strip(),
        )
        versions: List[str] = []
        for candidate in view.index.get(key, ()):
            for value in candidate.get("fixed_versions") or []:
                text = str(value).strip()
                if text and text not in versions:
                    versions.append(text)
        return tuple(versions)

    def _scan_freshness(self, agent_id: str, view: GrypeView) -> Tuple[List[str], bool]:
        """Avalia idade/erro do último scan do agente. Retorna (avisos, expirado)."""
        metadata = view.metadata or {}
        agents = metadata.get("agents") if isinstance(metadata, dict) else None
        if not isinstance(agents, dict):
            return ([], False)  # Consolidado legado sem estado por agente
        state = agents.get(agent_id)
        if not isinstance(state, dict):
            return ([], False)

        warnings: List[str] = []
        scanned_at = _parse_iso(state.get("last_success_at") or "")
        if state.get("last_error"):
            warnings.append(
                "Último scan Grype deste agente falhou; usando a evidência válida anterior."
            )
        if scanned_at is None:
            return (warnings, False)

        age_hours = (datetime.now(timezone.utc) - scanned_at).total_seconds() / 3600.0
        if age_hours > self._max_scan_age_hours:
            warnings.append(
                f"Evidência Grype expirada ({int(age_hours)}h; limite {self._max_scan_age_hours}h); desconsiderada."
            )
            logger.info("Scan Grype do agente %s expirado (%dh).", agent_id, int(age_hours))
            return (warnings, True)
        if state.get("last_error"):
            warnings.append(f"Idade da evidência Grype: {int(age_hours)}h.")
        return (warnings, False)
