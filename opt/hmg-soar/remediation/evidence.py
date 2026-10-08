"""
Catálogo local de evidências de fabricante para o módulo de Remediation Guidance.

Lê entradas verificadas manualmente (vendor_evidence.json). Uma entrada só é
aplicada quando CVE, produto e ramo de build coincidem com o achado. As
evidências alimentam fontes, justificativa, pré-requisitos e diagnósticos de
leitura — nunca o campo de comando de instalação.

Invariantes:
- Somente leitura de arquivo local controlado
- Nenhuma rede, subprocess, eval ou exec
- Não inventa KB, URL ou nome de arquivo: tudo vem do arquivo controlado
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import List, Optional

from .snapshot import FileSignature, file_signature
from .versioning import parse_windows_build

logger = logging.getLogger("hmg-soar-remediation.evidence")

_DEFAULT_EVIDENCE_PATH = Path(__file__).parent / "data" / "vendor_evidence.json"
_KB_RE = re.compile(r"^KB[0-9]{6,8}$")
_ALLOWED_URL_PREFIXES = (
    "https://support.microsoft.com/",
    "https://msrc.microsoft.com/",
    "https://learn.microsoft.com/",
    "https://www.catalog.update.microsoft.com/",
)


class VendorEvidenceCatalog:
    """Catálogo de evidências recarregado por assinatura do arquivo."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or _DEFAULT_EVIDENCE_PATH
        self._sig: FileSignature = None
        self._entries: List[dict] = []
        self._loaded = False

    @property
    def path(self) -> Path:
        return self._path

    @property
    def loaded_signature(self):
        return self._sig

    def refresh(self) -> None:
        self._refresh()

    def _refresh(self) -> None:
        sig = file_signature(self._path)
        if self._loaded and sig == self._sig:
            return
        self._sig = sig
        self._loaded = True
        self._entries = []
        if sig is None:
            return
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            logger.error("Erro ao carregar catálogo de evidências: %s", type(e).__name__)
            return
        entries = data.get("entries") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            return
        self._entries = [e for e in entries if self._is_valid_entry(e)]

    @staticmethod
    def _is_valid_entry(entry: object) -> bool:
        if not isinstance(entry, dict):
            return False
        if not entry.get("cve") or not entry.get("verified_at"):
            return False
        kb = entry.get("kb")
        if kb is not None and not _KB_RE.match(str(kb)):
            return False
        sources = entry.get("sources") or []
        if not isinstance(sources, list) or not sources:
            return False
        for source in sources:
            url = str((source or {}).get("url") or "")
            if url and not url.startswith(_ALLOWED_URL_PREFIXES):
                return False
        return True

    def find_windows(self, cve: str, product_name: str, installed_version: str) -> Optional[dict]:
        """Retorna a evidência que casa CVE + produto + ramo de build, ou None.

        Usa a revisão carregada por refresh() no início da requisição.
        """
        if not self._loaded:
            self._refresh()
        installed = parse_windows_build(installed_version)
        if installed is None:
            return None
        product = str(product_name or "").lower()
        for entry in self._entries:
            if str(entry.get("cve")).upper() != str(cve or "").upper():
                continue
            if str(entry.get("vendor")) != "microsoft":
                continue
            matches = [str(m).lower() for m in entry.get("product_match") or []]
            if not matches or not any(m in product for m in matches):
                continue
            if str(entry.get("os_build") or "") != str(installed[2]):
                continue
            return dict(entry)
        return None
