"""
Assinaturas de arquivo e revisões de snapshot para o módulo de Remediation Guidance.

Uma assinatura identifica o conteúdo publicado de um arquivo sem lê-lo:
(mtime_ns, size, inode). A substituição atômica (rename) troca o inode mesmo
quando mtime/size coincidem. Arquivo ausente ou inacessível tem assinatura None.

Invariantes:
- Somente stat() — nenhuma escrita, rede ou subprocess
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable, Optional, Tuple

FileSignature = Optional[Tuple[int, int, int]]


def file_signature(path: Optional[Path]) -> FileSignature:
    """Retorna (mtime_ns, size, inode) ou None quando o arquivo não existe/não é legível."""
    if path is None:
        return None
    try:
        st = path.stat()
    except OSError:
        return None
    if not path.is_file():
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino)


def revision_of(signatures: Iterable[FileSignature]) -> str:
    """Revisão opaca (16 hex) de um conjunto ordenado de assinaturas.

    Não expõe caminhos nem valores de stat ao consumidor.
    """
    raw = "|".join(repr(sig) for sig in signatures)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
