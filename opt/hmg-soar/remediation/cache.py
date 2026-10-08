"""
Cache de orientações de remediação (GuidanceRecord) em memória.

Implementa cache por finding_id e lookup por guidance_id para auditoria.
Thread-safe via threading.Lock. Sem persistência (perde-se no restart).

Invariantes:
- Nenhum subprocess ou chamada de sistema
- Somente leitura do snapshot (para verificar mtime)
- Não modifica snapshot ou analyserV1.py
- Não faz chamadas de rede
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence, Union

from .models import GuidanceRecord
from .snapshot import file_signature

DependencyPaths = Union[Sequence[Path], Callable[[], Iterable[Path]]]
_UNOBSERVED = object()

logger = logging.getLogger("hmg-soar-remediation.cache")


class GuidanceCache:
    """Cache em memória de GuidanceRecord por finding_id.

    Features:
    - Lookup por finding_id (GET endpoint)
    - Lookup por guidance_id (POST audit endpoint)
    - TTL: 6 horas padrão
    - Max entries: 10,000 (LRU eviction)
    - Invalidação por mudança de assinatura de QUALQUER dependência
      (snapshot Wazuh, Grype, contexto de ativos, políticas, templates,
      evidências). Arquivo removido também invalida.
    - Thread-safe (threading.Lock)
    - Sem persistência (aceitável perder no restart)
    """

    def __init__(
        self,
        snapshot_path: Optional[Path] = None,
        ttl_seconds: int = 21600,  # 6 hours
        max_entries: int = 10000,
        dependency_paths: Optional[DependencyPaths] = None,
    ) -> None:
        self._snapshot_path = snapshot_path
        self._dependency_paths = dependency_paths
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._lock = threading.Lock()

        # finding_id → (GuidanceRecord, timestamp_inserted)
        self._by_finding_id: OrderedDict[str, tuple[GuidanceRecord, float]] = OrderedDict()

        # guidance_id → finding_id (reverse lookup for audit)
        self._by_guidance_id: dict[str, str] = {}

        # Assinatura combinada das dependências (None = sem dependências)
        self._snapshot_sig: object = _UNOBSERVED

    def get_by_finding_id(self, finding_id: str) -> Optional[GuidanceRecord]:
        """Retorna GuidanceRecord do cache se existir e não estiver expirado.

        Verifica invalidação por mtime do snapshot antes.
        Retorna None se cache miss ou expirado.
        """
        with self._lock:
            self._check_snapshot_invalidation()

            entry = self._by_finding_id.get(finding_id)
            if entry is None:
                return None

            record, inserted_at = entry
            if time.time() - inserted_at > self._ttl_seconds:
                # Expirado — remover
                self._remove_entry(finding_id)
                return None

            # Move to end (LRU: most recently accessed)
            self._by_finding_id.move_to_end(finding_id)
            return record

    def get_by_guidance_id(self, guidance_id: str) -> Optional[GuidanceRecord]:
        """Retorna GuidanceRecord pelo guidance_id (para audit POST).

        Retorna None se não encontrado ou expirado.
        """
        with self._lock:
            self._check_snapshot_invalidation()

            finding_id = self._by_guidance_id.get(guidance_id)
            if finding_id is None:
                return None

            entry = self._by_finding_id.get(finding_id)
            if entry is None:
                # Inconsistência — limpar
                del self._by_guidance_id[guidance_id]
                return None

            record, inserted_at = entry
            if time.time() - inserted_at > self._ttl_seconds:
                # Expirado — remover
                self._remove_entry(finding_id)
                return None

            return record

    def dependency_signature(self) -> Optional[tuple]:
        """Assinatura atual das dependências (capturar ANTES de gerar a orientação)."""
        with self._lock:
            return self._current_signature()

    def put(
        self,
        finding_id: str,
        record: GuidanceRecord,
        expected_signature: object = _UNOBSERVED,
    ) -> bool:
        """Armazena GuidanceRecord no cache.

        Se expected_signature for informada e as dependências tiverem mudado
        durante a geração, o registro NÃO é armazenado (evita fixar no cache
        um resultado vinculado a uma revisão já superada). Retorna True se
        armazenou.

        Evicta entrada LRU se limite atingido.
        """
        with self._lock:
            self._check_snapshot_invalidation()
            if (expected_signature is not _UNOBSERVED
                    and expected_signature != self._current_signature()):
                logger.info("Dependências mudaram durante a geração; resultado não armazenado em cache.")
                return False

            # Se já existe, remover primeiro (para atualizar posição e timestamp)
            if finding_id in self._by_finding_id:
                self._remove_entry(finding_id)

            # Eviction: remover mais antigo se no limite
            while len(self._by_finding_id) >= self._max_entries:
                oldest_key, oldest_entry = self._by_finding_id.popitem(last=False)
                oldest_record, _ = oldest_entry
                # Remove reverse lookup
                self._by_guidance_id.pop(oldest_record.guidance_id, None)

            # Inserir
            self._by_finding_id[finding_id] = (record, time.time())
            self._by_guidance_id[record.guidance_id] = finding_id
            return True

    def invalidate_all(self) -> None:
        """Invalida todo o cache (ex: snapshot mudou)."""
        with self._lock:
            self._by_finding_id.clear()
            self._by_guidance_id.clear()
            self._snapshot_sig = _UNOBSERVED

    def size(self) -> int:
        """Retorna o número de entradas no cache."""
        with self._lock:
            return len(self._by_finding_id)

    def _remove_entry(self, finding_id: str) -> None:
        """Remove uma entrada (deve ser chamado com lock adquirido)."""
        entry = self._by_finding_id.pop(finding_id, None)
        if entry is not None:
            record, _ = entry
            self._by_guidance_id.pop(record.guidance_id, None)

    def _paths(self) -> list:
        paths = []
        if self._snapshot_path is not None:
            paths.append(self._snapshot_path)
        deps = self._dependency_paths
        if callable(deps):
            try:
                deps = list(deps())
            except Exception:
                logger.warning("Falha ao obter dependências do cache.")
                deps = []
        for path in deps or []:
            if path is not None and path not in paths:
                paths.append(path)
        return paths

    def _current_signature(self) -> Optional[tuple]:
        paths = self._paths()
        if not paths:
            return None
        return tuple(file_signature(path) for path in paths)

    def _check_snapshot_invalidation(self) -> None:
        """Invalida o cache se a assinatura de qualquer dependência mudou.

        Deve ser chamado com lock adquirido. Arquivo removido/inacessível tem
        assinatura None e também conta como mudança (nunca mantém dados de
        uma fonte que deixou de existir).
        """
        current_sig = self._current_signature()
        if current_sig is None:
            return

        if self._snapshot_sig is _UNOBSERVED:
            # Primeira observação — apenas registrar sem invalidar
            self._snapshot_sig = current_sig
            return

        if current_sig != self._snapshot_sig:
            logger.info("Assinatura de dependências mudou, invalidando cache de guidance.")
            self._by_finding_id.clear()
            self._by_guidance_id.clear()
            self._snapshot_sig = current_sig
