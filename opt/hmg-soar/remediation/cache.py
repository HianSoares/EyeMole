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
from typing import Optional

from .models import GuidanceRecord

logger = logging.getLogger("hmg-soar-remediation.cache")


class GuidanceCache:
    """Cache em memória de GuidanceRecord por finding_id.

    Features:
    - Lookup por finding_id (GET endpoint)
    - Lookup por guidance_id (POST audit endpoint)
    - TTL: 6 horas padrão
    - Max entries: 10,000 (LRU eviction)
    - Invalidação por mudança de mtime do snapshot
    - Thread-safe (threading.Lock)
    - Sem persistência (aceitável perder no restart)
    """

    def __init__(
        self,
        snapshot_path: Optional[Path] = None,
        ttl_seconds: int = 21600,  # 6 hours
        max_entries: int = 10000,
    ) -> None:
        self._snapshot_path = snapshot_path
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._lock = threading.Lock()

        # finding_id → (GuidanceRecord, timestamp_inserted)
        self._by_finding_id: OrderedDict[str, tuple[GuidanceRecord, float]] = OrderedDict()

        # guidance_id → finding_id (reverse lookup for audit)
        self._by_guidance_id: dict[str, str] = {}

        # Track snapshot signature for invalidation: (mtime_ns, size)
        self._snapshot_sig: tuple = (0, 0)

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

    def put(self, finding_id: str, record: GuidanceRecord) -> None:
        """Armazena GuidanceRecord no cache.

        Evicta entrada LRU se limite atingido.
        """
        with self._lock:
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

    def invalidate_all(self) -> None:
        """Invalida todo o cache (ex: snapshot mudou)."""
        with self._lock:
            self._by_finding_id.clear()
            self._by_guidance_id.clear()
            self._snapshot_sig = (0, 0)

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

    def _check_snapshot_invalidation(self) -> None:
        """Verifica se o snapshot mudou (mtime_ns, size) e invalida cache se sim.

        Deve ser chamado com lock adquirido.
        """
        if self._snapshot_path is None:
            return

        try:
            stat_result = self._snapshot_path.stat()
            current_sig = (stat_result.st_mtime_ns, stat_result.st_size)

            if self._snapshot_sig == (0, 0):
                # Primeira observação — apenas registrar sem invalidar
                self._snapshot_sig = current_sig
                return

            if current_sig != self._snapshot_sig:
                # Snapshot mudou — invalidar ambos os índices
                logger.info("Snapshot signature mudou, invalidando cache de guidance.")
                self._by_finding_id.clear()
                self._by_guidance_id.clear()
                self._snapshot_sig = current_sig

        except OSError:
            # Não conseguimos verificar — manter cache como está (fail-safe)
            logger.warning("Falha ao verificar stat do snapshot, mantendo cache.")
