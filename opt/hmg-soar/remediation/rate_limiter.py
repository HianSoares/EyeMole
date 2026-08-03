"""
Rate limiter baseado em Sliding Window Log para o módulo de Remediation Guidance.

Implementa janela deslizante por chave (user, user:guidance_id).
Thread-safe via threading.Lock. Sem persistência (reset no restart).

Invariantes:
- Nenhum subprocess ou chamada de sistema
- Não faz chamadas de rede
- Somente em memória
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict

logger = logging.getLogger("hmg-soar-remediation.rate_limiter")


class SlidingWindowLog:
    """Rate limiter com janela deslizante (sliding window log).

    Cada chave mantém uma lista de timestamps de requisições dentro da janela.
    Quando a janela enche (max_tokens), rejeita com retry_after.

    - Thread-safe via Lock
    - Limpeza automática de entradas stale a cada 5 minutos
    - Limite máximo de chaves (max_keys) com comportamento fail-closed:
      - Remove apenas chaves cujos timestamps expiraram totalmente;
      - Nunca remove um contador ativo para admitir uma nova chave;
      - Rejeita a nova identidade quando max_keys estiver cheio.
    - Sem persistência (aceitável para single-instance MVP)
    """

    def __init__(
        self,
        max_tokens: int = 60,
        window_seconds: int = 60,
        cleanup_interval_seconds: int = 300,
        max_keys: int = 5000,
    ) -> None:
        self._max_tokens = max_tokens
        self._window_seconds = window_seconds
        self._cleanup_interval = cleanup_interval_seconds
        self._max_keys = max_keys
        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, list] = OrderedDict()
        self._last_cleanup: float = time.time()

    def is_allowed(self, key: str) -> bool:
        """Verifica se a requisição é permitida e consome um token.

        Args:
            key: Identificador do bucket (ex: "user123" ou "copy:user:alice")

        Returns:
            True se permitido, False se excedeu o limite.
        """
        now = time.time()
        cutoff = now - self._window_seconds
        with self._lock:
            self._maybe_cleanup(now)

            if key in self._buckets:
                # Chave já existente:
                # - manter o contador normal;
                # - remover timestamps expirados;
                # - aplicar o limite normalmente.
                timestamps = self._buckets[key]
                timestamps[:] = [t for t in timestamps if t > cutoff]

                if len(timestamps) >= self._max_tokens:
                    self._buckets.move_to_end(key)
                    return False

                timestamps.append(now)
                self._buckets.move_to_end(key)
                return True
            else:
                # Chave nova:
                if self._max_tokens <= 0:
                    return False

                # 1. remover todas as chaves totalmente expiradas (sem timestamps válidos)
                self._enforce_max_keys(now)

                # 2. verificar se existe espaço
                if len(self._buckets) < self._max_keys:
                    # 3. se houver espaço, criar a chave
                    self._buckets[key] = [now]
                    return True
                else:
                    # 4. se max_keys continuar atingido:
                    # - não remover chave ativa;
                    # - não inserir a nova identidade;
                    # - rejeitar de forma fail-closed (retornar False).
                    return False

    def get_retry_after(self, key: str) -> int:
        """Retorna segundos até o próximo slot disponível.

        Args:
            key: Identificador do bucket.

        Returns:
            Segundos até poder fazer nova requisição (mínimo 1).
        """
        now = time.time()
        cutoff = now - self._window_seconds
        with self._lock:
            # Limpeza rápida de expirados para verificar espaço correto
            expired_keys = []
            for k, timestamps in self._buckets.items():
                timestamps[:] = [t for t in timestamps if t > cutoff]
                if not timestamps:
                    expired_keys.append(k)
            for k in expired_keys:
                del self._buckets[k]

            # Se a chave não existe e não há espaço
            if key not in self._buckets:
                if len(self._buckets) >= self._max_keys:
                    # Fornecer Retry-After genérico e válido
                    return self._window_seconds
                return 0

            timestamps = self._buckets.get(key)
            if not timestamps:
                return 0

            valid_timestamps = [t for t in timestamps if t > cutoff]
            if len(valid_timestamps) < self._max_tokens:
                return 0

            # O token mais antigo na janela expira em:
            oldest_in_window = min(valid_timestamps)
            retry_after = int(oldest_in_window + self._window_seconds - now) + 1
            return max(retry_after, 1)

    def key_count(self) -> int:
        """Retorna o número atual de chaves no rate limiter."""
        with self._lock:
            return len(self._buckets)

    def _enforce_max_keys(self, now: float) -> None:
        """Remove todas as chaves totalmente expiradas (sem timestamps na janela).

        Deve ser chamado com lock adquirido.
        """
        cutoff = now - self._window_seconds
        expired_keys = []
        for k, timestamps in self._buckets.items():
            timestamps[:] = [t for t in timestamps if t > cutoff]
            if not timestamps:
                expired_keys.append(k)

        for k in expired_keys:
            del self._buckets[k]

    def _maybe_cleanup(self, now: float) -> None:
        """Remove entradas stale (sem atividade na janela).

        Deve ser chamado com lock adquirido.
        """
        if now - self._last_cleanup < self._cleanup_interval:
            return

        self._last_cleanup = now
        cutoff = now - self._window_seconds

        stale_keys = []
        for key, timestamps in self._buckets.items():
            # Remove timestamps expirados
            timestamps[:] = [t for t in timestamps if t > cutoff]
            if not timestamps:
                stale_keys.append(key)

        for key in stale_keys:
            del self._buckets[key]

        if stale_keys:
            logger.debug("Rate limiter cleanup: %d stale entries removed", len(stale_keys))
