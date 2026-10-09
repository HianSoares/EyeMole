"""OpenAI-compatible chat-completions adapter (NVIDIA API Catalog by default).

Security properties:
- The endpoint comes only from administrative configuration and must match the
  provider registry (HTTPS, approved host, no credentials/query). Browser
  requests never choose the provider, URL or model.
- Redirects are refused, so the API key is never forwarded to another host.
- TLS is always validated (system trust or an administrator-supplied CA file).
- Bounded total time budget, limited retries honoring Retry-After, bounded
  response size, no streaming of partial answers.
- Errors carry only operator-safe text: never the key, request or remote body.

Adding another OpenAI-compatible provider means adding a ProviderSpec entry;
there is deliberately no automatic routing between companies.
"""
import email.utils
import json
import logging
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import requests

from .security import OperationError

logger = logging.getLogger("eyemole-ai")

MODEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}")
MAX_ATTEMPTS = 3
MAX_RETRY_WAIT_SECONDS = 30
DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    label: str
    default_base_url: str
    allowed_hosts: frozenset
    secret: str
    default_model: str
    default_params: dict = field(default_factory=dict)
    # Provider/model supports chat_template_kwargs.enable_thinking (Nemotron).
    thinking_toggle: bool = False


PROVIDERS = {
    "nvidia": ProviderSpec(
        name="nvidia",
        label="NVIDIA",
        default_base_url="https://integrate.api.nvidia.com/v1",
        allowed_hosts=frozenset({"integrate.api.nvidia.com"}),
        secret="NVIDIA_API_KEY",
        default_model="nvidia/nemotron-3-super-120b-a12b",
        # Sampling recommended on the model card for all tasks.
        default_params={"temperature": 1.0, "top_p": 0.95},
        thinking_toggle=True,
    ),
}


class AIProviderError(OperationError):
    """Provider unavailable/refused. `code` is stable for UI and tests."""

    def __init__(self, message, code, status=502, retry_after=None):
        super().__init__(message, status)
        self.code = code
        self.retry_after = retry_after


@dataclass(frozen=True)
class ProviderSettings:
    spec: ProviderSpec
    base_url: str
    model: str
    timeout_seconds: int
    max_output_tokens: int
    max_response_bytes: int
    ca: object
    thinking: str  # "disabled" | "provider_default"
    temperature: float
    top_p: float

    @property
    def public(self):
        """Safe description for API/UI: no URL, CA path or secret name."""
        return {"provider": self.spec.name, "provider_label": self.spec.label, "model": self.model}


def _number(value, default, minimum, maximum, kind=int):
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OperationError("Configuração de IA inválida: valores numéricos esperados.", 503)
    return kind(min(max(value, minimum), maximum))


def resolve_settings(config):
    """Validate the administrative `integrations.ai` block. Raises 503 on misconfiguration."""
    if not isinstance(config, dict):
        raise OperationError("Configuração de IA inválida.", 503)
    name = config.get("provider", "nvidia")
    spec = PROVIDERS.get(name)
    if spec is None:
        raise OperationError("Provedor de IA não suportado: " + str(name)[:40], 503)
    base_url = str(config.get("base_url") or spec.default_base_url).rstrip("/")
    parsed = urlsplit(base_url)
    if (parsed.scheme != "https" or parsed.hostname not in spec.allowed_hosts or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.port not in (None, 443) or parsed.path != "/v1"):
        raise OperationError(f"Endereço do provedor {spec.label} fora da allowlist administrativa.", 503)
    model = str(config.get("model") or spec.default_model)
    if not MODEL_PATTERN.fullmatch(model):
        raise OperationError("Identificador de modelo inválido.", 503)
    ca = config.get("ca") or True
    if ca is not True and (not isinstance(ca, str) or not ca.startswith("/")):
        raise OperationError("CA do provedor de IA deve ser caminho absoluto.", 503)
    thinking = config.get("thinking", "disabled")
    if thinking not in {"disabled", "provider_default"}:
        raise OperationError("thinking deve ser 'disabled' ou 'provider_default'.", 503)
    return ProviderSettings(
        spec=spec, base_url=base_url, model=model,
        timeout_seconds=_number(config.get("timeout_seconds"), 90, 15, 300),
        max_output_tokens=_number(config.get("max_output_tokens"), 2048, 256, 8192),
        max_response_bytes=_number(config.get("max_response_bytes"), DEFAULT_MAX_RESPONSE_BYTES, 16 * 1024, 1024 * 1024),
        ca=ca, thinking=thinking,
        temperature=_number(config.get("temperature"), spec.default_params.get("temperature", 0.2), 0.0, 2.0, float),
        top_p=_number(config.get("top_p"), spec.default_params.get("top_p", 1.0), 0.01, 1.0, float),
    )


def new_session():
    """Factory kept separate so tests inject a simulated transport."""
    return requests.Session()


def _retry_after(headers, now=None):
    value = (headers or {}).get("Retry-After")
    if value is None:
        return None
    value = str(value).strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
        return max(0.0, when.timestamp() - (now if now is not None else time.time()))
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


class ChatCompletionsClient:
    def __init__(self, settings, api_key, session=None, clock=time.monotonic, sleep=time.sleep):
        if not isinstance(api_key, str) or not api_key.strip():
            raise AIProviderError(f"{settings.spec.label}: chave {settings.spec.secret} ausente no worker.",
                                  "missing_credentials", 503)
        self.settings = settings
        self._api_key = api_key.strip()
        self._session = session or new_session()
        self._session.trust_env = False  # no proxy/netrc credentials from the environment
        self._clock, self._sleep = clock, sleep

    def _payload(self, messages):
        payload = {"model": self.settings.model, "messages": messages, "stream": False,
                   "max_tokens": self.settings.max_output_tokens,
                   "temperature": self.settings.temperature, "top_p": self.settings.top_p}
        if self.settings.spec.thinking_toggle and self.settings.thinking == "disabled":
            payload["chat_template_kwargs"] = {"enable_thinking": False}
        return payload

    def complete(self, messages):
        """Return (content, served_model). Raises AIProviderError / OperationError."""
        label = self.settings.spec.label
        url = self.settings.base_url + "/chat/completions"
        body = json.dumps(self._payload(messages), ensure_ascii=False).encode("utf-8")
        headers = {"Authorization": "Bearer " + self._api_key, "Content-Type": "application/json",
                   "Accept": "application/json", "User-Agent": "EyeMole-remediation/1"}
        started = self._clock()
        deadline = started + self.settings.timeout_seconds
        last_error = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            remaining = deadline - self._clock()
            if remaining <= 1:
                break
            try:
                response = self._session.request(
                    "POST", url, data=body, headers=headers, timeout=(5, max(1.0, min(remaining, 120))),
                    allow_redirects=False, stream=True, verify=self.settings.ca)
            except requests.Timeout:
                last_error = AIProviderError(f"{label}: tempo limite excedido.", "timeout", 504)
                wait = min(2 ** (attempt - 1), MAX_RETRY_WAIT_SECONDS)
            except requests.RequestException:
                last_error = AIProviderError(f"{label}: falha de conexão ou TLS.", "connection_failed", 502)
                wait = min(2 ** (attempt - 1), MAX_RETRY_WAIT_SECONDS)
            else:
                with response:
                    status = response.status_code
                    if 200 <= status < 300:
                        return self._read(response, label)
                    if 300 <= status < 400:
                        raise AIProviderError(f"{label}: redirecionamento recusado.", "redirect_refused", 502)
                    if status in (401, 403):
                        raise AIProviderError(f"{label}: autenticação recusada; confira {self.settings.spec.secret} no worker.",
                                              "auth_failed", 502)
                    if status in (404, 410):
                        raise AIProviderError(f"{label}: modelo {self.settings.model} indisponível.", "model_unavailable", 502)
                    if status in (400, 413, 422):
                        raise AIProviderError(f"{label}: requisição recusada pelo modelo (parâmetros ou tamanho).",
                                              "request_rejected", 502)
                    if status not in RETRYABLE_STATUS:
                        raise AIProviderError(f"{label}: erro HTTP {status}.", "provider_error", 502)
                    advised = _retry_after(response.headers)
                    if status == 429:
                        last_error = AIProviderError(f"{label}: limite de requisições atingido (HTTP 429).", "rate_limited",
                                                     429, advised)
                    else:
                        last_error = AIProviderError(f"{label}: provedor indisponível (HTTP {status}).", "provider_unavailable",
                                                     503, advised)
                    wait = advised if advised is not None else min(2 ** (attempt - 1), MAX_RETRY_WAIT_SECONDS)
            if attempt == MAX_ATTEMPTS:
                break
            # Retry-After beyond the remaining budget (or too long): give up now, don't sleep in vain.
            if wait > MAX_RETRY_WAIT_SECONDS or self._clock() + wait >= deadline - 1:
                break
            logger.info("Provedor de IA %s: tentativa %d falhou (%s); nova tentativa em %.1fs.",
                        self.settings.spec.name, attempt, last_error.code, wait)
            self._sleep(wait)
        raise last_error or AIProviderError(f"{label}: orçamento de tempo esgotado.", "timeout", 504)

    def _read(self, response, label):
        content_type = response.headers.get("Content-Type", "")
        if "json" not in content_type.lower():
            raise AIProviderError(f"{label}: resposta não JSON.", "invalid_response", 502)
        raw = bytearray()
        for chunk in response.iter_content(65536):
            raw.extend(chunk)
            if len(raw) > self.settings.max_response_bytes:
                raise AIProviderError(f"{label}: resposta acima do limite de tamanho.", "response_too_large", 502)
        try:
            data = json.loads(bytes(raw))
            choices = data["choices"]
            if not isinstance(choices, list) or len(choices) != 1:
                raise ValueError()
            choice = choices[0]
            message = choice["message"]
        except (ValueError, KeyError, TypeError, IndexError):
            raise AIProviderError(f"{label}: resposta fora do formato chat completions.", "invalid_response", 502)
        if message.get("tool_calls") or message.get("function_call") or choice.get("finish_reason") in {"tool_calls", "function_call"}:
            raise AIProviderError(f"{label}: chamada de ferramenta não permitida.", "tool_call_rejected", 502)
        if choice.get("finish_reason") == "length":
            raise AIProviderError(f"{label}: resposta truncada pelo limite de tokens.", "truncated", 502)
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise AIProviderError(f"{label}: resposta vazia.", "invalid_response", 502)
        served = data.get("model") if isinstance(data.get("model"), str) else self.settings.model
        return content, served[:128]
