"""
AutoSOC - Ollama & Fixture LLM Provider Adapters (Day 12)

Implements `OllamaLLMProvider` targeting local Ollama REST endpoints (`/api/tags`,
`/api/chat`) over `httpx.AsyncClient` with strict timeout bounds, malformed
payload rejection, model-not-found handling, and secret/trace scrubbing.
Also includes `DeterministicFixtureLLMProvider` for zero-network tests.
"""

import time
from typing import Any, Dict, List, Optional, Sequence

import httpx

from app.llm.provider_contract import scrub_llm_error_message
from app.llm.schemas import (
    LLMErrorCategoryEnum,
    LLMErrorInfo,
    LLMGenerationRequest,
    LLMGenerationResponse,
    LLMProviderCapabilities,
    LLMProviderStatusEnum,
    LLMProviderStatusResponse,
    LLMTokenUsage,
    sanitize_base_url,
    utc_now_iso,
)


def _match_ollama_model(configured_model: str, raw_models: Sequence[Any]) -> bool:
    """Return True if configured_model matches an installed Ollama model entry."""
    target = configured_model.strip().lower()
    if not target:
        return False
    target_with_latest = target if ":" in target else f"{target}:latest"
    for item in raw_models:
        if not isinstance(item, dict):
            continue
        for key in ("name", "model"):
            candidate = item.get(key)
            if isinstance(candidate, str):
                norm = candidate.strip().lower()
                if norm == target or norm == target_with_latest:
                    return True
    return False


class OllamaLLMProvider:
    """
    Provider-neutral adapter for a local Ollama server.
    Makes no network calls until `check_readiness()` or `generate()` is invoked.
    """

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: float = 30.0,
        max_tokens: int = 512,
        temperature: float = 0.1,
    ) -> None:
        self._raw_base_url = base_url
        self._base_url = sanitize_base_url(base_url)
        self._model = (model or "").strip()
        self._timeout_seconds = max(0.1, min(300.0, float(timeout_seconds)))
        self._max_tokens = max(1, min(32768, int(max_tokens)))
        self._temperature = max(0.0, min(2.0, float(temperature)))
        self._capabilities = LLMProviderCapabilities(
            supports_chat=True,
            supports_json_mode=True,
            supports_streaming=False,
            max_context_tokens=None,
        )

    @property
    def provider_id(self) -> str:
        return "ollama"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def base_url(self) -> Optional[str]:
        return self._base_url

    @property
    def capabilities(self) -> LLMProviderCapabilities:
        return self._capabilities

    def is_configured(self) -> bool:
        return bool(self._base_url and self._model)

    async def check_readiness(
        self, *, timeout_seconds: Optional[float] = None
    ) -> LLMProviderStatusResponse:
        effective_timeout = (
            max(0.1, min(300.0, float(timeout_seconds)))
            if timeout_seconds is not None
            else self._timeout_seconds
        )
        now = utc_now_iso()

        if not self.is_configured():
            missing = []
            if not self._base_url:
                missing.append("base URL")
            if not self._model:
                missing.append("model name")
            return LLMProviderStatusResponse(
                enabled=True,
                configured=False,
                provider=self.provider_id,
                model=self._model or None,
                base_url=self._base_url,
                status=LLMProviderStatusEnum.UNCONFIGURED,
                available=False,
                timeout_seconds=effective_timeout,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                capabilities=self._capabilities,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.UNCONFIGURED,
                    message=f"Ollama provider missing {', '.join(missing)}",
                    retryable=False,
                ),
                checked_at=now,
            )

        try:
            async with httpx.AsyncClient(
                timeout=effective_timeout, follow_redirects=False
            ) as client:
                resp = await client.get(f"{self._base_url}/api/tags")
        except httpx.TimeoutException:
            return LLMProviderStatusResponse(
                enabled=True,
                configured=True,
                provider=self.provider_id,
                model=self._model,
                base_url=self._base_url,
                status=LLMProviderStatusEnum.UNAVAILABLE,
                available=False,
                timeout_seconds=effective_timeout,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                capabilities=self._capabilities,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.TIMEOUT,
                    message=f"Ollama readiness check timed out after {effective_timeout:.1f}s",
                    retryable=True,
                ),
                checked_at=now,
            )
        except (httpx.HTTPError, OSError) as exc:
            return LLMProviderStatusResponse(
                enabled=True,
                configured=True,
                provider=self.provider_id,
                model=self._model,
                base_url=self._base_url,
                status=LLMProviderStatusEnum.UNAVAILABLE,
                available=False,
                timeout_seconds=effective_timeout,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                capabilities=self._capabilities,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.UNAVAILABLE,
                    message=scrub_llm_error_message(
                        f"Ollama server unreachable: {type(exc).__name__}"
                    ),
                    retryable=True,
                ),
                checked_at=now,
            )

        if resp.status_code >= 500:
            return LLMProviderStatusResponse(
                enabled=True,
                configured=True,
                provider=self.provider_id,
                model=self._model,
                base_url=self._base_url,
                status=LLMProviderStatusEnum.UNAVAILABLE,
                available=False,
                timeout_seconds=effective_timeout,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                capabilities=self._capabilities,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.UNAVAILABLE,
                    message=f"Ollama returned HTTP {resp.status_code}",
                    retryable=True,
                ),
                checked_at=now,
            )

        if resp.status_code >= 400:
            return LLMProviderStatusResponse(
                enabled=True,
                configured=True,
                provider=self.provider_id,
                model=self._model,
                base_url=self._base_url,
                status=LLMProviderStatusEnum.ERROR,
                available=False,
                timeout_seconds=effective_timeout,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                capabilities=self._capabilities,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.PROVIDER_ERROR,
                    message=f"Ollama readiness check failed with HTTP {resp.status_code}",
                    retryable=False,
                ),
                checked_at=now,
            )

        try:
            payload = resp.json()
        except ValueError:
            payload = None

        if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
            return LLMProviderStatusResponse(
                enabled=True,
                configured=True,
                provider=self.provider_id,
                model=self._model,
                base_url=self._base_url,
                status=LLMProviderStatusEnum.ERROR,
                available=False,
                timeout_seconds=effective_timeout,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                capabilities=self._capabilities,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.MALFORMED_RESPONSE,
                    message="Ollama /api/tags returned malformed JSON payload",
                    retryable=False,
                ),
                checked_at=now,
            )

        if not _match_ollama_model(self._model, payload["models"]):
            return LLMProviderStatusResponse(
                enabled=True,
                configured=True,
                provider=self.provider_id,
                model=self._model,
                base_url=self._base_url,
                status=LLMProviderStatusEnum.ERROR,
                available=False,
                timeout_seconds=effective_timeout,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                capabilities=self._capabilities,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.MODEL_NOT_FOUND,
                    message=scrub_llm_error_message(
                        f"Configured model '{self._model}' is not available on Ollama"
                    ),
                    retryable=False,
                ),
                checked_at=now,
            )

        return LLMProviderStatusResponse(
            enabled=True,
            configured=True,
            provider=self.provider_id,
            model=self._model,
            base_url=self._base_url,
            status=LLMProviderStatusEnum.READY,
            available=True,
            timeout_seconds=effective_timeout,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            capabilities=self._capabilities,
            error=None,
            checked_at=now,
        )

    async def generate(self, request: LLMGenerationRequest) -> LLMGenerationResponse:
        target_model = (request.model or self._model).strip()
        effective_timeout = (
            float(request.timeout_seconds)
            if request.timeout_seconds is not None
            else self._timeout_seconds
        )

        if not self._base_url or not target_model:
            return LLMGenerationResponse(
                provider=self.provider_id,
                model=target_model,
                ok=False,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.UNCONFIGURED,
                    message="Ollama base URL and model name must be configured",
                    retryable=False,
                ),
            )

        effective_max_tokens = (
            int(request.max_tokens)
            if request.max_tokens is not None
            else self._max_tokens
        )
        effective_temperature = (
            float(request.temperature)
            if request.temperature is not None
            else self._temperature
        )
        body: Dict[str, Any] = {
            "model": target_model,
            "stream": False,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
            "options": {
                "temperature": effective_temperature,
                "num_predict": effective_max_tokens,
            },
        }
        if request.json_mode:
            body["format"] = "json"

        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(
                timeout=effective_timeout, follow_redirects=False
            ) as client:
                resp = await client.post(f"{self._base_url}/api/chat", json=body)
        except httpx.TimeoutException:
            return LLMGenerationResponse(
                provider=self.provider_id,
                model=target_model,
                ok=False,
                latency_ms=round((time.perf_counter() - start) * 1000, 2),
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.TIMEOUT,
                    message=f"Ollama request timed out after {effective_timeout:.1f}s",
                    retryable=True,
                ),
            )
        except (httpx.HTTPError, OSError) as exc:
            return LLMGenerationResponse(
                provider=self.provider_id,
                model=target_model,
                ok=False,
                latency_ms=round((time.perf_counter() - start) * 1000, 2),
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.UNAVAILABLE,
                    message=scrub_llm_error_message(
                        f"Ollama server unreachable: {type(exc).__name__}"
                    ),
                    retryable=True,
                ),
            )

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

        if resp.status_code == 404:
            return LLMGenerationResponse(
                provider=self.provider_id,
                model=target_model,
                ok=False,
                latency_ms=elapsed_ms,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.MODEL_NOT_FOUND,
                    message=scrub_llm_error_message(
                        f"Model '{target_model}' not found on Ollama server"
                    ),
                    retryable=False,
                ),
            )

        if resp.status_code >= 500:
            return LLMGenerationResponse(
                provider=self.provider_id,
                model=target_model,
                ok=False,
                latency_ms=elapsed_ms,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.UNAVAILABLE,
                    message=f"Ollama server HTTP {resp.status_code}",
                    retryable=True,
                ),
            )

        if resp.status_code >= 400:
            return LLMGenerationResponse(
                provider=self.provider_id,
                model=target_model,
                ok=False,
                latency_ms=elapsed_ms,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.PROVIDER_ERROR,
                    message=f"Ollama rejected request with HTTP {resp.status_code}",
                    retryable=False,
                ),
            )

        try:
            data = resp.json()
        except ValueError:
            data = None

        if not isinstance(data, dict):
            return LLMGenerationResponse(
                provider=self.provider_id,
                model=target_model,
                ok=False,
                latency_ms=elapsed_ms,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.MALFORMED_RESPONSE,
                    message="Ollama /api/chat returned non-object JSON payload",
                    retryable=False,
                ),
            )

        if isinstance(data.get("error"), str) and data["error"].strip():
            err_text = data["error"].strip()
            is_missing_model = "not found" in err_text.lower()
            return LLMGenerationResponse(
                provider=self.provider_id,
                model=target_model,
                ok=False,
                latency_ms=elapsed_ms,
                error=LLMErrorInfo(
                    category=(
                        LLMErrorCategoryEnum.MODEL_NOT_FOUND
                        if is_missing_model
                        else LLMErrorCategoryEnum.PROVIDER_ERROR
                    ),
                    message=scrub_llm_error_message(err_text),
                    retryable=False,
                ),
            )

        msg_obj = data.get("message")
        content = msg_obj.get("content") if isinstance(msg_obj, dict) else None
        if not isinstance(content, str) or not content.strip():
            return LLMGenerationResponse(
                provider=self.provider_id,
                model=target_model,
                ok=False,
                latency_ms=elapsed_ms,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.MALFORMED_RESPONSE,
                    message="Ollama response missing non-empty 'message.content'",
                    retryable=False,
                ),
            )

        raw_prompt_tokens = data.get("prompt_eval_count")
        raw_completion_tokens = data.get("eval_count")
        prompt_tokens = (
            int(raw_prompt_tokens)
            if isinstance(raw_prompt_tokens, int) and not isinstance(raw_prompt_tokens, bool) and raw_prompt_tokens >= 0
            else None
        )
        completion_tokens = (
            int(raw_completion_tokens)
            if isinstance(raw_completion_tokens, int) and not isinstance(raw_completion_tokens, bool) and raw_completion_tokens >= 0
            else None
        )
        usage: Optional[LLMTokenUsage] = None
        if prompt_tokens is not None or completion_tokens is not None:
            total = (prompt_tokens or 0) + (completion_tokens or 0)
            usage = LLMTokenUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total,
            )

        done_reason = data.get("done_reason")
        finish_reason = (
            str(done_reason).strip()[:64]
            if isinstance(done_reason, str) and done_reason.strip()
            else ("stop" if data.get("done") is True else None)
        )
        reported_model = (
            str(data.get("model")).strip()[:128]
            if isinstance(data.get("model"), str) and str(data.get("model")).strip()
            else target_model
        )

        return LLMGenerationResponse(
            provider=self.provider_id,
            model=reported_model,
            ok=True,
            content=content,
            usage=usage,
            finish_reason=finish_reason,
            latency_ms=elapsed_ms,
            error=None,
        )


class DeterministicFixtureLLMProvider:
    """
    Network-free deterministic fixture provider implementing `LLMProviderProtocol`
    for contract verification without requiring a live Ollama runtime.
    """

    def __init__(
        self,
        *,
        model: str = "fixture-soc-model",
        ready: bool = True,
        fixed_response: str = '{"summary":"fixture deterministic output"}',
        error_category: Optional[LLMErrorCategoryEnum] = None,
        timeout_seconds: float = 10.0,
        max_tokens: int = 512,
        temperature: float = 0.0,
    ) -> None:
        self._model = model.strip()
        self._ready = ready
        self._fixed_response = fixed_response
        self._error_category = error_category
        self._timeout_seconds = timeout_seconds
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._capabilities = LLMProviderCapabilities(
            supports_chat=True,
            supports_json_mode=True,
            supports_streaming=False,
            max_context_tokens=4096,
        )
        self.calls: List[LLMGenerationRequest] = []

    @property
    def provider_id(self) -> str:
        return "fixture"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def capabilities(self) -> LLMProviderCapabilities:
        return self._capabilities

    def is_configured(self) -> bool:
        return bool(self._model)

    async def check_readiness(
        self, *, timeout_seconds: Optional[float] = None
    ) -> LLMProviderStatusResponse:
        effective_timeout = (
            float(timeout_seconds) if timeout_seconds is not None else self._timeout_seconds
        )
        if not self.is_configured():
            return LLMProviderStatusResponse(
                enabled=True,
                configured=False,
                provider=self.provider_id,
                model=None,
                base_url=None,
                status=LLMProviderStatusEnum.UNCONFIGURED,
                available=False,
                timeout_seconds=effective_timeout,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                capabilities=self._capabilities,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.UNCONFIGURED,
                    message="Fixture LLM provider model is empty",
                    retryable=False,
                ),
            )
        if not self._ready or self._error_category is not None:
            cat = self._error_category or LLMErrorCategoryEnum.UNAVAILABLE
            st = (
                LLMProviderStatusEnum.UNAVAILABLE
                if cat in (LLMErrorCategoryEnum.UNAVAILABLE, LLMErrorCategoryEnum.TIMEOUT)
                else LLMProviderStatusEnum.ERROR
            )
            return LLMProviderStatusResponse(
                enabled=True,
                configured=True,
                provider=self.provider_id,
                model=self._model,
                base_url=None,
                status=st,
                available=False,
                timeout_seconds=effective_timeout,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                capabilities=self._capabilities,
                error=LLMErrorInfo(
                    category=cat,
                    message=f"Fixture LLM provider unavailable ({cat.value})",
                    retryable=cat in (LLMErrorCategoryEnum.UNAVAILABLE, LLMErrorCategoryEnum.TIMEOUT),
                ),
            )
        return LLMProviderStatusResponse(
            enabled=True,
            configured=True,
            provider=self.provider_id,
            model=self._model,
            base_url=None,
            status=LLMProviderStatusEnum.READY,
            available=True,
            timeout_seconds=effective_timeout,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            capabilities=self._capabilities,
            error=None,
        )

    async def generate(self, request: LLMGenerationRequest) -> LLMGenerationResponse:
        self.calls.append(request)
        if not self.is_configured():
            return LLMGenerationResponse(
                provider=self.provider_id,
                model=self._model,
                ok=False,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.UNCONFIGURED,
                    message="Fixture LLM provider model is empty",
                    retryable=False,
                ),
            )
        if not self._ready or self._error_category is not None:
            cat = self._error_category or LLMErrorCategoryEnum.UNAVAILABLE
            return LLMGenerationResponse(
                provider=self.provider_id,
                model=self._model,
                ok=False,
                error=LLMErrorInfo(
                    category=cat,
                    message=f"Fixture LLM simulated failure ({cat.value})",
                    retryable=cat in (LLMErrorCategoryEnum.UNAVAILABLE, LLMErrorCategoryEnum.TIMEOUT),
                ),
            )
        return LLMGenerationResponse(
            provider=self.provider_id,
            model=request.model or self._model,
            ok=True,
            content=self._fixed_response,
            usage=LLMTokenUsage(prompt_tokens=12, completion_tokens=8, total_tokens=20),
            finish_reason="stop",
            latency_ms=1.0,
            error=None,
        )
