"""
AutoSOC - LLM Runtime Service & Status Diagnostics (Day 12)

Resolves configured local LLM providers (`ollama` or `fixture`), executes bounded
readiness checks and generation calls cleanly, and produces sanitized status
responses without exposing secrets, raw prompts, generated output, or traces.
"""

import asyncio
from typing import Any, Optional

from app.core.config import settings
from app.llm.ollama_adapter import (
    DeterministicFixtureLLMProvider,
    OllamaLLMProvider,
)
from app.llm.provider_contract import LLMProviderProtocol, scrub_llm_error_message
from app.llm.schemas import (
    LLMErrorCategoryEnum,
    LLMErrorInfo,
    LLMGenerationRequest,
    LLMGenerationResponse,
    LLMProviderCapabilities,
    LLMProviderStatusEnum,
    LLMProviderStatusResponse,
    sanitize_base_url,
    utc_now_iso,
)


def build_configured_llm_provider(app_settings: Any) -> Optional[LLMProviderProtocol]:
    """Instantiate the configured local LLM provider from validated Settings."""
    provider_name = str(getattr(app_settings, "LLM_PROVIDER", "ollama") or "ollama").strip().lower()
    timeout_seconds = float(getattr(app_settings, "LLM_TIMEOUT_SECONDS", 30.0))
    max_tokens = int(getattr(app_settings, "LLM_MAX_TOKENS", 512))
    temperature = float(getattr(app_settings, "LLM_TEMPERATURE", 0.1))
    model = str(getattr(app_settings, "LLM_MODEL", "") or "").strip()
    base_url = getattr(app_settings, "LLM_BASE_URL", None)

    if provider_name == "ollama":
        return OllamaLLMProvider(
            base_url=base_url,
            model=model,
            timeout_seconds=timeout_seconds,
            max_tokens=max_tokens,
            temperature=temperature,
        )
    if provider_name == "fixture":
        return DeterministicFixtureLLMProvider(
            model=model,
            timeout_seconds=timeout_seconds,
            max_tokens=max_tokens,
            temperature=temperature,
        )
    return None


class LLMRuntimeService:
    """
    Coordinates provider resolution, sanitized readiness status checks, and bounded
    LLM generation requests without vendor SDK lock-in.
    """

    def __init__(
        self,
        *,
        settings_obj: Any = settings,
        provider: Optional[LLMProviderProtocol] = None,
    ) -> None:
        self._settings = settings_obj
        self._explicit_provider = provider

    @property
    def enabled(self) -> bool:
        return bool(getattr(self._settings, "LLM_ENABLED", False))

    @property
    def provider_name(self) -> str:
        if self._explicit_provider is not None:
            return self._explicit_provider.provider_id
        return str(getattr(self._settings, "LLM_PROVIDER", "ollama") or "ollama").strip().lower()

    @property
    def model_name(self) -> Optional[str]:
        if self._explicit_provider is not None:
            return self._explicit_provider.model_name or None
        raw = str(getattr(self._settings, "LLM_MODEL", "") or "").strip()
        return raw or None

    @property
    def timeout_seconds(self) -> float:
        return float(getattr(self._settings, "LLM_TIMEOUT_SECONDS", 30.0))

    @property
    def max_tokens(self) -> int:
        return int(getattr(self._settings, "LLM_MAX_TOKENS", 512))

    @property
    def temperature(self) -> float:
        return float(getattr(self._settings, "LLM_TEMPERATURE", 0.1))

    @property
    def sanitized_base_url(self) -> Optional[str]:
        return sanitize_base_url(getattr(self._settings, "LLM_BASE_URL", None))

    def resolve_provider(self) -> Optional[LLMProviderProtocol]:
        if self._explicit_provider is not None:
            return self._explicit_provider
        return build_configured_llm_provider(self._settings)

    async def get_status(self) -> LLMProviderStatusResponse:
        """
        Return sanitized LLM readiness state:
        disabled -> unconfigured -> ready | unavailable | error.
        Makes zero external calls when disabled or unconfigured.
        """
        provider = self.resolve_provider()
        now = utc_now_iso()
        caps = (
            provider.capabilities
            if provider is not None
            else LLMProviderCapabilities()
        )
        configured = provider.is_configured() if provider is not None else False
        reported_base = (
            getattr(provider, "base_url", None)
            if provider is not None
            else self.sanitized_base_url
        )

        if not self.enabled:
            return LLMProviderStatusResponse(
                enabled=False,
                configured=configured,
                provider=self.provider_name,
                model=self.model_name,
                base_url=reported_base,
                status=LLMProviderStatusEnum.DISABLED,
                available=False,
                timeout_seconds=self.timeout_seconds,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                capabilities=caps,
                error=None,
                checked_at=now,
            )

        if provider is None:
            return LLMProviderStatusResponse(
                enabled=True,
                configured=False,
                provider=self.provider_name,
                model=self.model_name,
                base_url=self.sanitized_base_url,
                status=LLMProviderStatusEnum.ERROR,
                available=False,
                timeout_seconds=self.timeout_seconds,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                capabilities=caps,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.PROVIDER_ERROR,
                    message=scrub_llm_error_message(
                        f"Unsupported LLM provider '{self.provider_name}'"
                    ),
                    retryable=False,
                ),
                checked_at=now,
            )

        if not configured:
            return LLMProviderStatusResponse(
                enabled=True,
                configured=False,
                provider=provider.provider_id,
                model=provider.model_name or None,
                base_url=reported_base,
                status=LLMProviderStatusEnum.UNCONFIGURED,
                available=False,
                timeout_seconds=self.timeout_seconds,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                capabilities=provider.capabilities,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.UNCONFIGURED,
                    message="LLM provider is enabled but missing model or base URL configuration",
                    retryable=False,
                ),
                checked_at=now,
            )

        try:
            return await asyncio.wait_for(
                provider.check_readiness(timeout_seconds=self.timeout_seconds),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError:
            return LLMProviderStatusResponse(
                enabled=True,
                configured=True,
                provider=provider.provider_id,
                model=provider.model_name or None,
                base_url=reported_base,
                status=LLMProviderStatusEnum.UNAVAILABLE,
                available=False,
                timeout_seconds=self.timeout_seconds,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                capabilities=provider.capabilities,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.TIMEOUT,
                    message=f"LLM readiness check timed out after {self.timeout_seconds:.1f}s",
                    retryable=True,
                ),
                checked_at=now,
            )
        except Exception as exc:
            return LLMProviderStatusResponse(
                enabled=True,
                configured=True,
                provider=provider.provider_id,
                model=provider.model_name or None,
                base_url=reported_base,
                status=LLMProviderStatusEnum.ERROR,
                available=False,
                timeout_seconds=self.timeout_seconds,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                capabilities=provider.capabilities,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.PROVIDER_ERROR,
                    message=scrub_llm_error_message(
                        f"LLM readiness check failed: {type(exc).__name__}"
                    ),
                    retryable=False,
                ),
                checked_at=now,
            )

    async def generate(self, request: LLMGenerationRequest) -> LLMGenerationResponse:
        """Execute a bounded generation call enforcing enabled/configured guards and timeout."""
        model = (request.model or self.model_name or "").strip()
        if not self.enabled:
            return LLMGenerationResponse(
                provider=self.provider_name,
                model=model,
                ok=False,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.DISABLED,
                    message="LLM runtime is disabled",
                    retryable=False,
                ),
            )

        provider = self.resolve_provider()
        if provider is None:
            return LLMGenerationResponse(
                provider=self.provider_name,
                model=model,
                ok=False,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.PROVIDER_ERROR,
                    message=scrub_llm_error_message(
                        f"Unsupported LLM provider '{self.provider_name}'"
                    ),
                    retryable=False,
                ),
            )

        if not provider.is_configured():
            return LLMGenerationResponse(
                provider=provider.provider_id,
                model=model,
                ok=False,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.UNCONFIGURED,
                    message="LLM provider is not configured",
                    retryable=False,
                ),
            )

        effective_timeout = (
            float(request.timeout_seconds)
            if request.timeout_seconds is not None
            else self.timeout_seconds
        )
        try:
            return await asyncio.wait_for(
                provider.generate(request),
                timeout=effective_timeout,
            )
        except asyncio.TimeoutError:
            return LLMGenerationResponse(
                provider=provider.provider_id,
                model=model or provider.model_name,
                ok=False,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.TIMEOUT,
                    message=f"LLM request timed out after {effective_timeout:.1f}s",
                    retryable=True,
                ),
            )
        except Exception as exc:
            return LLMGenerationResponse(
                provider=provider.provider_id,
                model=model or provider.model_name,
                ok=False,
                error=LLMErrorInfo(
                    category=LLMErrorCategoryEnum.PROVIDER_ERROR,
                    message=scrub_llm_error_message(
                        f"LLM provider error: {type(exc).__name__}"
                    ),
                    retryable=False,
                ),
            )
