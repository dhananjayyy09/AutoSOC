"""
AutoSOC - Canonical LLM Provider Contract Schemas (Day 12)

Defines strictly typed, provider-neutral request, response, token usage,
capability, normalized error, and operational status contracts for local LLM runtime.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Literal, Optional
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, model_validator

from app.events.schemas import BaseModel


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sanitize_base_url(url: Optional[str]) -> Optional[str]:
    """Return scheme://host[:port][path] stripped of credentials, query, and fragments."""
    if not url or not isinstance(url, str):
        return None
    stripped = url.strip()
    if not stripped:
        return None
    try:
        parsed = urlsplit(stripped)
    except ValueError:
        return None
    if not parsed.scheme or not parsed.netloc:
        return None
    host = parsed.hostname or ""
    if not host:
        return None
    if ":" in host and not host.startswith("["):
        host_repr = f"[{host}]"
    else:
        host_repr = host
    try:
        port_part = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        return None
    clean_path = (parsed.path or "").rstrip("/")
    return f"{parsed.scheme.lower()}://{host_repr}{port_part}{clean_path}"


class LLMProviderStatusEnum(str, Enum):
    """Sanitized operational readiness state for the configured LLM runtime."""

    DISABLED = "disabled"
    UNCONFIGURED = "unconfigured"
    READY = "ready"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class LLMErrorCategoryEnum(str, Enum):
    """Sanitized, bounded failure categories (never exposes stack traces or prompts)."""

    NONE = "none"
    DISABLED = "disabled"
    UNCONFIGURED = "unconfigured"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    MODEL_NOT_FOUND = "model_not_found"
    MALFORMED_RESPONSE = "malformed_response"
    VALIDATION_ERROR = "validation_error"
    PROVIDER_ERROR = "provider_error"


class LLMErrorInfo(BaseModel):
    """Normalized, secret-free error metadata returned by LLM adapters and runtime."""

    model_config = ConfigDict(extra="forbid")

    category: LLMErrorCategoryEnum
    message: str = Field(min_length=1, max_length=256)
    retryable: bool = False


class LLMProviderCapabilities(BaseModel):
    """Declared capabilities supported by an LLM provider adapter."""

    model_config = ConfigDict(extra="forbid")

    supports_chat: bool = True
    supports_json_mode: bool = False
    supports_streaming: bool = False
    max_context_tokens: Optional[int] = Field(default=None, ge=1)


class LLMMessage(BaseModel):
    """Single structured chat turn passed to a provider adapter."""

    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=32768)


class LLMGenerationRequest(BaseModel):
    """
    Bounded, provider-neutral generation request.
    Extra keys (such as raw_event, raw_payload, credentials) are strictly rejected.
    """

    model_config = ConfigDict(extra="forbid")

    messages: List[LLMMessage] = Field(min_length=1, max_length=32)
    model: Optional[str] = Field(default=None, min_length=1, max_length=128)
    max_tokens: Optional[int] = Field(default=None, ge=1, le=32768)
    temperature: Optional[float] = Field(default=None, ge=0.0, le=2.0)
    timeout_seconds: Optional[float] = Field(default=None, gt=0.0, le=300.0)
    json_mode: bool = False


class LLMTokenUsage(BaseModel):
    """Optional token accounting metadata reported by an LLM provider."""

    model_config = ConfigDict(extra="forbid")

    prompt_tokens: Optional[int] = Field(default=None, ge=0)
    completion_tokens: Optional[int] = Field(default=None, ge=0)
    total_tokens: Optional[int] = Field(default=None, ge=0)


class LLMGenerationResponse(BaseModel):
    """Normalized generation response returned by any LLMProviderProtocol adapter."""

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(max_length=128)
    ok: bool
    content: Optional[str] = None
    usage: Optional[LLMTokenUsage] = None
    finish_reason: Optional[str] = Field(default=None, max_length=64)
    latency_ms: Optional[float] = Field(default=None, ge=0.0)
    error: Optional[LLMErrorInfo] = None
    generated_at: str = Field(default_factory=utc_now_iso, min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_outcome_invariants(self) -> "LLMGenerationResponse":
        if self.ok:
            if not self.content or not self.content.strip():
                raise ValueError("Successful LLMGenerationResponse requires non-empty content")
            if self.error is not None:
                raise ValueError("Successful LLMGenerationResponse must not contain error")
        else:
            if self.error is None:
                raise ValueError("Failed LLMGenerationResponse requires structured error")
            if self.content is not None:
                raise ValueError("Failed LLMGenerationResponse must not carry content")
        return self


class LLMProviderStatusResponse(BaseModel):
    """
    Sanitized operational readiness snapshot exposed via API.
    Never exposes credentials, prompts, generated text, or stack traces.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool
    configured: bool
    provider: str = Field(min_length=1, max_length=64)
    model: Optional[str] = Field(default=None, max_length=128)
    base_url: Optional[str] = Field(default=None, max_length=256)
    status: LLMProviderStatusEnum
    available: bool
    timeout_seconds: float = Field(gt=0.0, le=300.0)
    max_tokens: int = Field(ge=1, le=32768)
    temperature: float = Field(ge=0.0, le=2.0)
    capabilities: LLMProviderCapabilities
    error: Optional[LLMErrorInfo] = None
    checked_at: str = Field(default_factory=utc_now_iso, min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_status_invariants(self) -> "LLMProviderStatusResponse":
        if self.available and self.status != LLMProviderStatusEnum.READY:
            raise ValueError("available=True is only valid when status=='ready'")
        if self.status == LLMProviderStatusEnum.READY and not self.available:
            raise ValueError("status=='ready' requires available=True")
        return self
