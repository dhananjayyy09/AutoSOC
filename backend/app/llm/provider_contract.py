"""
AutoSOC - Provider-Neutral LLM Interface & Safety Helpers (Day 12)

Defines `LLMProviderProtocol` (runtime-checkable PEP 544 abstraction) and
sanitization helpers to guarantee no credentials, internal traces, or raw
security payloads ever leak through LLM error or status outputs.
"""

import re
from typing import FrozenSet, Optional, Protocol, Sequence, runtime_checkable

from app.llm.schemas import (
    LLMGenerationRequest,
    LLMGenerationResponse,
    LLMProviderCapabilities,
    LLMProviderStatusResponse,
)

FORBIDDEN_LLM_PAYLOAD_KEYS: FrozenSet[str] = frozenset(
    {
        "raw_event",
        "raw_payload",
        "raw_envelope",
        "api_key",
        "apikey",
        "secret",
        "token",
        "authorization",
        "password",
        "credentials",
        "private_key",
    }
)

_SECRET_PATTERN_RE = re.compile(
    r"(?i)(bearer\s+\S+|(?:api[_-]?key|token|secret|password|authorization)\s*[:=]\s*[^\s,;]+)"
)
_URL_CREDENTIALS_RE = re.compile(r"(https?://)([^/@:\s]+:[^/@\s]+)@")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


def scrub_llm_error_message(raw_message: Optional[str], secrets: Sequence[str] = ()) -> str:
    """
    Strip URLs credentials, bearer tokens, env secret values, stack-trace newlines,
    and control chars from error summaries. Bounded to 256 characters.
    """
    if not raw_message or not isinstance(raw_message, str):
        return "LLM provider error"
    text = raw_message
    for sec in secrets:
        if sec and len(sec) >= 4:
            text = text.replace(sec, "[REDACTED]")
    text = _URL_CREDENTIALS_RE.sub(r"\1[REDACTED]@", text)
    text = _SECRET_PATTERN_RE.sub("[REDACTED]", text)
    # Collapse newlines so multi-line tracebacks never escape to API consumers
    first_line = text.splitlines()[0] if text.splitlines() else text
    cleaned = _CONTROL_CHAR_RE.sub(" ", first_line).strip()
    if not cleaned:
        return "LLM provider error"
    return cleaned[:256]


@runtime_checkable
class LLMProviderProtocol(Protocol):
    """
    Provider-neutral async interface implemented by local (Ollama / fixture) or
    future vetted LLM adapters without coupling services to vendor SDKs.
    """

    @property
    def provider_id(self) -> str:
        """Stable lowercase provider identifier (e.g. 'ollama', 'fixture')."""
        ...

    @property
    def model_name(self) -> str:
        """Configured model identifier (empty string if unconfigured)."""
        ...

    @property
    def capabilities(self) -> LLMProviderCapabilities:
        """Static capability metadata supported by this adapter."""
        ...

    def is_configured(self) -> bool:
        """Return True when required runtime settings (endpoint/model) are valid."""
        ...

    async def check_readiness(
        self, *, timeout_seconds: Optional[float] = None
    ) -> LLMProviderStatusResponse:
        """Inspect adapter readiness safely without exposing prompts or secrets."""
        ...

    async def generate(self, request: LLMGenerationRequest) -> LLMGenerationResponse:
        """Execute a bounded generation request and return a normalized response."""
        ...
