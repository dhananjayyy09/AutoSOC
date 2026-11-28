"""
AutoSOC - Provider-Neutral LLM Foundation Package (Day 12)
"""

from app.llm.ollama_adapter import (
    DeterministicFixtureLLMProvider,
    OllamaLLMProvider,
)
from app.llm.provider_contract import (
    FORBIDDEN_LLM_PAYLOAD_KEYS,
    LLMProviderProtocol,
    scrub_llm_error_message,
)
from app.llm.schemas import (
    LLMErrorCategoryEnum,
    LLMErrorInfo,
    LLMGenerationRequest,
    LLMGenerationResponse,
    LLMMessage,
    LLMProviderCapabilities,
    LLMProviderStatusEnum,
    LLMProviderStatusResponse,
    LLMTokenUsage,
    sanitize_base_url,
)
from app.llm.service import (
    LLMRuntimeService,
    build_configured_llm_provider,
)

__all__ = [
    "DeterministicFixtureLLMProvider",
    "FORBIDDEN_LLM_PAYLOAD_KEYS",
    "LLMErrorCategoryEnum",
    "LLMErrorInfo",
    "LLMGenerationRequest",
    "LLMGenerationResponse",
    "LLMMessage",
    "LLMProviderCapabilities",
    "LLMProviderProtocol",
    "LLMProviderStatusEnum",
    "LLMProviderStatusResponse",
    "LLMRuntimeService",
    "LLMTokenUsage",
    "OllamaLLMProvider",
    "build_configured_llm_provider",
    "sanitize_base_url",
    "scrub_llm_error_message",
]
