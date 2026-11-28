"""
AutoSOC - Provider-Neutral LLM Foundation, Security Contracts & Boundary Layer (Day 12)

Exports minimized security input contracts, strict output validation,
prompt-injection boundary isolation, deterministic evaluation fixtures, and the
provider-neutral LLM interface, runtime service, and Ollama/fixture adapters.
"""

from app.llm.boundary import (
    EVENT_DATA_BEGIN_DELIMITER,
    EVENT_DATA_END_DELIMITER,
    TI_DATA_BEGIN_DELIMITER,
    TI_DATA_END_DELIMITER,
    PromptBoundaryEnvelope,
    PromptInjectionScanResult,
    TrustZoneEnum,
    build_prompt_boundary_envelope,
    scan_llm_request_for_injection,
    scan_untrusted_text,
)
from app.llm.contracts import (
    FORBIDDEN_LLM_INPUT_KEYS,
    MAX_COMMAND_LINE_PREVIEW_CHARS,
    MAX_SUMMARY_CHARS,
    MAX_TI_EVIDENCE_CHARS,
    MAX_UNCERTAIN_CONFIDENCE,
    LLMAnalysisTaskEnum,
    LLMAssessmentEnum,
    LLMMitreReference,
    LLMOutputValidationResult,
    LLMOutputValidationStatusEnum,
    LLMSafeNormalizedEventSummary,
    LLMSafeObservableInput,
    LLMSecurityAnalysisOutput,
    LLMSecurityAnalysisRequest,
    build_safe_llm_analysis_request,
    contains_forbidden_llm_input_keys,
    validate_llm_analysis_output,
    verify_ti_verdicts_unchanged,
)
from app.llm.evaluation_fixtures import (
    LLMEvaluationFixture,
    get_day12_evaluation_fixture,
    get_day12_evaluation_fixtures,
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

__all__ = [
    "EVENT_DATA_BEGIN_DELIMITER",
    "EVENT_DATA_END_DELIMITER",
    "FORBIDDEN_LLM_INPUT_KEYS",
    "FORBIDDEN_LLM_PAYLOAD_KEYS",
    "LLMAnalysisTaskEnum",
    "LLMAssessmentEnum",
    "LLMErrorCategoryEnum",
    "LLMErrorInfo",
    "LLMEvaluationFixture",
    "LLMGenerationRequest",
    "LLMGenerationResponse",
    "LLMMessage",
    "LLMMitreReference",
    "LLMOutputValidationResult",
    "LLMOutputValidationStatusEnum",
    "LLMProviderCapabilities",
    "LLMProviderProtocol",
    "LLMProviderStatusEnum",
    "LLMProviderStatusResponse",
    "LLMSafeNormalizedEventSummary",
    "LLMSafeObservableInput",
    "LLMSecurityAnalysisOutput",
    "LLMSecurityAnalysisRequest",
    "LLMTokenUsage",
    "MAX_COMMAND_LINE_PREVIEW_CHARS",
    "MAX_SUMMARY_CHARS",
    "MAX_TI_EVIDENCE_CHARS",
    "MAX_UNCERTAIN_CONFIDENCE",
    "PromptBoundaryEnvelope",
    "PromptInjectionScanResult",
    "TI_DATA_BEGIN_DELIMITER",
    "TI_DATA_END_DELIMITER",
    "TrustZoneEnum",
    "build_prompt_boundary_envelope",
    "build_safe_llm_analysis_request",
    "contains_forbidden_llm_input_keys",
    "get_day12_evaluation_fixture",
    "get_day12_evaluation_fixtures",
    "sanitize_base_url",
    "scan_llm_request_for_injection",
    "scan_untrusted_text",
    "scrub_llm_error_message",
    "validate_llm_analysis_output",
    "verify_ti_verdicts_unchanged",
]

try:
    from app.llm.ollama_adapter import (
        DeterministicFixtureLLMProvider,
        OllamaLLMProvider,
    )
    from app.llm.service import (
        LLMRuntimeService,
        build_configured_llm_provider,
    )

    __all__.extend(
        [
            "DeterministicFixtureLLMProvider",
            "LLMRuntimeService",
            "OllamaLLMProvider",
            "build_configured_llm_provider",
        ]
    )
except ImportError:
    pass
