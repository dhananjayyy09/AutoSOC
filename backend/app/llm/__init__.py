"""
AutoSOC LLM Security Contracts & Boundary Layer Package (Day 12)

Exports minimized input contracts, strict output validation, prompt-injection
boundary isolation, and deterministic synthetic evaluation fixtures.
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

__all__ = [
    "EVENT_DATA_BEGIN_DELIMITER",
    "EVENT_DATA_END_DELIMITER",
    "TI_DATA_BEGIN_DELIMITER",
    "TI_DATA_END_DELIMITER",
    "FORBIDDEN_LLM_INPUT_KEYS",
    "MAX_COMMAND_LINE_PREVIEW_CHARS",
    "MAX_SUMMARY_CHARS",
    "MAX_TI_EVIDENCE_CHARS",
    "MAX_UNCERTAIN_CONFIDENCE",
    "LLMAnalysisTaskEnum",
    "LLMAssessmentEnum",
    "LLMEvaluationFixture",
    "LLMMitreReference",
    "LLMOutputValidationResult",
    "LLMOutputValidationStatusEnum",
    "LLMSafeNormalizedEventSummary",
    "LLMSafeObservableInput",
    "LLMSecurityAnalysisOutput",
    "LLMSecurityAnalysisRequest",
    "PromptBoundaryEnvelope",
    "PromptInjectionScanResult",
    "TrustZoneEnum",
    "build_prompt_boundary_envelope",
    "build_safe_llm_analysis_request",
    "contains_forbidden_llm_input_keys",
    "get_day12_evaluation_fixture",
    "get_day12_evaluation_fixtures",
    "scan_llm_request_for_injection",
    "scan_untrusted_text",
    "validate_llm_analysis_output",
    "verify_ti_verdicts_unchanged",
]
