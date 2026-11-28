"""
AutoSOC - LLM Cybersecurity Input & Output Contracts (Day 12)

Isolated, reusable safety and validation contracts defining:
  1. Minimized, allowlisted security inputs (`LLMSecurityAnalysisRequest`)
     constructed from normalized events and threat-intelligence enrichment
     without raw payloads, secrets, PII, or unbounded command lines.
  2. Strict structured LLM output contracts (`LLMSecurityAnalysisOutput`)
     and validators (`validate_llm_analysis_output`) that distinguish
     advisory LLM claims from authoritative deterministic/TI verdicts.

Integration Note:
  DJ's backend LLM provider contract (`backend/app/llm/`) does not exist yet
  in the shared workspace; this module serves as the canonical cybersecurity
  safety contract ready for backend LLM client integration.
"""

from enum import Enum
import json
import math
import re
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from app.events.schemas import BaseModel, Field, SourceTypeEnum
from app.events.validation import ValidationErrorCategory, ValidationIssue
try:
    from app.threat_intelligence.schemas import (
        EnrichmentStatusEnum,
        ObservableClassificationEnum,
        ObservableTypeEnum,
        ObservableVerdictEnum,
    )
except ImportError:  # Fallback when optional runtime deps (e.g., pydantic) are absent locally
    class EnrichmentStatusEnum(str, Enum):  # type: ignore[no-redef]
        ENRICHED = "enriched"
        ENRICHED_PARTIAL = "enriched_partial"
        NO_OBSERVABLES = "no_observables"
        SKIPPED = "skipped"
        FAILED = "failed"

    class ObservableTypeEnum(str, Enum):  # type: ignore[no-redef]
        IP = "ip"
        DOMAIN = "domain"
        URL = "url"
        FILE_HASH = "file_hash"

    class ObservableClassificationEnum(str, Enum):  # type: ignore[no-redef]
        PRIVATE_RFC1918 = "private_rfc1918"
        LOOPBACK = "loopback"
        LINK_LOCAL = "link_local"
        DOCUMENTATION_TEST = "documentation_test"
        MULTICAST = "multicast"
        RESERVED = "reserved"
        PUBLIC_ROUTABLE = "public_routable"
        INTERNAL_OR_LOCAL = "internal_or_local"
        RESERVED_TEST_DOMAIN = "reserved_test_domain"
        EXTERNAL_FQDN = "external_fqdn"
        URL_HTTP = "url_http"
        URL_HTTPS = "url_https"
        HASH_SHA256 = "hash_sha256"
        HASH_SHA1 = "hash_sha1"
        HASH_MD5 = "hash_md5"

    class ObservableVerdictEnum(str, Enum):  # type: ignore[no-redef]
        UNKNOWN = "unknown"
        BENIGN = "benign"
        SUSPICIOUS = "suspicious"
        MALICIOUS = "malicious"

MAX_COMMAND_LINE_PREVIEW_CHARS = 256
MAX_SUMMARY_CHARS = 1000
MAX_TI_EVIDENCE_CHARS = 512
MAX_UNCERTAIN_CONFIDENCE = 0.50

_MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_INLINE_RE = re.compile(
    r"(?i)\b(bearer|apikey|api_key|x-apikey|token|secret|password|pwd)\s*[:=]\s*[^\s,;\"']+"
)

# Fields strictly prohibited from entering LLM input payloads
FORBIDDEN_LLM_INPUT_KEYS: FrozenSet[str] = frozenset(
    {
        "raw_payload",
        "raw_event",
        "raw_envelope_id",
        "id",
        "user",
        "user_name",
        "user_domain",
        "credentials",
        "authorization",
        "api_key",
        "apikey",
        "secret",
        "secret_key",
        "token",
        "access_token",
        "password",
        "file_content",
        "file_bytes",
    }
)

# Action / instruction-override triggers disallowed in structured LLM outputs
_FORBIDDEN_OUTPUT_ACTION_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("instruction_override", re.compile(r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|system)\s+instructions?\b")),
    ("system_role_spoof", re.compile(r"(?i)(?:^|\n)\s*(?:system|<\|im_start\|>|<\|system\|>)\s*:")),
    ("unauthorized_action_trigger", re.compile(r"(?i)\b(close_incident|delete_event|block_ip|isolate_host|execute_shell|run_command|drop_table)\b")),
    ("autonomous_closure_directive", re.compile(r"(?i)\b(close\s+this\s+incident|mark\s+(it\s+)?as\s+false\s+positive\s+immediately|auto[- ]?remediate)\b")),
)


class LLMAnalysisTaskEnum(str, Enum):
    """Explicit bounded analysis tasks permitted for future LLM invocations."""

    EVENT_SUMMARY = "event_summary"
    TRIAGE_EXPLANATION = "triage_explanation"
    THREAT_INTEL_SYNTHESIS = "threat_intel_synthesis"


class LLMAssessmentEnum(str, Enum):
    """Advisory LLM assessment categories (never overwrites authoritative TI verdicts)."""

    BENIGN_CONTEXT = "benign_context"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    UNCERTAIN = "uncertain"


class LLMOutputValidationStatusEnum(str, Enum):
    """Structured outcome of validating an untrusted LLM response."""

    VALID = "valid"
    VALID_UNCERTAIN = "valid_uncertain"
    REJECTED = "rejected"


class LLMSafeObservableInput(BaseModel):
    """Minimized observable representation permitted inside an LLM analysis request."""

    observable_type: ObservableTypeEnum = Field(description="Observable type")
    normalized_value: str = Field(description="Canonical normalized observable string")
    classification: ObservableClassificationEnum = Field(
        description="Deterministic factual classification"
    )
    authoritative_verdict: ObservableVerdictEnum = Field(
        default=ObservableVerdictEnum.UNKNOWN,
        description="Authoritative Day 9-11 verdict (immutable by LLM)",
    )
    confidence: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Authoritative TI confidence if supplied"
    )
    source_fields: List[str] = Field(
        default_factory=list, description="Normalized fields that produced this observable"
    )
    ti_evidence_summary: Optional[str] = Field(
        default=None, description="Untrusted bounded TI evidence text"
    )
    references: List[Dict[str, Any]] = Field(
        default_factory=list, description="Validated TI reference metadata"
    )
    live_lookup_performed: bool = Field(
        default=False, description="Whether live external TI lookup occurred"
    )


class LLMSafeNormalizedEventSummary(BaseModel):
    """
    Allowlisted normalized event summary safe for LLM consumption.
    Omits raw_payload, raw_event, internal DB row IDs, user PII, and secrets.
    """

    event_id: str = Field(description="Normalized event UUID")
    timestamp: Optional[str] = Field(default=None, description="ISO 8601 UTC timestamp")
    source_type: SourceTypeEnum = Field(description="Telemetry source type")
    event_category: Optional[str] = Field(default=None, description="Coarse event category")
    event_type: Optional[str] = Field(default=None, description="Dot-notation event type")
    host: Optional[str] = Field(default=None, description="Originating host/sensor name")
    source_ip: Optional[str] = Field(default=None, description="Normalized source IP")
    destination_ip: Optional[str] = Field(default=None, description="Normalized destination IP")
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[str] = Field(default=None, description="Normalized protocol")
    process: Optional[str] = Field(default=None, description="Process basename only")
    domain: Optional[str] = Field(default=None, description="Normalized FQDN")
    file_hash: Optional[str] = Field(default=None, description="Prefixed cryptographic hash")
    command_line_preview: Optional[str] = Field(
        default=None,
        description="Bounded (<=256 chars), secret-redacted command line preview (untrusted)",
    )
    severity: Optional[int] = Field(default=None, ge=1, le=5)


class LLMSecurityAnalysisRequest(BaseModel):
    """Canonical safe input payload passed to future LLM providers."""

    schema_version: str = Field(default="1.0.0", description="LLM input contract version")
    task: LLMAnalysisTaskEnum = Field(description="Explicit bounded analysis task")
    event_summary: LLMSafeNormalizedEventSummary = Field(
        description="Allowlisted normalized event summary"
    )
    enrichment_status: EnrichmentStatusEnum = Field(
        default=EnrichmentStatusEnum.NO_OBSERVABLES,
        description="Deterministic enrichment status",
    )
    observables: List[LLMSafeObservableInput] = Field(
        default_factory=list, description="Minimized enriched observables"
    )
    deterministic_context: Dict[str, Any] = Field(
        default_factory=dict, description="Safe deterministic network/indicator flags"
    )
    allowed_evidence_refs: List[str] = Field(
        default_factory=list,
        description="Exhaustive allowlist of evidence reference IDs the LLM is allowed to cite",
    )
    require_uncertainty_when_insufficient: bool = Field(
        default=True,
        description="Enforces explicit uncertainty when evidence is absent or conflicting",
    )


class LLMMitreReference(BaseModel):
    """MITRE ATT&CK technique reference permitted only when tied to valid evidence refs."""

    technique_id: str = Field(description="ATT&CK ID (e.g. T1059 or T1059.001)")
    technique_name: str = Field(description="Human-readable ATT&CK technique name")
    supporting_evidence_refs: List[str] = Field(
        default_factory=list,
        description="Non-empty list of allowed_evidence_refs supporting this mapping",
    )


class LLMSecurityAnalysisOutput(BaseModel):
    """Strict structured output contract required from future LLM analysis."""

    schema_version: str = Field(default="1.0.0")
    claim_origin: str = Field(
        default="llm_advisory",
        description="Must remain 'llm_advisory' to distinguish AI claims from verified TI",
    )
    assessment: LLMAssessmentEnum = Field(description="Advisory LLM assessment")
    insufficient_evidence: bool = Field(
        description="True when available evidence cannot support a definitive conclusion"
    )
    summary: str = Field(description="Concise grounded analysis summary")
    evidence_refs: List[str] = Field(
        default_factory=list,
        description="Verified subset of request.allowed_evidence_refs",
    )
    confidence: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="LLM self-assessed confidence [0.0, 1.0]"
    )
    mitre_references: List[LLMMitreReference] = Field(
        default_factory=list,
        description="MITRE ATT&CK mappings backed by supporting_evidence_refs",
    )
    uncertainty_reason: Optional[str] = Field(
        default=None,
        description="Explicit explanation of missing or conflicting evidence when uncertain",
    )
    recommended_next_step: Optional[str] = Field(
        default=None,
        description="Read-only human analyst review note (never executable commands)",
    )


class LLMOutputValidationResult(BaseModel):
    """Structured outcome from validating a raw untrusted LLM response."""

    valid: bool = Field(description="True only if response passes all schema and safety gates")
    validation_status: LLMOutputValidationStatusEnum = Field(
        description="valid | valid_uncertain | rejected"
    )
    output: Optional[LLMSecurityAnalysisOutput] = Field(
        default=None, description="Validated output when valid is True; None if rejected"
    )
    authoritative_ti_verdicts_preserved: bool = Field(
        default=True,
        description="Always True: LLM validation never mutates authoritative TI verdicts",
    )
    errors: List[ValidationIssue] = Field(default_factory=list)
    warnings: List[ValidationIssue] = Field(default_factory=list)


def _redact_and_bound_text(text: Optional[str], max_len: int) -> Optional[str]:
    if text is None or not isinstance(text, str):
        return None
    cleaned = _CONTROL_CHAR_RE.sub(" ", text).strip()
    if not cleaned:
        return None
    redacted = _SECRET_INLINE_RE.sub(r"\1=[REDACTED]", cleaned)
    if len(redacted) > max_len:
        return redacted[: max_len - 3] + "..."
    return redacted


def _sanitize_context_dict(obj: Any, *, depth: int = 0) -> Any:
    if depth >= 3:
        return "[truncated]"
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            key_str = str(k)
            if key_str.lower() in FORBIDDEN_LLM_INPUT_KEYS:
                continue
            out[key_str] = _sanitize_context_dict(v, depth=depth + 1)
        return out
    if isinstance(obj, list):
        return [_sanitize_context_dict(item, depth=depth + 1) for item in obj[:25]]
    if isinstance(obj, str):
        return _redact_and_bound_text(obj, 256)
    return obj


def _to_dict(obj: Any) -> Dict[str, Any]:
    if isinstance(obj, dict):
        return dict(obj)
    if hasattr(obj, "model_dump") and callable(obj.model_dump):
        return obj.model_dump()
    raise TypeError("Expected dict or BaseModel instance")


def contains_forbidden_llm_input_keys(obj: Any) -> bool:
    """Recursively verify that no raw/secret/PII/internal-ID keys exist in an object."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in FORBIDDEN_LLM_INPUT_KEYS or contains_forbidden_llm_input_keys(v):
                return True
    elif isinstance(obj, list):
        return any(contains_forbidden_llm_input_keys(item) for item in obj)
    return False


def build_safe_llm_analysis_request(
    normalized_event: Any,
    enrichment_result: Optional[Any] = None,
    *,
    task: LLMAnalysisTaskEnum = LLMAnalysisTaskEnum.TRIAGE_EXPLANATION,
) -> Tuple[LLMSecurityAnalysisRequest, List[ValidationIssue]]:
    """
    Construct a minimized, allowlisted LLMSecurityAnalysisRequest from a normalized
    event and optional enrichment output. Strips raw payloads, secrets, PII, and
    unbounded command lines, and computes deterministic `allowed_evidence_refs`.
    """
    ev = _to_dict(normalized_event)
    warnings: List[ValidationIssue] = []

    raw_source = ev.get("source_type") or ev.get("source")
    source_enum = (
        raw_source
        if isinstance(raw_source, SourceTypeEnum)
        else SourceTypeEnum(str(raw_source))
    )

    event_id = ev.get("event_id")
    if not isinstance(event_id, str) or not event_id.strip():
        raise ValueError("Normalized event must contain non-empty 'event_id' for LLM analysis")

    cmd_preview = _redact_and_bound_text(
        ev.get("command_line"), MAX_COMMAND_LINE_PREVIEW_CHARS
    )
    if isinstance(ev.get("command_line"), str) and len(ev["command_line"]) > MAX_COMMAND_LINE_PREVIEW_CHARS:
        warnings.append(
            ValidationIssue(
                category=ValidationErrorCategory.PAYLOAD_TRUNCATED,
                field="command_line_preview",
                message=f"command_line truncated to {MAX_COMMAND_LINE_PREVIEW_CHARS} chars for safe LLM input",
                severity="warning",
            )
        )

    event_summary = LLMSafeNormalizedEventSummary(
        event_id=event_id.strip(),
        timestamp=ev.get("timestamp"),
        source_type=source_enum,
        event_category=ev["event_category"].value
        if hasattr(ev.get("event_category"), "value")
        else ev.get("event_category"),
        event_type=ev.get("event_type"),
        host=_redact_and_bound_text(ev.get("host"), 255),
        source_ip=ev.get("source_ip"),
        destination_ip=ev.get("destination_ip"),
        source_port=ev.get("source_port"),
        destination_port=ev.get("destination_port"),
        protocol=ev["protocol"].value
        if hasattr(ev.get("protocol"), "value")
        else ev.get("protocol"),
        process=_redact_and_bound_text(ev.get("process"), 255),
        domain=_redact_and_bound_text(ev.get("domain"), 255),
        file_hash=ev.get("file_hash"),
        command_line_preview=cmd_preview,
        severity=ev.get("severity"),
    )

    allowed_refs: List[str] = []
    for f_name in (
        "source_ip",
        "destination_ip",
        "domain",
        "file_hash",
        "process",
        "command_line_preview",
        "event_type",
    ):
        if getattr(event_summary, f_name, None) is not None:
            ref_str = f"field:{f_name}"
            if ref_str not in allowed_refs:
                allowed_refs.append(ref_str)

    safe_observables: List[LLMSafeObservableInput] = []
    enrichment_status = EnrichmentStatusEnum.NO_OBSERVABLES
    deterministic_ctx: Dict[str, Any] = {}

    if enrichment_result is not None:
        enr = _to_dict(enrichment_result)
        raw_status = enr.get("enrichment_status") or enr.get("status") or "no_observables"
        enrichment_status = (
            raw_status
            if isinstance(raw_status, EnrichmentStatusEnum)
            else EnrichmentStatusEnum(str(raw_status))
        )

        # Support both Day 9 EventEnrichmentResult (`observables`) and Day 9/10 API/service (`enrichment_data`)
        raw_obs_list = enr.get("observables")
        if raw_obs_list is None and isinstance(enr.get("enrichment_data"), dict):
            raw_obs_list = enr["enrichment_data"].get("observables", [])
            deterministic_ctx = _sanitize_context_dict(
                enr["enrichment_data"].get("context", {})
            )
        elif isinstance(enr.get("context"), dict):
            deterministic_ctx = _sanitize_context_dict(enr["context"])

        for obs_raw in raw_obs_list or []:
            obs = _to_dict(obs_raw)
            obs_type = (
                obs["observable_type"]
                if isinstance(obs.get("observable_type"), ObservableTypeEnum)
                else ObservableTypeEnum(str(obs["observable_type"]))
            )
            norm_val = str(obs["normalized_value"])
            obs_cls = (
                obs["classification"]
                if isinstance(obs.get("classification"), ObservableClassificationEnum)
                else ObservableClassificationEnum(str(obs["classification"]))
            )
            verdict = (
                obs["verdict"]
                if isinstance(obs.get("verdict"), ObservableVerdictEnum)
                else ObservableVerdictEnum(str(obs.get("verdict", "unknown")))
            )

            prov = obs.get("provenance") if isinstance(obs.get("provenance"), dict) else {}
            src_fields = list(prov.get("source_fields", []))
            ti_ev_text = obs.get("evidence_summary") or prov.get("evidence")
            refs = list(obs.get("references") or [])
            if not refs and isinstance(obs.get("context"), dict):
                ti_ctx = obs["context"].get("threat_intel")
                if isinstance(ti_ctx, dict):
                    for lookup_item in ti_ctx.get("lookups", []) or []:
                        if isinstance(lookup_item, dict):
                            refs.extend(lookup_item.get("references") or [])

            safe_refs: List[Dict[str, Any]] = []
            for r in refs[:20]:
                if isinstance(r, dict) and r.get("source_name"):
                    clean_r = _sanitize_context_dict(r)
                    safe_refs.append(clean_r)
                    if clean_r.get("reference_id"):
                        ref_key = f"ref:{clean_r['reference_id']}"
                        if ref_key not in allowed_refs:
                            allowed_refs.append(ref_key)

            obs_ref = f"obs:{obs_type.value}:{norm_val}"
            if obs_ref not in allowed_refs:
                allowed_refs.append(obs_ref)

            safe_observables.append(
                LLMSafeObservableInput(
                    observable_type=obs_type,
                    normalized_value=norm_val,
                    classification=obs_cls,
                    authoritative_verdict=verdict,
                    confidence=obs.get("confidence"),
                    source_fields=src_fields,
                    ti_evidence_summary=_redact_and_bound_text(ti_ev_text, MAX_TI_EVIDENCE_CHARS),
                    references=safe_refs,
                    live_lookup_performed=bool(
                        obs.get("live_lookup_performed")
                        if obs.get("live_lookup_performed") is not None
                        else prov.get("live_lookup_performed", False)
                    ),
                )
            )

    req = LLMSecurityAnalysisRequest(
        task=task,
        event_summary=event_summary,
        enrichment_status=enrichment_status,
        observables=safe_observables,
        deterministic_context=deterministic_ctx,
        allowed_evidence_refs=allowed_refs,
    )
    return req, warnings


def _contains_forbidden_output_directives(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    for rule_name, pattern in _FORBIDDEN_OUTPUT_ACTION_PATTERNS:
        if pattern.search(text):
            return rule_name
    return None


def validate_llm_analysis_output(
    raw_output: Any,
    request: LLMSecurityAnalysisRequest,
) -> LLMOutputValidationResult:
    """
    Strictly validate an untrusted LLM JSON string or dictionary against
    LLMSecurityAnalysisOutput and the grounding evidence in `request`.

    Rejects:
      - Malformed JSON or missing/invalid required fields
      - Responses attempting instruction overrides or autonomous action triggers
      - Unsupported evidence references outside `request.allowed_evidence_refs`
      - Unsupported or malformed MITRE ATT&CK references
      - Non-uncertain factual claims lacking supporting evidence
      - Invalid confidence scores (non-numeric, bool, NaN/Inf, out of [0,1],
        or > 0.50 when assessment is uncertain)
    """
    def _reject(category: ValidationErrorCategory, field: str, msg: str) -> LLMOutputValidationResult:
        return LLMOutputValidationResult(
            valid=False,
            validation_status=LLMOutputValidationStatusEnum.REJECTED,
            output=None,
            authoritative_ti_verdicts_preserved=True,
            errors=[
                ValidationIssue(
                    category=category,
                    field=field,
                    message=msg,
                    severity="error",
                )
            ],
        )

    if isinstance(raw_output, str):
        stripped = raw_output.strip()
        if not stripped:
            return _reject(
                ValidationErrorCategory.MALFORMED_PAYLOAD,
                "llm_output",
                "LLM output string is empty",
            )
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return _reject(
                ValidationErrorCategory.MALFORMED_PAYLOAD,
                "llm_output",
                "LLM output is not valid JSON",
            )
    elif isinstance(raw_output, dict):
        parsed = dict(raw_output)
    else:
        return _reject(
            ValidationErrorCategory.INVALID_SCHEMA_TYPE,
            "llm_output",
            "LLM output must be a JSON string or dictionary",
        )

    if not isinstance(parsed, dict):
        return _reject(
            ValidationErrorCategory.INVALID_SCHEMA_TYPE,
            "llm_output",
            "LLM output JSON root must be an object",
        )

    # Check claim_origin cannot masquerade as authoritative TI
    claim_origin = parsed.get("claim_origin", "llm_advisory")
    if claim_origin != "llm_advisory":
        return _reject(
            ValidationErrorCategory.INVALID_SCHEMA_TYPE,
            "claim_origin",
            "LLM output 'claim_origin' must be 'llm_advisory' and cannot impersonate verified TI",
        )

    raw_assessment = parsed.get("assessment")
    try:
        assessment = (
            raw_assessment
            if isinstance(raw_assessment, LLMAssessmentEnum)
            else LLMAssessmentEnum(str(raw_assessment).strip().lower())
        )
    except ValueError:
        return _reject(
            ValidationErrorCategory.INVALID_SCHEMA_TYPE,
            "assessment",
            "Invalid or missing LLM 'assessment' (allowed: benign_context, suspicious_activity, uncertain)",
        )

    insufficient_evidence = parsed.get("insufficient_evidence")
    if not isinstance(insufficient_evidence, bool):
        return _reject(
            ValidationErrorCategory.INVALID_SCHEMA_TYPE,
            "insufficient_evidence",
            "'insufficient_evidence' must be a boolean",
        )

    raw_summary = parsed.get("summary")
    if not isinstance(raw_summary, str) or not raw_summary.strip():
        return _reject(
            ValidationErrorCategory.MISSING_REQUIRED_FIELD,
            "summary",
            "LLM output missing non-empty 'summary'",
        )
    summary = _redact_and_bound_text(raw_summary, MAX_SUMMARY_CHARS) or ""

    # Guard against instruction overrides or unauthorized action directives in text fields
    for text_field_name, text_val in (
        ("summary", raw_summary),
        ("uncertainty_reason", parsed.get("uncertainty_reason")),
        ("recommended_next_step", parsed.get("recommended_next_step")),
    ):
        if text_val is not None and not isinstance(text_val, str):
            return _reject(
                ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                text_field_name,
                f"'{text_field_name}' must be a string when provided",
            )
        triggered = _contains_forbidden_output_directives(text_val)
        if triggered is not None:
            return _reject(
                ValidationErrorCategory.MALFORMED_PAYLOAD,
                text_field_name,
                f"Rejected LLM output containing disallowed {triggered} pattern in '{text_field_name}'",
            )

    # Validate confidence
    raw_conf = parsed.get("confidence")
    confidence: Optional[float] = None
    if raw_conf is not None:
        if isinstance(raw_conf, bool) or not isinstance(raw_conf, (int, float)):
            return _reject(
                ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                "confidence",
                "LLM confidence must be numeric in [0.0, 1.0]",
            )
        conf_f = float(raw_conf)
        if math.isnan(conf_f) or math.isinf(conf_f) or conf_f < 0.0 or conf_f > 1.0:
            return _reject(
                ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                "confidence",
                "LLM confidence out of valid range [0.0, 1.0]",
            )
        if (assessment == LLMAssessmentEnum.UNCERTAIN or insufficient_evidence) and conf_f > MAX_UNCERTAIN_CONFIDENCE:
            return _reject(
                ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                "confidence",
                f"Uncertain assessment cannot carry confidence > {MAX_UNCERTAIN_CONFIDENCE}",
            )
        confidence = conf_f

    # Validate evidence_refs against request.allowed_evidence_refs
    raw_refs = parsed.get("evidence_refs", [])
    if not isinstance(raw_refs, list) or not all(isinstance(r, str) for r in raw_refs):
        return _reject(
            ValidationErrorCategory.INVALID_SCHEMA_TYPE,
            "evidence_refs",
            "'evidence_refs' must be a list of strings",
        )
    allowed_set: Set[str] = set(request.allowed_evidence_refs)
    evidence_refs: List[str] = []
    for ref in raw_refs:
        cleaned_ref = ref.strip()
        if cleaned_ref not in allowed_set:
            return _reject(
                ValidationErrorCategory.INVALID_IDENTIFIER,
                "evidence_refs",
                f"Unsupported evidence reference '{cleaned_ref}' not present in request allowlist",
            )
        if cleaned_ref not in evidence_refs:
            evidence_refs.append(cleaned_ref)

    # Factual non-uncertain assessments require at least one grounded evidence_ref
    if assessment != LLMAssessmentEnum.UNCERTAIN and not insufficient_evidence and not evidence_refs:
        return _reject(
            ValidationErrorCategory.MISSING_REQUIRED_FIELD,
            "evidence_refs",
            f"Assessment '{assessment.value}' requires at least one verified evidence_ref",
        )

    # Enforce explicit uncertainty when request requires it and no TI verdict/reference supports a conclusion
    if request.require_uncertainty_when_insufficient:
        has_verdict_evidence = any(
            obs.authoritative_verdict != ObservableVerdictEnum.UNKNOWN
            or bool(obs.references)
            for obs in request.observables
        )
        has_conflict = bool(request.deterministic_context.get("has_conflicting_ti_evidence"))
        if (not has_verdict_evidence or has_conflict) and (
            assessment != LLMAssessmentEnum.UNCERTAIN or not insufficient_evidence
        ):
            return _reject(
                ValidationErrorCategory.MISSING_REQUIRED_FIELD,
                "assessment",
                "Analysis without decisive or non-conflicting TI evidence must remain uncertain (insufficient_evidence=true)",
            )

    # Validate MITRE ATT&CK references strictly
    raw_mitre = parsed.get("mitre_references", [])
    if not isinstance(raw_mitre, list):
        return _reject(
            ValidationErrorCategory.INVALID_SCHEMA_TYPE,
            "mitre_references",
            "'mitre_references' must be an array",
        )
    mitre_refs: List[LLMMitreReference] = []
    for item in raw_mitre:
        if not isinstance(item, dict):
            return _reject(
                ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                "mitre_references",
                "Each MITRE reference must be an object",
            )
        tech_id = item.get("technique_id")
        tech_name = item.get("technique_name")
        sup_refs = item.get("supporting_evidence_refs")
        if not isinstance(tech_id, str) or not _MITRE_TECHNIQUE_RE.match(tech_id.strip()):
            return _reject(
                ValidationErrorCategory.INVALID_IDENTIFIER,
                "mitre_references.technique_id",
                "Invalid MITRE ATT&CK technique_id format (expected T#### or T####.###)",
            )
        if not isinstance(tech_name, str) or not tech_name.strip():
            return _reject(
                ValidationErrorCategory.MISSING_REQUIRED_FIELD,
                "mitre_references.technique_name",
                "MITRE reference missing 'technique_name'",
            )
        if not isinstance(sup_refs, list) or not sup_refs or not all(isinstance(s, str) for s in sup_refs):
            return _reject(
                ValidationErrorCategory.MISSING_REQUIRED_FIELD,
                "mitre_references.supporting_evidence_refs",
                "MITRE ATT&CK mapping requires non-empty supporting_evidence_refs",
            )
        for s_ref in sup_refs:
            if s_ref.strip() not in allowed_set:
                return _reject(
                    ValidationErrorCategory.INVALID_IDENTIFIER,
                    "mitre_references.supporting_evidence_refs",
                    f"Unsupported MITRE supporting_evidence_ref '{s_ref.strip()}'",
                )
        mitre_refs.append(
            LLMMitreReference(
                technique_id=tech_id.strip(),
                technique_name=_redact_and_bound_text(tech_name, 128) or "",
                supporting_evidence_refs=[s.strip() for s in sup_refs],
            )
        )

    uncertainty_reason = _redact_and_bound_text(parsed.get("uncertainty_reason"), 512)
    if (assessment == LLMAssessmentEnum.UNCERTAIN or insufficient_evidence) and not uncertainty_reason:
        return _reject(
            ValidationErrorCategory.MISSING_REQUIRED_FIELD,
            "uncertainty_reason",
            "Uncertain or insufficient_evidence output requires 'uncertainty_reason'",
        )

    rec_next = _redact_and_bound_text(parsed.get("recommended_next_step"), 512)

    validated_out = LLMSecurityAnalysisOutput(
        schema_version=str(parsed.get("schema_version", "1.0.0")),
        claim_origin="llm_advisory",
        assessment=assessment,
        insufficient_evidence=insufficient_evidence,
        summary=summary,
        evidence_refs=evidence_refs,
        confidence=confidence,
        mitre_references=mitre_refs,
        uncertainty_reason=uncertainty_reason,
        recommended_next_step=rec_next,
    )

    val_status = (
        LLMOutputValidationStatusEnum.VALID_UNCERTAIN
        if (assessment == LLMAssessmentEnum.UNCERTAIN or insufficient_evidence)
        else LLMOutputValidationStatusEnum.VALID
    )
    return LLMOutputValidationResult(
        valid=True,
        validation_status=val_status,
        output=validated_out,
        authoritative_ti_verdicts_preserved=True,
        errors=[],
        warnings=[],
    )


def verify_ti_verdicts_unchanged(
    before_enrichment: Any,
    after_enrichment: Any,
) -> bool:
    """
    Confirm that authoritative TI observable verdicts and enrichment status remain
    identical before and after any LLM analysis/validation step.
    """
    b = _to_dict(before_enrichment)
    a = _to_dict(after_enrichment)
    b_obs = [(o.get("observable_type"), o.get("normalized_value"), o.get("verdict")) for o in b.get("observables", [])]
    a_obs = [(o.get("observable_type"), o.get("normalized_value"), o.get("verdict")) for o in a.get("observables", [])]
    return b_obs == a_obs and b.get("enrichment_status") == a.get("enrichment_status")
