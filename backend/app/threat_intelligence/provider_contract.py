"""
AutoSOC - Provider-Neutral Threat Intelligence Contract & Response Sanitizer (Day 10)

Defines:
- `ProviderLookupStatusEnum`, `ObservableLookupRequest`, `ProviderReference`, `ObservableLookupResult`
- `ThreatIntelProviderProtocol` (runtime-checkable PEP 544 interface)
- Strict pre-lookup observable validation (rejects malformed indicators without coercing)
- Untrusted provider response validation & secret-stripping sanitizer
"""

from datetime import datetime, timezone
from enum import Enum
import math
import re
from typing import Any, Dict, FrozenSet, List, Optional, Protocol, Tuple, runtime_checkable
from urllib.parse import urlsplit

from app.events.schemas import BaseModel, Field
from app.events.validation import ValidationErrorCategory, ValidationIssue
from app.threat_intelligence.schemas import ObservableTypeEnum, ObservableVerdictEnum

MAX_EVIDENCE_DEPTH = 4
MAX_EVIDENCE_ITEMS = 50
MAX_EVIDENCE_STR_LEN = 512

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

_FORBIDDEN_PROVIDER_KEYS: FrozenSet[str] = frozenset(
    {
        "api_key",
        "apikey",
        "secret",
        "secret_key",
        "token",
        "access_token",
        "password",
        "authorization",
        "auth_header",
        "raw_event",
        "raw_payload",
        "credentials",
    }
)


class ProviderLookupStatusEnum(str, Enum):
    """Provider-neutral status of an observable intelligence lookup."""

    FOUND = "found"
    NO_RESULT = "no_result"
    UNSUPPORTED_OBSERVABLE = "unsupported_observable"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    MALFORMED_RESPONSE = "malformed_response"
    FAILED = "failed"
    SKIPPED = "skipped"


class ObservableLookupRequest(BaseModel):
    """
    Minimal, privacy-preserving provider lookup request containing ONLY
    the validated observable type and normalized value.
    Never carries raw events, full normalized events, credentials, or PII.
    """

    observable_type: ObservableTypeEnum = Field(description="Validated observable category")
    normalized_value: str = Field(description="Canonical normalized observable string")


class ProviderReference(BaseModel):
    """Source or reference metadata returned by a threat-intelligence provider."""

    source_name: str = Field(description="Originating feed or report source name")
    reference_id: Optional[str] = Field(
        default=None, description="Provider report or record identifier"
    )
    reference_url: Optional[str] = Field(
        default=None, description="Validated http/https reference URL if supplied"
    )


class ObservableLookupResult(BaseModel):
    """
    Provider-neutral intelligence lookup response normalized for downstream
    enrichment pipelines without vendor coupling.
    """

    provider_name: str = Field(description="Stable identifier of the TI provider")
    provider_version: str = Field(description="Version of the TI provider/adapter")
    observable_type: ObservableTypeEnum = Field(description="Requested observable type")
    normalized_value: str = Field(description="Canonical normalized observable value")
    lookup_status: ProviderLookupStatusEnum = Field(
        description="Structured lookup outcome status"
    )
    verdict: ObservableVerdictEnum = Field(
        default=ObservableVerdictEnum.UNKNOWN,
        description="Conservative reputation verdict ('unknown' unless provider supplies evidence)",
    )
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Provider confidence in [0.0, 1.0]; None when omitted or unavailable",
    )
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized structured supporting attributes from provider",
    )
    references: List[ProviderReference] = Field(
        default_factory=list,
        description="Sanitized source/reference metadata supplied by provider",
    )
    lookup_timestamp: str = Field(
        description="ISO 8601 UTC timestamp when lookup executed"
    )
    warnings: List[ValidationIssue] = Field(
        default_factory=list, description="Non-blocking lookup warnings"
    )
    errors: List[ValidationIssue] = Field(
        default_factory=list, description="Structured lookup errors"
    )
    live_lookup_performed: bool = Field(
        default=False,
        description="True only if an actual live external lookup occurred",
    )


@runtime_checkable
class ThreatIntelProviderProtocol(Protocol):
    """
    Runtime-checkable interface for mock, local, or future external TI providers.
    Implementations must accept ObservableLookupRequest (never full events),
    perform no network calls by default in test/mock adapters, and never log secrets.
    """

    @property
    def provider_name(self) -> str:
        """Stable unique provider name."""
        ...

    @property
    def provider_version(self) -> str:
        """Semantic version of provider/adapter."""
        ...

    @property
    def is_live_lookup(self) -> bool:
        """False for mock/fixture or offline adapters; True only for live external lookups."""
        ...

    @property
    def supported_observable_types(self) -> FrozenSet[ObservableTypeEnum]:
        """Set of observable types supported by this provider."""
        ...

    def lookup(
        self,
        request: ObservableLookupRequest,
        *,
        lookup_timestamp: Optional[str] = None,
    ) -> ObservableLookupResult:
        """Execute an observable intelligence lookup and return ObservableLookupResult."""
        ...


def utc_now_iso() -> str:
    dt = datetime.now(timezone.utc)
    ms = dt.microsecond // 1000
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"


def validate_observable_for_lookup(
    observable_type: Any, raw_or_normalized_value: Any
) -> Tuple[bool, Optional[ObservableTypeEnum], Optional[str], Optional[str]]:
    """
    Validate observable_type and observable value prior to provider lookup.
    Rejects malformed inputs safely without transforming them into different indicators.
    Returns: (is_valid, parsed_type, canonical_value, error_message)
    """
    from app.threat_intelligence.enricher import (
        _normalize_domain_observable,
        _normalize_hash_observable,
        _normalize_ip_observable,
        _normalize_url_observable,
    )

    try:
        obs_type = (
            observable_type
            if isinstance(observable_type, ObservableTypeEnum)
            else ObservableTypeEnum(observable_type)
        )
    except ValueError:
        return False, None, None, "Unsupported observable_type for TI lookup"

    if obs_type == ObservableTypeEnum.IP:
        norm, err = _normalize_ip_observable(raw_or_normalized_value)
    elif obs_type == ObservableTypeEnum.DOMAIN:
        norm, err = _normalize_domain_observable(raw_or_normalized_value)
    elif obs_type == ObservableTypeEnum.URL:
        norm, err = _normalize_url_observable(raw_or_normalized_value)
    elif obs_type == ObservableTypeEnum.FILE_HASH:
        norm, err = _normalize_hash_observable(raw_or_normalized_value)
    else:
        return False, None, None, "Unsupported observable_type for TI lookup"

    if err is not None or norm is None:
        return False, obs_type, None, err or "Malformed observable value"
    return True, obs_type, norm, None


def _sanitize_value(value: Any, *, depth: int = 0) -> Any:
    """Recursively sanitize untrusted provider evidence values."""
    if depth >= MAX_EVIDENCE_DEPTH:
        return "[truncated]"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return value
    if isinstance(value, str):
        cleaned = _CONTROL_CHAR_RE.sub(" ", value).strip()
        if len(cleaned) > MAX_EVIDENCE_STR_LEN:
            return cleaned[:MAX_EVIDENCE_STR_LEN] + "..."
        return cleaned
    if isinstance(value, list):
        return [_sanitize_value(item, depth=depth + 1) for item in value[:MAX_EVIDENCE_ITEMS]]
    if isinstance(value, dict):
        sanitized: Dict[str, Any] = {}
        for count, (k, v) in enumerate(value.items()):
            if count >= MAX_EVIDENCE_ITEMS:
                break
            key_str = _CONTROL_CHAR_RE.sub("", str(k)).strip()
            if not key_str or key_str.lower() in _FORBIDDEN_PROVIDER_KEYS:
                continue
            sanitized[key_str] = _sanitize_value(v, depth=depth + 1)
        return sanitized
    return str(value)[:MAX_EVIDENCE_STR_LEN]


def _sanitize_references(raw_refs: Any) -> Tuple[Optional[List[ProviderReference]], Optional[str]]:
    if raw_refs is None:
        return [], None
    if not isinstance(raw_refs, list):
        return None, "Provider response 'references' must be a list"

    refs: List[ProviderReference] = []
    for item in raw_refs[:20]:
        if not isinstance(item, dict):
            return None, "Each provider reference entry must be an object"
        src_name = item.get("source_name")
        if not isinstance(src_name, str) or not src_name.strip():
            return None, "Provider reference missing non-empty 'source_name'"

        ref_id = item.get("reference_id")
        if ref_id is not None and not isinstance(ref_id, str):
            return None, "Provider reference 'reference_id' must be a string"

        ref_url = item.get("reference_url")
        safe_url: Optional[str] = None
        if ref_url is not None:
            if not isinstance(ref_url, str) or _CONTROL_CHAR_RE.search(ref_url):
                return None, "Provider reference 'reference_url' is invalid"
            parsed = urlsplit(ref_url.strip())
            if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
                return None, "Provider reference_url must use http/https with valid host"
            safe_url = ref_url.strip()[:MAX_EVIDENCE_STR_LEN]

        refs.append(
            ProviderReference(
                source_name=_CONTROL_CHAR_RE.sub("", src_name).strip()[:128],
                reference_id=_CONTROL_CHAR_RE.sub("", ref_id).strip()[:128] if ref_id else None,
                reference_url=safe_url,
            )
        )
    return refs, None


def sanitize_provider_response(
    raw_response: Any,
    *,
    provider_name: str,
    provider_version: str,
    observable_type: ObservableTypeEnum,
    normalized_value: str,
    live_lookup_performed: bool,
    lookup_timestamp: Optional[str] = None,
) -> ObservableLookupResult:
    """
    Validate and sanitize an untrusted raw provider response dictionary into
    an ObservableLookupResult. Returns MALFORMED_RESPONSE on structural violations.
    """
    ts = lookup_timestamp or utc_now_iso()

    def _malformed(reason: str) -> ObservableLookupResult:
        return ObservableLookupResult(
            provider_name=provider_name,
            provider_version=provider_version,
            observable_type=observable_type,
            normalized_value=normalized_value,
            lookup_status=ProviderLookupStatusEnum.MALFORMED_RESPONSE,
            verdict=ObservableVerdictEnum.UNKNOWN,
            confidence=None,
            evidence={},
            references=[],
            lookup_timestamp=ts,
            errors=[
                ValidationIssue(
                    category=ValidationErrorCategory.MALFORMED_PAYLOAD,
                    field="provider_response",
                    message=reason,
                    severity="error",
                )
            ],
            live_lookup_performed=live_lookup_performed,
        )

    if not isinstance(raw_response, dict):
        return _malformed("Provider returned non-object response")

    raw_verdict = raw_response.get("verdict")
    if raw_verdict is None:
        return _malformed("Provider response missing required 'verdict'")
    try:
        verdict = (
            raw_verdict
            if isinstance(raw_verdict, ObservableVerdictEnum)
            else ObservableVerdictEnum(str(raw_verdict).strip().lower())
        )
    except ValueError:
        return _malformed("Provider response contained unrecognized 'verdict'")

    raw_confidence = raw_response.get("confidence")
    confidence: Optional[float] = None
    if raw_confidence is not None:
        if isinstance(raw_confidence, bool) or not isinstance(raw_confidence, (int, float)):
            return _malformed("Provider response 'confidence' must be numeric in [0.0, 1.0]")
        conf_float = float(raw_confidence)
        if math.isnan(conf_float) or math.isinf(conf_float) or conf_float < 0.0 or conf_float > 1.0:
            return _malformed("Provider response 'confidence' out of range [0.0, 1.0]")
        confidence = conf_float

    raw_evidence = raw_response.get("evidence", {})
    if not isinstance(raw_evidence, dict):
        return _malformed("Provider response 'evidence' must be a JSON object")
    sanitized_evidence = _sanitize_value(raw_evidence)

    refs, ref_err = _sanitize_references(raw_response.get("references"))
    if ref_err is not None or refs is None:
        return _malformed(ref_err or "Malformed provider references")

    return ObservableLookupResult(
        provider_name=provider_name,
        provider_version=provider_version,
        observable_type=observable_type,
        normalized_value=normalized_value,
        lookup_status=ProviderLookupStatusEnum.FOUND,
        verdict=verdict,
        confidence=confidence,
        evidence=sanitized_evidence,
        references=refs,
        lookup_timestamp=ts,
        warnings=[],
        errors=[],
        live_lookup_performed=live_lookup_performed,
    )
