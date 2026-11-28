"""
AutoSOC - Deterministic Fixture / Mock Threat Intelligence Provider Adapter (Day 10)

Provides `FixtureThreatIntelProvider` implementing `ThreatIntelProviderProtocol`
for development, contract validation, and deterministic testing without making
any external network calls or requiring API keys.
"""

from typing import Any, Dict, FrozenSet, Optional, Tuple

from app.events.validation import ValidationErrorCategory, ValidationIssue
from app.threat_intelligence.provider_contract import (
    ObservableLookupRequest,
    ObservableLookupResult,
    ProviderLookupStatusEnum,
    sanitize_provider_response,
    utc_now_iso,
    validate_observable_for_lookup,
)
from app.threat_intelligence.schemas import ObservableTypeEnum, ObservableVerdictEnum

ALL_SUPPORTED_OBSERVABLES: FrozenSet[ObservableTypeEnum] = frozenset(
    {
        ObservableTypeEnum.IP,
        ObservableTypeEnum.DOMAIN,
        ObservableTypeEnum.URL,
        ObservableTypeEnum.FILE_HASH,
    }
)

# Controlled synthetic test fixtures using RFC 5737 / RFC 2606 reserved indicators.
# NEVER represents live external reputation telemetry.
DEFAULT_SYNTHETIC_TI_FIXTURES: Dict[Tuple[str, str], Dict[str, Any]] = {
    ("ip", "203.0.113.99"): {
        "verdict": "malicious",
        "confidence": 0.92,
        "evidence": {
            "categories": ["c2_simulation"],
            "fixture_id": "SYNTH-IP-001",
            "note": "Controlled RFC 5737 test IP fixture",
        },
        "references": [
            {
                "source_name": "autosoc_synthetic_ti_fixture",
                "reference_id": "FIXTURE-IP-001",
            }
        ],
    },
    ("ip", "198.51.100.10"): {
        "verdict": "benign",
        "confidence": 0.85,
        "evidence": {
            "categories": ["allowlisted_scanner_simulation"],
            "fixture_id": "SYNTH-IP-002",
        },
        "references": [
            {
                "source_name": "autosoc_synthetic_ti_fixture",
                "reference_id": "FIXTURE-IP-002",
            }
        ],
    },
    ("domain", "malicious-sim.example.invalid"): {
        "verdict": "malicious",
        "confidence": 0.88,
        "evidence": {
            "categories": ["phishing_simulation"],
            "fixture_id": "SYNTH-DOM-001",
        },
        "references": [
            {
                "source_name": "autosoc_synthetic_ti_fixture",
                "reference_id": "FIXTURE-DOM-001",
            }
        ],
    },
    ("domain", "benign-cdn.example.invalid"): {
        "verdict": "benign",
        "confidence": 0.95,
        "evidence": {
            "categories": ["known_benign_fixture"],
            "fixture_id": "SYNTH-DOM-002",
        },
        "references": [
            {
                "source_name": "autosoc_synthetic_ti_fixture",
                "reference_id": "FIXTURE-DOM-002",
            }
        ],
    },
    ("url", "https://phish-sim.example.invalid/login"): {
        "verdict": "suspicious",
        "confidence": 0.70,
        "evidence": {
            "categories": ["credential_harvest_simulation"],
            "fixture_id": "SYNTH-URL-001",
        },
        "references": [
            {
                "source_name": "autosoc_synthetic_ti_fixture",
                "reference_id": "FIXTURE-URL-001",
            }
        ],
    },
    (
        "file_hash",
        "sha256:" + ("e" * 64),
    ): {
        "verdict": "malicious",
        "confidence": 0.99,
        "evidence": {
            "categories": ["synthetic_malware_hash"],
            "fixture_id": "SYNTH-HASH-001",
        },
        "references": [
            {
                "source_name": "autosoc_synthetic_ti_fixture",
                "reference_id": "FIXTURE-HASH-001",
            }
        ],
    },
    # Controlled failure-simulation fixtures for deterministic error handling tests
    ("ip", "203.0.113.250"): {"mode": "timeout"},
    ("ip", "203.0.113.251"): {"mode": "unavailable"},
    ("domain", "malformed-resp.example.invalid"): {
        "mode": "malformed_response",
        "raw_response": {"verdict": "invented_bad_verdict", "confidence": 42},
    },
}


class FixtureThreatIntelProvider:
    """
    Deterministic mock/fixture-based TI provider implementing ThreatIntelProviderProtocol.
    Makes zero network calls (`is_live_lookup=False`) and supports controlled simulation
    of found, no_result, unsupported_observable, unavailable, timeout, and malformed_response.
    """

    def __init__(
        self,
        *,
        provider_name: str = "autosoc.mock_ti_fixture",
        provider_version: str = "0.1.0",
        fixtures: Optional[Dict[Tuple[str, str], Dict[str, Any]]] = None,
        supported_types: Optional[FrozenSet[ObservableTypeEnum]] = None,
        force_status: Optional[ProviderLookupStatusEnum] = None,
    ) -> None:
        self._provider_name = provider_name
        self._provider_version = provider_version
        self._fixtures = (
            dict(fixtures) if fixtures is not None else dict(DEFAULT_SYNTHETIC_TI_FIXTURES)
        )
        self._supported_types = (
            supported_types if supported_types is not None else ALL_SUPPORTED_OBSERVABLES
        )
        self._force_status = force_status

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def provider_version(self) -> str:
        return self._provider_version

    @property
    def is_live_lookup(self) -> bool:
        return False

    @property
    def supported_observable_types(self) -> FrozenSet[ObservableTypeEnum]:
        return self._supported_types

    def lookup(
        self,
        request: ObservableLookupRequest,
        *,
        lookup_timestamp: Optional[str] = None,
    ) -> ObservableLookupResult:
        ts = lookup_timestamp or utc_now_iso()

        is_valid, obs_type, canonical_val, err_msg = validate_observable_for_lookup(
            request.observable_type, request.normalized_value
        )
        if not is_valid or obs_type is None or canonical_val is None:
            safe_type = obs_type if obs_type is not None else ObservableTypeEnum.IP
            return ObservableLookupResult(
                provider_name=self._provider_name,
                provider_version=self._provider_version,
                observable_type=safe_type,
                normalized_value="",
                lookup_status=ProviderLookupStatusEnum.FAILED
                if obs_type is not None
                else ProviderLookupStatusEnum.UNSUPPORTED_OBSERVABLE,
                verdict=ObservableVerdictEnum.UNKNOWN,
                confidence=None,
                evidence={},
                references=[],
                lookup_timestamp=ts,
                errors=[
                    ValidationIssue(
                        category=ValidationErrorCategory.INVALID_SCHEMA_TYPE
                        if obs_type is not None
                        else ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE,
                        field="normalized_value" if obs_type is not None else "observable_type",
                        message=err_msg or "Invalid observable lookup request",
                        severity="error",
                    )
                ],
                live_lookup_performed=False,
            )

        if obs_type not in self._supported_types:
            return ObservableLookupResult(
                provider_name=self._provider_name,
                provider_version=self._provider_version,
                observable_type=obs_type,
                normalized_value=canonical_val,
                lookup_status=ProviderLookupStatusEnum.UNSUPPORTED_OBSERVABLE,
                verdict=ObservableVerdictEnum.UNKNOWN,
                confidence=None,
                evidence={},
                references=[],
                lookup_timestamp=ts,
                warnings=[
                    ValidationIssue(
                        category=ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE,
                        field="observable_type",
                        message=f"Provider '{self._provider_name}' does not support '{obs_type.value}' lookups",
                        severity="warning",
                    )
                ],
                live_lookup_performed=False,
            )

        if self._force_status == ProviderLookupStatusEnum.UNAVAILABLE:
            return self._error_result(
                obs_type,
                canonical_val,
                ts,
                ProviderLookupStatusEnum.UNAVAILABLE,
                f"Provider '{self._provider_name}' is currently unavailable",
            )
        if self._force_status == ProviderLookupStatusEnum.TIMEOUT:
            return self._error_result(
                obs_type,
                canonical_val,
                ts,
                ProviderLookupStatusEnum.TIMEOUT,
                f"Provider '{self._provider_name}' lookup timed out",
            )

        entry = self._fixtures.get((obs_type.value, canonical_val))
        if entry is None:
            return ObservableLookupResult(
                provider_name=self._provider_name,
                provider_version=self._provider_version,
                observable_type=obs_type,
                normalized_value=canonical_val,
                lookup_status=ProviderLookupStatusEnum.NO_RESULT,
                verdict=ObservableVerdictEnum.UNKNOWN,
                confidence=None,
                evidence={},
                references=[],
                lookup_timestamp=ts,
                warnings=[],
                errors=[],
                live_lookup_performed=False,
            )

        mode = entry.get("mode")
        if mode == "unavailable":
            return self._error_result(
                obs_type,
                canonical_val,
                ts,
                ProviderLookupStatusEnum.UNAVAILABLE,
                f"Provider '{self._provider_name}' is currently unavailable",
            )
        if mode == "timeout":
            return self._error_result(
                obs_type,
                canonical_val,
                ts,
                ProviderLookupStatusEnum.TIMEOUT,
                f"Provider '{self._provider_name}' lookup timed out",
            )
        if mode == "malformed_response":
            return sanitize_provider_response(
                entry.get("raw_response"),
                provider_name=self._provider_name,
                provider_version=self._provider_version,
                observable_type=obs_type,
                normalized_value=canonical_val,
                live_lookup_performed=False,
                lookup_timestamp=ts,
            )

        return sanitize_provider_response(
            entry,
            provider_name=self._provider_name,
            provider_version=self._provider_version,
            observable_type=obs_type,
            normalized_value=canonical_val,
            live_lookup_performed=False,
            lookup_timestamp=ts,
        )

    def _error_result(
        self,
        obs_type: ObservableTypeEnum,
        canonical_val: str,
        ts: str,
        status: ProviderLookupStatusEnum,
        message: str,
    ) -> ObservableLookupResult:
        return ObservableLookupResult(
            provider_name=self._provider_name,
            provider_version=self._provider_version,
            observable_type=obs_type,
            normalized_value=canonical_val,
            lookup_status=status,
            verdict=ObservableVerdictEnum.UNKNOWN,
            confidence=None,
            evidence={},
            references=[],
            lookup_timestamp=ts,
            errors=[
                ValidationIssue(
                    category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                    field="provider",
                    message=message,
                    severity="error",
                )
            ],
            live_lookup_performed=False,
        )
