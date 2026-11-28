"""
AutoSOC - Enrichment Provider Abstraction and Deterministic Local Provider (Day 9)

Defines the runtime-checkable `EnrichmentProviderProtocol` for future threat
intelligence sources and implements `DeterministicLocalEnrichmentProvider`
using strictly local, network-free, deterministic classification rules.
"""

import base64
from datetime import datetime, timezone
import ipaddress
import re
from typing import Any, Dict, FrozenSet, List, Optional, Protocol, Sequence, Tuple, runtime_checkable
from urllib.parse import urlsplit

from app.events.schemas import PYDANTIC_V2

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

if PYDANTIC_V2:
    from pydantic import SecretStr
else:
    SecretStr = None  # type: ignore[assignment,misc]

from app.threat_intelligence.schemas import (
    EnrichedObservable,
    EnrichmentProvenance,
    ObservableClassificationEnum,
    ObservableTypeEnum,
    ObservableVerdictEnum,
    ThreatIntelLookupRequest,
    ThreatIntelLookupStatusEnum,
)

# RFC 5737 (IPv4) & RFC 3849 (IPv6) documentation/test address ranges
_DOCUMENTATION_IP_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

# RFC 1918 (IPv4) & RFC 4193 (IPv6 ULA) private networks
_PRIVATE_IP_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)

_INTERNAL_DOMAIN_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".home",
    ".arpa",
    ".localdomain",
)

_RESERVED_TEST_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "localhost",
)

_RESERVED_TEST_SUFFIXES = (
    ".invalid",
    ".test",
    ".example",
    ".localhost",
)


@runtime_checkable
class EnrichmentProviderProtocol(Protocol):
    """
    Interface for local or future external threat-intelligence enrichment providers.
    Implementations must never mutate source event evidence or execute observable values.
    """

    @property
    def provider_id(self) -> str:
        """Unique stable provider identifier."""
        ...

    @property
    def provider_version(self) -> str:
        """Semantic version of the enrichment provider."""
        ...

    @property
    def is_live_lookup(self) -> bool:
        """False for offline/deterministic providers; True for external TI lookups."""
        ...

    def supports_observable(self, observable_type: ObservableTypeEnum) -> bool:
        """Return True if this provider can classify/enrich the given observable type."""
        ...

    def enrich_observable(
        self,
        *,
        observable_type: ObservableTypeEnum,
        normalized_value: str,
        original_value: str,
        source_fields: List[str],
        original_values: List[str],
        source_event_id: Optional[str],
        ingestion_id: str,
    ) -> Optional[EnrichedObservable]:
        """Produce a structured EnrichedObservable with provenance, or None if unsupported."""
        ...


def _classify_ip(normalized_value: str) -> Tuple[ObservableClassificationEnum, Dict[str, Any], str]:
    ip_obj = ipaddress.ip_address(normalized_value)
    is_internal = False

    if ip_obj.is_loopback:
        classification = ObservableClassificationEnum.LOOPBACK
        is_internal = True
        evidence = f"IPv{ip_obj.version} address {normalized_value} is a loopback address"
    elif ip_obj.is_link_local:
        classification = ObservableClassificationEnum.LINK_LOCAL
        is_internal = True
        evidence = f"IPv{ip_obj.version} address {normalized_value} is a link-local address"
    elif ip_obj.is_multicast:
        classification = ObservableClassificationEnum.MULTICAST
        evidence = f"IPv{ip_obj.version} address {normalized_value} is a multicast address"
    elif any(ip_obj in net for net in _DOCUMENTATION_IP_NETWORKS):
        classification = ObservableClassificationEnum.DOCUMENTATION_TEST
        evidence = (
            f"IPv{ip_obj.version} address {normalized_value} falls within an RFC 5737/3849 "
            "documentation/test range"
        )
    elif any(ip_obj in net for net in _PRIVATE_IP_NETWORKS):
        classification = ObservableClassificationEnum.PRIVATE_RFC1918
        is_internal = True
        evidence = (
            f"IPv{ip_obj.version} address {normalized_value} falls within a private internal "
            "network range (RFC 1918 / RFC 4193)"
        )
    elif ip_obj.is_reserved or ip_obj.is_unspecified:
        classification = ObservableClassificationEnum.RESERVED
        evidence = f"IPv{ip_obj.version} address {normalized_value} is a reserved/unspecified address"
    elif ip_obj.is_global:
        classification = ObservableClassificationEnum.PUBLIC_ROUTABLE
        evidence = (
            f"IPv{ip_obj.version} address {normalized_value} is globally routable; "
            "no live reputation lookup performed"
        )
    else:
        classification = ObservableClassificationEnum.RESERVED
        evidence = f"IPv{ip_obj.version} address {normalized_value} is non-global/special-use"

    context = {
        "ip_version": ip_obj.version,
        "is_internal": is_internal,
        "is_global": bool(ip_obj.is_global and not any(ip_obj in net for net in _DOCUMENTATION_IP_NETWORKS)),
        "is_loopback": bool(ip_obj.is_loopback),
        "is_multicast": bool(ip_obj.is_multicast),
    }
    return classification, context, evidence


def _classify_domain(normalized_value: str) -> Tuple[ObservableClassificationEnum, Dict[str, Any], str]:
    labels = normalized_value.split(".")
    tld = labels[-1] if len(labels) > 1 else None

    if normalized_value in _RESERVED_TEST_DOMAINS or normalized_value.endswith(_RESERVED_TEST_SUFFIXES):
        classification = ObservableClassificationEnum.RESERVED_TEST_DOMAIN
        evidence = (
            f"Domain '{normalized_value}' matches an RFC 2606/6761 reserved/test domain"
        )
    elif len(labels) == 1 or normalized_value.endswith(_INTERNAL_DOMAIN_SUFFIXES):
        classification = ObservableClassificationEnum.INTERNAL_OR_LOCAL
        evidence = (
            f"Domain '{normalized_value}' is single-label or uses an internal/local suffix"
        )
    else:
        classification = ObservableClassificationEnum.EXTERNAL_FQDN
        evidence = (
            f"Domain '{normalized_value}' has external FQDN syntax (TLD '.{tld}'); "
            "no live reputation lookup performed"
        )

    context = {
        "label_count": len(labels),
        "tld": tld,
        "is_internal_suffix": classification == ObservableClassificationEnum.INTERNAL_OR_LOCAL,
        "is_reserved_test": classification == ObservableClassificationEnum.RESERVED_TEST_DOMAIN,
    }
    return classification, context, evidence


def _classify_url(normalized_value: str) -> Tuple[ObservableClassificationEnum, Dict[str, Any], str]:
    parsed = urlsplit(normalized_value)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    classification = (
        ObservableClassificationEnum.URL_HTTPS
        if scheme == "https"
        else ObservableClassificationEnum.URL_HTTP
    )
    path_segments = [seg for seg in path.split("/") if seg]
    context = {
        "scheme": scheme,
        "host": host,
        "port": parsed.port,
        "has_query": bool(parsed.query),
        "path_depth": len(path_segments),
    }
    evidence = (
        f"Syntactic {scheme.upper()} URL parsed locally without fetching "
        f"(host='{host}', path_depth={len(path_segments)})"
    )
    return classification, context, evidence


def _classify_file_hash(normalized_value: str) -> Tuple[ObservableClassificationEnum, Dict[str, Any], str]:
    algo, digest = normalized_value.split(":", 1)
    if algo == "sha256":
        classification = ObservableClassificationEnum.HASH_SHA256
    elif algo == "sha1":
        classification = ObservableClassificationEnum.HASH_SHA1
    else:
        classification = ObservableClassificationEnum.HASH_MD5

    context = {
        "algorithm": algo,
        "hex_length": len(digest),
    }
    evidence = (
        f"Cryptographic {algo.upper()} digest ({len(digest)} hex chars) normalized locally; "
        "no live malware lookup performed"
    )
    return classification, context, evidence


class DeterministicLocalEnrichmentProvider:
    """
    Network-free deterministic enrichment provider implementing EnrichmentProviderProtocol.
    Extracts strictly factual classifications without inventing malicious verdicts.
    """

    _METHOD_MAP = {
        ObservableTypeEnum.IP: "deterministic_ip_classifier",
        ObservableTypeEnum.DOMAIN: "deterministic_domain_classifier",
        ObservableTypeEnum.URL: "deterministic_url_parser",
        ObservableTypeEnum.FILE_HASH: "deterministic_hash_classifier",
    }

    @property
    def provider_id(self) -> str:
        return "autosoc.deterministic_local"

    @property
    def provider_version(self) -> str:
        return "0.1.0"

    @property
    def is_live_lookup(self) -> bool:
        return False

    def supports_observable(self, observable_type: ObservableTypeEnum) -> bool:
        return observable_type in self._METHOD_MAP

    def enrich_observable(
        self,
        *,
        observable_type: ObservableTypeEnum,
        normalized_value: str,
        original_value: str,
        source_fields: List[str],
        original_values: List[str],
        source_event_id: Optional[str],
        ingestion_id: str,
    ) -> Optional[EnrichedObservable]:
        if observable_type == ObservableTypeEnum.IP:
            classification, context, evidence = _classify_ip(normalized_value)
        elif observable_type == ObservableTypeEnum.DOMAIN:
            classification, context, evidence = _classify_domain(normalized_value)
        elif observable_type == ObservableTypeEnum.URL:
            classification, context, evidence = _classify_url(normalized_value)
        elif observable_type == ObservableTypeEnum.FILE_HASH:
            classification, context, evidence = _classify_file_hash(normalized_value)
        else:
            return None

        provenance = EnrichmentProvenance(
            source_event_id=source_event_id,
            ingestion_id=ingestion_id,
            source_fields=list(source_fields),
            original_values=list(original_values),
            provider=self.provider_id,
            provider_version=self.provider_version,
            method=self._METHOD_MAP[observable_type],
            evidence=evidence,
            live_lookup_performed=self.is_live_lookup,
        )

        return EnrichedObservable(
            observable_type=observable_type,
            normalized_value=normalized_value,
            original_value=original_value,
            classification=classification,
            verdict=ObservableVerdictEnum.UNKNOWN,
            context=context,
            provenance=provenance,
        )


# ---------------------------------------------------------------------------
# Day 10 External Threat Intelligence Provider Abstraction & Adapters
# ---------------------------------------------------------------------------

_BEARER_HEADER_RE = re.compile(r"(?i)(bearer|apikey|x-apikey|key)\s*[:=]\s*[^\s,;]+")


class ThreatIntelProviderUnavailableError(RuntimeError):
    """Raised cleanly when an external TI provider returns HTTP 401/403/5xx or transport failure."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = True,
        retry_after_seconds: Optional[float] = None,
        rate_limited: bool = False,
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.retry_after_seconds = retry_after_seconds
        self.rate_limited = rate_limited


class ThreatIntelProviderRateLimitedError(ThreatIntelProviderUnavailableError):
    """Raised cleanly when an external TI provider returns HTTP 429 rate-limiting."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = True,
        retry_after_seconds: Optional[float] = None,
        rate_limited: bool = True,
    ) -> None:
        super().__init__(
            message,
            retryable=retryable,
            retry_after_seconds=retry_after_seconds,
            rate_limited=rate_limited,
        )


def _parse_retry_after(headers: Any) -> Optional[float]:
    """Safely parse numeric Retry-After header seconds into a bounded float."""
    if headers is None:
        return None
    raw = headers.get("retry-after") or headers.get("Retry-After")
    if not raw or not isinstance(raw, str):
        return None
    try:
        seconds = float(raw.strip())
    except ValueError:
        return None
    if seconds <= 0 or seconds != seconds:
        return None
    return min(3600.0, seconds)


def _raise_for_http_unavailable(provider_label: str, resp: Any) -> None:
    """Raise ThreatIntelProviderUnavailableError / RateLimitedError with metadata."""
    status_code = int(resp.status_code)
    if status_code in (401, 403):
        raise ThreatIntelProviderUnavailableError(
            f"{provider_label} HTTP {status_code} response",
            retryable=False,
            rate_limited=False,
        )
    if status_code == 429:
        raise ThreatIntelProviderRateLimitedError(
            f"{provider_label} HTTP 429 rate limit exceeded",
            retryable=True,
            retry_after_seconds=_parse_retry_after(getattr(resp, "headers", None)),
            rate_limited=True,
        )
    if status_code >= 500:
        raise ThreatIntelProviderUnavailableError(
            f"{provider_label} HTTP {status_code} response",
            retryable=True,
            retry_after_seconds=_parse_retry_after(getattr(resp, "headers", None)),
            rate_limited=False,
        )


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def scrub_secrets(text: Optional[str], secrets: Sequence[Optional[str]] = ()) -> Optional[str]:
    """Redact configured API credentials and authorization fragments from messages."""
    if not text:
        return text
    cleaned = str(text)
    for secret in secrets:
        if secret and len(secret) >= 4:
            cleaned = cleaned.replace(secret, "[REDACTED]")
    cleaned = _BEARER_HEADER_RE.sub(r"\1=[REDACTED]", cleaned)
    return cleaned[:256]


def _unwrap_secret(secret: Optional[Any]) -> Optional[str]:
    if secret is None:
        return None
    if SecretStr is not None and isinstance(secret, SecretStr):
        val = secret.get_secret_value().strip()
        return val or None
    if isinstance(secret, str):
        val = secret.strip()
        return val or None
    return None


@runtime_checkable
class ThreatIntelProviderProtocol(Protocol):
    """
    Day 10 async interface for configurable external Threat Intelligence providers.
    Implementations must return raw unvalidated dictionaries matching
    `ThreatIntelLookupResult`, never execute observables, and never leak credentials.
    """

    @property
    def provider_id(self) -> str:
        """Unique stable lowercase identifier (e.g. 'virustotal', 'abuseipdb')."""
        ...

    @property
    def provider_version(self) -> str:
        """API/adapter version string."""
        ...

    def supports_observable(self, observable_type: ObservableTypeEnum) -> bool:
        """Return True if this provider supports querying the observable type."""
        ...

    def is_configured(self) -> bool:
        """Return True when required credentials/endpoints are configured."""
        ...

    async def lookup(self, request: ThreatIntelLookupRequest) -> Dict[str, Any]:
        """Execute lookup for a single normalized observable within request.timeout_seconds."""
        ...


class VirusTotalProvider:
    """Async VirusTotal API v3 adapter supporting IP, domain, URL, and file hash lookups."""

    _SUPPORTED: FrozenSet[ObservableTypeEnum] = frozenset(
        {
            ObservableTypeEnum.IP,
            ObservableTypeEnum.DOMAIN,
            ObservableTypeEnum.URL,
            ObservableTypeEnum.FILE_HASH,
        }
    )

    def __init__(self, api_key: Optional[Any] = None, *, base_url: str = "https://www.virustotal.com/api/v3") -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")

    @property
    def provider_id(self) -> str:
        return "virustotal"

    @property
    def provider_version(self) -> str:
        return "v3"

    def supports_observable(self, observable_type: ObservableTypeEnum) -> bool:
        return observable_type in self._SUPPORTED

    def is_configured(self) -> bool:
        return _unwrap_secret(self._api_key) is not None

    def secret_values(self) -> List[str]:
        val = _unwrap_secret(self._api_key)
        return [val] if val else []

    def _build_path(self, observable_type: ObservableTypeEnum, normalized_value: str) -> str:
        if observable_type == ObservableTypeEnum.IP:
            return f"/ip_addresses/{normalized_value}"
        if observable_type == ObservableTypeEnum.DOMAIN:
            return f"/domains/{normalized_value}"
        if observable_type == ObservableTypeEnum.FILE_HASH:
            digest = normalized_value.split(":", 1)[1] if ":" in normalized_value else normalized_value
            return f"/files/{digest}"
        url_id = base64.urlsafe_b64encode(normalized_value.encode("utf-8")).decode("ascii").rstrip("=")
        return f"/urls/{url_id}"

    async def lookup(self, request: ThreatIntelLookupRequest) -> Dict[str, Any]:
        api_key = _unwrap_secret(self._api_key)
        if not api_key:
            raise ThreatIntelProviderUnavailableError("VirusTotal API key is not configured")

        path = self._build_path(request.observable_type, request.normalized_value)
        url = f"{self._base_url}{path}"
        headers = {"x-apikey": api_key, "Accept": "application/json"}

        async with httpx.AsyncClient(timeout=request.timeout_seconds, follow_redirects=False) as client:
            resp = await client.get(url, headers=headers)

        if resp.status_code == 404:
            return {
                "provider": self.provider_id,
                "provider_version": self.provider_version,
                "observable_type": request.observable_type.value,
                "normalized_value": request.normalized_value,
                "lookup_status": ThreatIntelLookupStatusEnum.NO_DATA.value,
                "verdict": ObservableVerdictEnum.UNKNOWN.value,
                "evidence": "VirusTotal returned no existing record (404)",
                "lookup_timestamp": _utc_now_iso(),
                "live_lookup_performed": True,
            }

        if resp.status_code in (401, 403, 429) or resp.status_code >= 500:
            _raise_for_http_unavailable("VirusTotal", resp)
        if resp.status_code >= 400:
            return {
                "provider": self.provider_id,
                "provider_version": self.provider_version,
                "observable_type": request.observable_type.value,
                "normalized_value": request.normalized_value,
                "lookup_status": ThreatIntelLookupStatusEnum.INVALID_RESPONSE.value,
                "verdict": ObservableVerdictEnum.UNKNOWN.value,
                "error_message": f"VirusTotal rejected query with HTTP {resp.status_code}",
                "lookup_timestamp": _utc_now_iso(),
                "live_lookup_performed": True,
            }

        payload = resp.json()
        attrs = ((payload.get("data") or {}).get("attributes") or {}) if isinstance(payload, dict) else {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + harmless + undetected

        if malicious >= 2:
            verdict = ObservableVerdictEnum.MALICIOUS
        elif malicious == 1 or suspicious >= 2:
            verdict = ObservableVerdictEnum.SUSPICIOUS
        elif total > 0 and malicious == 0 and suspicious == 0 and harmless > 0:
            verdict = ObservableVerdictEnum.BENIGN
        else:
            verdict = ObservableVerdictEnum.UNKNOWN

        confidence = round(min(1.0, (malicious + 0.5 * suspicious) / max(1, total)), 3) if total > 0 else None
        score = min(100, int(round(((malicious * 100) + (suspicious * 50)) / max(1, total)))) if total > 0 else None
        raw_cats = attrs.get("categories") or {}
        categories = list(dict.fromkeys(str(v) for v in raw_cats.values()))[:10] if isinstance(raw_cats, dict) else []

        return {
            "provider": self.provider_id,
            "provider_version": self.provider_version,
            "observable_type": request.observable_type.value,
            "normalized_value": request.normalized_value,
            "lookup_status": ThreatIntelLookupStatusEnum.SUCCESS.value,
            "verdict": verdict.value,
            "confidence": confidence,
            "score": score,
            "categories": categories,
            "evidence": (
                f"VirusTotal stats: {malicious} malicious, {suspicious} suspicious, "
                f"{harmless} harmless of {total} engines"
            ),
            "attributes": {
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "total_engines": total,
            },
            "lookup_timestamp": _utc_now_iso(),
            "live_lookup_performed": True,
        }


class AbuseIPDBProvider:
    """Async AbuseIPDB v2 adapter supporting IP reputation lookups."""

    def __init__(self, api_key: Optional[Any] = None, *, base_url: str = "https://api.abuseipdb.com/api/v2") -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")

    @property
    def provider_id(self) -> str:
        return "abuseipdb"

    @property
    def provider_version(self) -> str:
        return "v2"

    def supports_observable(self, observable_type: ObservableTypeEnum) -> bool:
        return observable_type == ObservableTypeEnum.IP

    def is_configured(self) -> bool:
        return _unwrap_secret(self._api_key) is not None

    def secret_values(self) -> List[str]:
        val = _unwrap_secret(self._api_key)
        return [val] if val else []

    async def lookup(self, request: ThreatIntelLookupRequest) -> Dict[str, Any]:
        api_key = _unwrap_secret(self._api_key)
        if not api_key:
            raise ThreatIntelProviderUnavailableError("AbuseIPDB API key is not configured")

        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": request.normalized_value, "maxAgeInDays": "90"}

        async with httpx.AsyncClient(timeout=request.timeout_seconds, follow_redirects=False) as client:
            resp = await client.get(f"{self._base_url}/check", headers=headers, params=params)

        if resp.status_code in (401, 403, 429) or resp.status_code >= 500:
            _raise_for_http_unavailable("AbuseIPDB", resp)
        if resp.status_code >= 400:
            return {
                "provider": self.provider_id,
                "provider_version": self.provider_version,
                "observable_type": request.observable_type.value,
                "normalized_value": request.normalized_value,
                "lookup_status": ThreatIntelLookupStatusEnum.INVALID_RESPONSE.value,
                "verdict": ObservableVerdictEnum.UNKNOWN.value,
                "error_message": f"AbuseIPDB rejected query with HTTP {resp.status_code}",
                "lookup_timestamp": _utc_now_iso(),
                "live_lookup_performed": True,
            }

        payload = resp.json()
        data = (payload.get("data") or {}) if isinstance(payload, dict) else {}
        abuse_score = int(data.get("abuseConfidenceScore", 0) or 0)
        total_reports = int(data.get("totalReports", 0) or 0)

        if total_reports > 0 and abuse_score >= 75:
            verdict = ObservableVerdictEnum.MALICIOUS
        elif total_reports > 0 and abuse_score >= 25:
            verdict = ObservableVerdictEnum.SUSPICIOUS
        else:
            verdict = ObservableVerdictEnum.UNKNOWN

        categories = []
        if data.get("usageType"):
            categories.append(str(data["usageType"]))
        if data.get("isp"):
            categories.append(str(data["isp"]))

        return {
            "provider": self.provider_id,
            "provider_version": self.provider_version,
            "observable_type": request.observable_type.value,
            "normalized_value": request.normalized_value,
            "lookup_status": ThreatIntelLookupStatusEnum.SUCCESS.value,
            "verdict": verdict.value,
            "confidence": round(max(0.0, min(1.0, abuse_score / 100.0)), 3),
            "score": max(0, min(100, abuse_score)),
            "categories": categories,
            "evidence": (
                f"AbuseIPDB confidence {abuse_score}% across {total_reports} reports"
                + (f" ({data.get('countryCode')})" if data.get("countryCode") else "")
            ),
            "attributes": {
                "total_reports": total_reports,
                "country_code": data.get("countryCode"),
                "is_whitelisted": data.get("isWhitelisted"),
            },
            "lookup_timestamp": _utc_now_iso(),
            "live_lookup_performed": True,
        }


class GenericHTTPThreatIntelProvider:
    """Configurable HTTP TI provider adapter for custom enterprise TI gateways."""

    _SUPPORTED: FrozenSet[ObservableTypeEnum] = frozenset(
        {
            ObservableTypeEnum.IP,
            ObservableTypeEnum.DOMAIN,
            ObservableTypeEnum.URL,
            ObservableTypeEnum.FILE_HASH,
        }
    )

    def __init__(self, *, base_url: Optional[str] = None, api_key: Optional[Any] = None) -> None:
        self._base_url = base_url.rstrip("/") if isinstance(base_url, str) and base_url.strip() else None
        self._api_key = api_key

    @property
    def provider_id(self) -> str:
        return "generic_http"

    @property
    def provider_version(self) -> str:
        return "v1"

    def supports_observable(self, observable_type: ObservableTypeEnum) -> bool:
        return observable_type in self._SUPPORTED

    def is_configured(self) -> bool:
        return self._base_url is not None

    def secret_values(self) -> List[str]:
        val = _unwrap_secret(self._api_key)
        return [val] if val else []

    async def lookup(self, request: ThreatIntelLookupRequest) -> Dict[str, Any]:
        if not self._base_url:
            raise ThreatIntelProviderUnavailableError("Generic TI base URL is not configured")

        headers: Dict[str, str] = {"Accept": "application/json"}
        api_key = _unwrap_secret(self._api_key)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        params = {
            "type": request.observable_type.value,
            "value": request.normalized_value,
        }
        async with httpx.AsyncClient(timeout=request.timeout_seconds, follow_redirects=False) as client:
            resp = await client.get(f"{self._base_url}/lookup", headers=headers, params=params)

        if resp.status_code == 404:
            return {
                "provider": self.provider_id,
                "provider_version": self.provider_version,
                "observable_type": request.observable_type.value,
                "normalized_value": request.normalized_value,
                "lookup_status": ThreatIntelLookupStatusEnum.NO_DATA.value,
                "verdict": ObservableVerdictEnum.UNKNOWN.value,
                "evidence": "Generic TI gateway returned no record (404)",
                "lookup_timestamp": _utc_now_iso(),
                "live_lookup_performed": True,
            }
        if resp.status_code in (401, 403, 429) or resp.status_code >= 500:
            _raise_for_http_unavailable("Generic TI gateway", resp)

        data = resp.json()
        if not isinstance(data, dict):
            raise ValueError("Generic TI gateway payload must be a JSON object")
        return {
            "provider": self.provider_id,
            "provider_version": self.provider_version,
            "observable_type": request.observable_type.value,
            "normalized_value": request.normalized_value,
            "lookup_status": data.get("lookup_status", ThreatIntelLookupStatusEnum.SUCCESS.value),
            "verdict": data.get("verdict", ObservableVerdictEnum.UNKNOWN.value),
            "confidence": data.get("confidence"),
            "evidence": data.get("evidence"),
            "categories": data.get("categories") or [],
            "score": data.get("score"),
            "attributes": data.get("attributes") or {},
            "lookup_timestamp": data.get("lookup_timestamp") or _utc_now_iso(),
            "live_lookup_performed": True,
        }


def _format_sync_evidence(evidence: Dict[str, Any], errors: Sequence[Any], provider_name: str) -> Optional[str]:
    if errors:
        first_msg = getattr(errors[0], "message", None)
        if isinstance(first_msg, str) and first_msg.strip():
            return first_msg.strip()[:512]
    if not isinstance(evidence, dict) or not evidence:
        return None
    parts: List[str] = []
    if isinstance(evidence.get("note"), str) and evidence["note"].strip():
        parts.append(evidence["note"].strip())
    if isinstance(evidence.get("fixture_id"), str) and evidence["fixture_id"].strip():
        parts.append(f"fixture={evidence['fixture_id'].strip()}")
    if isinstance(evidence.get("categories"), list) and evidence["categories"]:
        cats = ", ".join(str(c) for c in evidence["categories"][:5])
        parts.append(f"categories={cats}")
    if not parts:
        parts.append(f"{provider_name} supplied structured attributes ({len(evidence)} keys)")
    return "; ".join(parts)[:512]


class SyncTIProviderAdapter:
    """
    Explicit bridge adapting Pranjal's synchronous `provider_contract.ThreatIntelProviderProtocol`
    (e.g., `FixtureThreatIntelProvider`) into DJ's async `ThreatIntelOrchestrator` path.
    Preserves `is_live_lookup` (False for synthetic/mock fixtures), strict observable-only
    requests, references, and conservative verdict semantics.
    """

    def __init__(self, sync_provider: Any) -> None:
        self._sync_provider = sync_provider

    @property
    def provider_id(self) -> str:
        return str(self._sync_provider.provider_name)

    @property
    def provider_version(self) -> str:
        return str(self._sync_provider.provider_version)

    @property
    def is_live_lookup(self) -> bool:
        return bool(self._sync_provider.is_live_lookup)

    def supports_observable(self, observable_type: ObservableTypeEnum) -> bool:
        return observable_type in self._sync_provider.supported_observable_types

    def is_configured(self) -> bool:
        return True

    def is_enabled(self) -> bool:
        return bool(getattr(self._sync_provider, "is_enabled", True))

    async def lookup(self, request: ThreatIntelLookupRequest) -> Dict[str, Any]:
        from app.threat_intelligence.provider_contract import (
            ObservableLookupRequest,
            ProviderLookupStatusEnum,
        )

        # Pass strictly minimal observable-only request (never event IDs, raw payloads, or secrets)
        sync_req = ObservableLookupRequest(
            observable_type=request.observable_type,
            normalized_value=request.normalized_value,
        )
        res = self._sync_provider.lookup(sync_req)

        status_map = {
            ProviderLookupStatusEnum.FOUND: ThreatIntelLookupStatusEnum.SUCCESS,
            ProviderLookupStatusEnum.NO_RESULT: ThreatIntelLookupStatusEnum.NO_DATA,
            ProviderLookupStatusEnum.TIMEOUT: ThreatIntelLookupStatusEnum.TIMEOUT,
            ProviderLookupStatusEnum.UNAVAILABLE: ThreatIntelLookupStatusEnum.UNAVAILABLE,
            ProviderLookupStatusEnum.RATE_LIMITED: ThreatIntelLookupStatusEnum.RATE_LIMITED,
            ProviderLookupStatusEnum.RETRY_EXHAUSTED: ThreatIntelLookupStatusEnum.RETRY_EXHAUSTED,
            ProviderLookupStatusEnum.CIRCUIT_OPEN: ThreatIntelLookupStatusEnum.CIRCUIT_OPEN,
            ProviderLookupStatusEnum.PROVIDER_DISABLED: ThreatIntelLookupStatusEnum.PROVIDER_DISABLED,
            ProviderLookupStatusEnum.INVALID_OBSERVABLE: ThreatIntelLookupStatusEnum.INVALID_OBSERVABLE,
            ProviderLookupStatusEnum.MALFORMED_RESPONSE: ThreatIntelLookupStatusEnum.INVALID_RESPONSE,
            ProviderLookupStatusEnum.FAILED: ThreatIntelLookupStatusEnum.INVALID_RESPONSE,
            ProviderLookupStatusEnum.UNSUPPORTED_OBSERVABLE: ThreatIntelLookupStatusEnum.UNSUPPORTED,
            ProviderLookupStatusEnum.SKIPPED: ThreatIntelLookupStatusEnum.SKIPPED_LIMIT,
        }
        mapped_status = status_map.get(
            res.lookup_status, ThreatIntelLookupStatusEnum.INVALID_RESPONSE
        )
        evidence_text = _format_sync_evidence(res.evidence, res.errors, self.provider_id)
        if res.verdict != ObservableVerdictEnum.UNKNOWN and not evidence_text:
            evidence_text = f"{self.provider_id} returned verdict '{res.verdict.value}'"

        categories: List[str] = []
        if isinstance(res.evidence, dict) and isinstance(res.evidence.get("categories"), list):
            categories = [str(c) for c in res.evidence["categories"][:20]]

        score: Optional[int] = None
        if res.confidence is not None:
            score = max(0, min(100, int(round(res.confidence * 100))))

        error_msg = res.errors[0].message[:256] if res.errors else None
        return {
            "provider": res.provider_name,
            "provider_version": res.provider_version,
            "observable_type": res.observable_type.value,
            "normalized_value": res.normalized_value,
            "lookup_status": mapped_status.value,
            "verdict": res.verdict.value,
            "confidence": res.confidence,
            "evidence": evidence_text,
            "references": [ref.model_dump() for ref in (res.references or [])],
            "categories": categories,
            "score": score,
            "attributes": dict(res.evidence or {}),
            "lookup_timestamp": res.lookup_timestamp,
            "live_lookup_performed": bool(res.live_lookup_performed),
            "error_message": error_msg,
        }


def build_configured_ti_providers(app_settings: Any) -> Dict[str, ThreatIntelProviderProtocol]:
    """Instantiate built-in live & deterministic fixture TI adapters from validated Settings."""
    from app.threat_intelligence.mock_adapter import FixtureThreatIntelProvider

    vt = VirusTotalProvider(api_key=getattr(app_settings, "TI_VIRUSTOTAL_API_KEY", None))
    abuse = AbuseIPDBProvider(api_key=getattr(app_settings, "TI_ABUSEIPDB_API_KEY", None))
    generic = GenericHTTPThreatIntelProvider(
        base_url=getattr(app_settings, "TI_GENERIC_BASE_URL", None),
        api_key=getattr(app_settings, "TI_GENERIC_API_KEY", None),
    )
    fixture_adapter = SyncTIProviderAdapter(FixtureThreatIntelProvider())
    return {
        vt.provider_id: vt,
        abuse.provider_id: abuse,
        generic.provider_id: generic,
        "fixture": fixture_adapter,
        "mock": fixture_adapter,
        fixture_adapter.provider_id: fixture_adapter,
    }
