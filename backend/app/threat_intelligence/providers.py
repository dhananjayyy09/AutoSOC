"""
AutoSOC - Enrichment Provider Abstraction and Deterministic Local Provider (Day 9)

Defines the runtime-checkable `EnrichmentProviderProtocol` for future threat
intelligence sources and implements `DeterministicLocalEnrichmentProvider`
using strictly local, network-free, deterministic classification rules.
"""

import ipaddress
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable
from urllib.parse import urlsplit

from app.threat_intelligence.schemas import (
    EnrichedObservable,
    EnrichmentProvenance,
    ObservableClassificationEnum,
    ObservableTypeEnum,
    ObservableVerdictEnum,
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
