"""
AutoSOC - Security Pipeline Interface Protocols (PEP 544)

These runtime-checkable protocols define the decoupled interfaces between
pipeline stages (Ingestion, Parsing, Normalization, Validation, Detection, Alerting).
"""

from typing import Protocol, runtime_checkable, Dict, Any, Tuple, Optional, List


@runtime_checkable
class SourceParserProtocol(Protocol):
    """Stateless pure-function parser converting raw payloads to source dictionaries."""

    def parse(
        self, raw_payload: str, source_type: str
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Parses raw text/bytes string into source-native dictionary.
        Returns: (success: bool, parsed_fields: Optional[dict], error_message: Optional[str])
        """
        ...


@runtime_checkable
class EventNormalizerProtocol(Protocol):
    """Maps parsed source fields into the normalized security event model."""

    def normalize(
        self, parsed_event: Dict[str, Any], ingestion_envelope: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Transforms source fields and transport envelope into NormalizedSecurityEvent.
        Assigns event_id, event_category, UTC timestamps, and metadata.
        """
        ...


@runtime_checkable
class EventValidatorProtocol(Protocol):
    """Validates schema structure and semantic sanity; checks deduplication state."""

    async def validate(
        self, normalized_event: Dict[str, Any]
    ) -> Tuple[str, List[str]]:
        """
        Validates event against structural and business constraints.
        Returns: (disposition: str, warnings_or_errors: List[str])
        Allowed dispositions: 'accepted', 'accepted_with_warnings', 'rejected', 'unsupported'.
        """
        ...


@runtime_checkable
class FeatureExtractorProtocol(Protocol):
    """Derives structured feature sets from validated normalized events."""

    def extract_features(self, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts categorical, network, process, file, dns, and temporal features.
        Returns: structured features dictionary.
        """
        ...


@runtime_checkable
class DetectionEngineProtocol(Protocol):
    """Evaluates rules/models against normalized events and features."""

    async def evaluate(
        self, normalized_event: Dict[str, Any], features: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Evaluates event against Sigma rules or anomaly detectors.
        Returns: List of DetectionResult dictionaries.
        """
        ...


@runtime_checkable
class AlertGeneratorProtocol(Protocol):
    """Deduplicates detection results and produces actionable Alert records."""

    async def process_detection(
        self, detection_result: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Applies sliding-window deduplication and produces an Alert record.
        Returns: Alert dict if a new alert was created, or None if count was incremented.
        """
        ...
