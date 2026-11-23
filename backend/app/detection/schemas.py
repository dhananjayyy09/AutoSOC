"""
AutoSOC - Detection Result and Alert Schemas

Authoritative data contracts for detection engine outputs, evidence structures,
and downstream alert representations.
Conforms to docs/security/detection-pipeline.md and docs/security/security-data-contract.md §5 & §6.
"""

from enum import Enum
from typing import Optional, List, Dict, Any, Union

try:
    from pydantic import BaseModel, Field, ConfigDict
    PYDANTIC_V2 = True
except ImportError:
    PYDANTIC_V2 = False

    class _FieldInfo:
        def __init__(self, default=..., default_factory=None, ge=None, le=None, description=None):
            self.default = default
            self.default_factory = default_factory
            self.ge = ge
            self.le = le
            self.description = description

    def Field(default=..., *, default_factory=None, ge=None, le=None, description=None, **kwargs: Any) -> Any:
        return _FieldInfo(default=default, default_factory=default_factory, ge=ge, le=le, description=description)

    class BaseModel:
        def __init__(self, **data: Any):
            cls = self.__class__
            annotations = getattr(cls, "__annotations__", {})
            for attr_name in annotations:
                field_def = getattr(cls, attr_name, None)
                if attr_name in data:
                    val = data[attr_name]
                elif isinstance(field_def, _FieldInfo):
                    if field_def.default_factory is not None:
                        val = field_def.default_factory()
                    elif field_def.default is not ...:
                        val = field_def.default
                    else:
                        raise ValueError(f"Missing required field: {attr_name}")
                elif field_def is not None and not isinstance(field_def, _FieldInfo):
                    val = field_def
                else:
                    raise ValueError(f"Missing required field: {attr_name}")

                if isinstance(field_def, _FieldInfo):
                    if val is not None and field_def.ge is not None and val < field_def.ge:
                        raise ValueError(f"{attr_name} must be >= {field_def.ge}, got {val}")
                    if val is not None and field_def.le is not None and val > field_def.le:
                        raise ValueError(f"{attr_name} must be <= {field_def.le}, got {val}")

                setattr(self, attr_name, val)

            for k, v in data.items():
                if k not in annotations:
                    setattr(self, k, v)

        def model_dump(self) -> Dict[str, Any]:
            res = {}
            for k, v in self.__dict__.items():
                if not k.startswith("_"):
                    if isinstance(v, BaseModel):
                        res[k] = v.model_dump()
                    elif isinstance(v, list):
                        res[k] = [
                            item.model_dump() if isinstance(item, BaseModel)
                            else (item.value if isinstance(item, Enum) else item)
                            for item in v
                        ]
                    elif isinstance(v, Enum):
                        res[k] = v.value
                    else:
                        res[k] = v
            return res

        def dict(self) -> Dict[str, Any]:
            return self.model_dump()


class DetectorTypeEnum(str, Enum):
    """Enumeration of detection engine types operating in AutoSOC."""
    RULE_SIGMA = "rule_sigma"
    ML_CLASSIFICATION = "ml_classification"
    ML_ANOMALY = "ml_anomaly"
    CORRELATION = "correlation"
    THREAT_INTEL = "threat_intel"


class AlertStatusEnum(str, Enum):
    """Lifecycle status of generated security alerts."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class EvidenceItem(BaseModel):
    """Structured evidence item supporting a detection finding."""
    field: str = Field(description="Normalized field name where indicator or anomaly occurred")
    value: Any = Field(description="Observed value in the normalized event")
    indicator: Optional[str] = Field(default=None, description="Matched indicator, pattern, or baseline reference")


class SourceEventRef(BaseModel):
    """Denormalized summary of triggering event for quick lookup without JOIN."""
    event_id: str = Field(description="UUID v4 of source NormalizedSecurityEvent")
    timestamp: str = Field(description="ISO 8601 UTC timestamp of source event")
    host: str = Field(description="Originating host identifier")
    event_type: str = Field(description="Normalized event type dot-notation")


class DetectionResult(BaseModel):
    """
    Standard output produced by any detection engine evaluating an event.
    Contract defined in docs/security/security-data-contract.md §5.
    """
    detection_id: str = Field(description="UUID v4 uniquely identifying this detection result")
    created_at: str = Field(description="ISO 8601 UTC timestamp when detection was produced")
    source_event_id: str = Field(description="UUID v4 of the NormalizedSecurityEvent that triggered detection")
    source_event_ref: SourceEventRef = Field(description="Denormalized summary of source event")
    detector_type: DetectorTypeEnum = Field(description="Type of detection mechanism")
    detector_id: str = Field(description="Identifier of specific rule (Sigma rule ID) or model ID")
    detector_version: str = Field(description="Version string of rule or model")
    severity: int = Field(default=1, ge=1, le=5, description="Detector severity (1=Info, 2=Low, 3=Med, 4=High, 5=Crit)")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score (1.0 for deterministic rule; 0.0-1.0 for ML)")
    matched_indicators: List[str] = Field(default_factory=list, description="List of matched indicators or anomaly codes")
    evidence: List[EvidenceItem] = Field(default_factory=list, description="Structured evidence items")
    mitre_tactics: List[str] = Field(default_factory=list, description="ATT&CK tactic IDs (e.g. TA0002)")
    mitre_techniques: List[str] = Field(default_factory=list, description="ATT&CK technique IDs (e.g. T1059.001)")
    explanation: Optional[str] = Field(default=None, description="Human-readable explanation of why detection fired")
    explanation_data: Optional[Dict[str, Any]] = Field(default=None, description="Structured explanation (SHAP values, rule match tree)")
    raw_score: Optional[float] = Field(default=None, description="Raw model score prior to thresholding")
    feature_snapshot: Optional[Dict[str, Any]] = Field(default=None, description="Snapshot of features used in detection for auditability")


class Alert(BaseModel):
    """
    Actionable alert produced downstream by AlertGenerator deduplicating DetectionResults.
    Contract defined in docs/security/detection-pipeline.md §3.6.
    """
    alert_id: str = Field(description="UUID v4 uniquely identifying this alert")
    created_at: str = Field(description="ISO 8601 UTC timestamp when alert was generated")
    rule_id: Optional[str] = Field(default=None, description="Triggering Sigma rule ID if rule-based")
    model_id: Optional[str] = Field(default=None, description="Triggering ML model ID if ML-based")
    title: str = Field(description="Concise human-readable alert title")
    description: str = Field(description="Detailed narrative description of the detected threat")
    severity: int = Field(default=1, ge=1, le=5, description="Alert severity integer (1-5)")
    mitre_tactics: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK tactic IDs")
    mitre_techniques: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK technique IDs")
    event_ids: List[str] = Field(default_factory=list, description="List of triggering NormalizedSecurityEvent UUIDs")
    host: str = Field(description="Affected host identifier")
    user: Optional[str] = Field(default=None, description="Target or executing user identity")
    source_ip: Optional[str] = Field(default=None, description="Network origin IP")
    destination_ip: Optional[str] = Field(default=None, description="Network target IP")
    status: AlertStatusEnum = Field(default=AlertStatusEnum.OPEN, description="Current triage lifecycle status")
    assigned_to: Optional[str] = Field(default=None, description="Analyst or agent assigned to triage")
    explanation: Optional[str] = Field(default=None, description="Synthesized or model explanation")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Operational metadata and deduplication counts")
