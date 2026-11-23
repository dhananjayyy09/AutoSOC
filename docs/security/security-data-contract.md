# AutoSOC — Security Data Contract

**Version:** 0.2.0  
**Owner:** Pranjal (Cybersecurity Pipeline)  
**Status:** Active — Day 4 (Phase 1 Architecture Preparation)  
**Last Updated:** 2026-11-21

> **Purpose of this document:** This is the authoritative reference for the contracts governing security data as it flows through AutoSOC. It consolidates the event lifecycle, source adapter contracts, detection result contract, validation requirements, duplicate-event strategy, and architectural boundaries in one place. It is the primary input document for Phase 2 implementation.
>
> **Implementation status:** ALL sections in this document describe PLANNED architecture. Nothing in this document is implemented. The word "must" means a future implementation requirement, not a current capability.

---

## 1. Data Model Hierarchy

AutoSOC defines five distinct data objects. These are **not** interchangeable terms. Each has a precise definition and a clear owner.

```
Raw Event              — Source payload as received; never modified
  └─ Parsed Event      — Source-native fields extracted into a dict
      └─ Normalized Security Event  — Common AutoSOC schema
          ├─ Feature Set            — Derived from normalized event for detection
          └─ Detection Result       — Output of a detection rule or model
              └─ Alert              — Deduplicated, enriched detection notification
                  └─ Incident       — Correlated group of related alerts
```

| Object | Owner stage | Storage | Schema reference |
|--------|-------------|---------|-----------------|
| Raw Event | Ingestion | `raw_event` field inside Normalized Event | None (opaque string) |
| Parsed Event | Parsing | Transient (not stored independently) | Source-specific |
| Normalized Security Event | Normalization | PostgreSQL `events` table | `security-event-model.md` + Section 2 of this document |
| Feature Set | Feature Extraction | Transient or PostgreSQL `event_features` table | Section 4 of this document |
| Detection Result | Detection | PostgreSQL `detection_results` table | Section 5 of this document |
| Alert | Alert Generation | PostgreSQL `alerts` table | `detection-pipeline.md` §3.6 |
| Incident | Triage | PostgreSQL `incidents` table | `detection-pipeline.md` §3.7 |

---

## 2. Normalized Security Event Contract

This section refines and consolidates the event schema defined in `security-event-model.md`. That file remains the authoritative source for field-level documentation (formats, examples, source mappings). This section adds the Day 2 lifecycle fields and classifies every field explicitly.

### 2.1 Field Classification Summary

| Classification | Definition |
|----------------|-----------|
| **Required** | Must be present and valid; normalization rejects events missing these |
| **Optional** | Present in many but not all sources; stored as `null` when absent; never stored as empty string or default value |
| **Derived** | Computed during or after normalization; not taken directly from source |
| **Source-specific** | Meaningful only for one telemetry source; stored in `metadata.source_fields` |

### 2.2 Complete Field Table

| Field | Type | Classification | Owner | Validation Expectation |
|-------|------|----------------|-------|----------------------|
| `event_id` | `string (UUID v4)` | **Required** | Normalization layer | Valid UUID v4 format; assigned by AutoSOC, never from source |
| `ingestion_id` | `string (UUID v4)` | **Required** | Ingestion layer | Valid UUID v4; identifies this delivery attempt; distinct from `event_id` |
| `timestamp` | `string (ISO 8601 UTC)` | **Required** | Normalization layer | Parseable ISO 8601; must be UTC; must not be in future; must not be before 2000-01-01 |
| `source` | `string (enum)` | **Required** | Normalization layer | One of: `sysmon`, `zeek`, `suricata`, `windows_event_log`, `auditd`, `osquery`, `custom` |
| `event_category` | `string (enum)` | **Required** | Normalization layer | High-level category; see taxonomy §2.3 |
| `event_type` | `string (enum)` | **Required** | Normalization layer | Detailed type within category; see taxonomy in `security-event-model.md` §4.4 |
| `host` | `string` | **Required** | Normalization layer | Non-empty; hostname or FQDN |
| `severity` | `integer [1–5]` | **Required** | Normalization layer | Integer in [1, 5]; assigned by source-specific mapping, not from source directly |
| `raw_event` | `string` | **Required** | Ingestion layer | Non-empty; original source payload preserved verbatim |
| `metadata` | `object` | **Required** | Normalization layer | JSON object (may be empty `{}`); never null |
| `user` | `string \| null` | **Optional** | Normalization layer | Lowercase; domain prefix removed to `metadata.user_domain`; null for network-only events |
| `source_ip` | `string \| null` | **Optional** | Normalization layer | Canonical IPv4 dotted-decimal or RFC 5952 IPv6; null for non-network events |
| `destination_ip` | `string \| null` | **Optional** | Normalization layer | Same as `source_ip` |
| `source_port` | `integer \| null` | **Optional** | Normalization layer | Integer in [0, 65535]; null for non-network events |
| `destination_port` | `integer \| null` | **Optional** | Normalization layer | Integer in [0, 65535]; null for non-network events |
| `protocol` | `string \| null` | **Optional** | Normalization layer | Lowercase; allowed values: `tcp`, `udp`, `icmp`, `dns`, `http`, `tls`, `smtp`, `ftp`, `ssh`, `rdp`, `smb`, `other` |
| `process` | `string \| null` | **Optional** | Normalization layer | Basename only; endpoint sources only; null for network-only events |
| `file_hash` | `string \| null` | **Optional** | Normalization layer | Prefixed: `sha256:hex`; prefer SHA-256; null when no file involved |
| `domain` | `string \| null` | **Optional** | Normalization layer | Lowercase FQDN without trailing dot; null when no domain relevant |
| `command_line` | `string \| null` | **Optional** | Normalization layer | Full command string; endpoint sources only; whitespace-only → null; sensitive args redacted before storage |
| `metadata.ingest_time` | `string (ISO 8601 UTC)` | **Derived** | Ingestion layer | Time event was received by AutoSOC; always set |
| `metadata.pipeline_version` | `string` | **Derived** | Normalization layer | Version string of normalization pipeline; always set |
| `metadata.source_event_id` | `string \| null` | **Derived** | Normalization layer | Source-assigned event identifier where available (e.g., Sysmon EventRecordID, Zeek UID) |
| `metadata.raw_hash` | `string` | **Derived** | Ingestion layer | SHA-256 of the raw payload bytes; used for exact-duplicate detection |
| `metadata.source_severity` | `string \| int \| null` | **Derived** | Normalization layer | Original severity from source before normalization mapping |
| `metadata.raw_truncated` | `boolean` | **Derived** | Normalization layer | True if `raw_event` exceeded 65,536-byte limit and was truncated |
| `metadata.geo` | `object \| null` | **Derived** | Normalization layer | GeoIP result for `source_ip`: `{country, city, asn, org}` |
| `metadata.is_internal_src` | `boolean \| null` | **Derived** | Normalization layer | Whether `source_ip` is in configured internal subnet list |
| `metadata.is_internal_dst` | `boolean \| null` | **Derived** | Normalization layer | Whether `destination_ip` is in configured internal subnet list |
| `metadata.mitre_techniques` | `array of string` | **Derived** | Detection layer | ATT&CK technique IDs from fired detection rules; populated after detection |
| `metadata.threat_intel` | `object \| null` | **Derived** | Threat Intelligence layer (future) | TI enrichment result |
| `metadata.alert_id` | `string (UUID) \| null` | **Derived** | Alert Generation layer | ID of the alert derived from this event |
| `metadata.hashes` | `object \| null` | **Source-specific** | Normalization layer | Full hash map: `{md5, sha1, sha256}`; endpoint sources only |
| `metadata.pid` | `integer \| null` | **Source-specific** | Normalization layer | Process ID; Sysmon/auditd |
| `metadata.parent_pid` | `integer \| null` | **Source-specific** | Normalization layer | Parent process ID |
| `metadata.parent_process` | `string \| null` | **Source-specific** | Normalization layer | Parent process name (basename) |
| `metadata.process_path` | `string \| null` | **Source-specific** | Normalization layer | Full filesystem path of process executable |
| `metadata.user_domain` | `string \| null` | **Source-specific** | Normalization layer | Domain portion of a domain-qualified username |
| `metadata.tags` | `array of string` | **Source-specific** | Normalization layer / Analyst | Pipeline or analyst tags |
| `metadata.source_fields` | `object` | **Source-specific** | Normalization layer | Catch-all for source fields not mapped to the common schema |

### 2.3 Event Category Taxonomy

`event_category` is a new required field (Day 2 addition). It is a high-level grouping above `event_type`, enabling efficient filtering without parsing subtypes.

| `event_category` | Covered `event_type` values |
|------------------|-----------------------------|
| `process` | `process.create`, `process.terminate`, `process.inject` |
| `network` | `network.connection`, `network.dns`, `network.http`, `network.alert` |
| `file` | `file.create`, `file.modify`, `file.delete`, `file.rename` |
| `registry` | `registry.create`, `registry.modify`, `registry.delete` |
| `auth` | `auth.logon`, `auth.logoff`, `auth.failure` |
| `alert` | `alert.ids`, `alert.anomaly` |
| `unknown` | Unrecognized event types that passed through validation |

### 2.4 `ingestion_id` vs `event_id` vs `source_event_id`

This distinction is critical for deduplication and forensic traceability.

| Identifier | Assigned by | Purpose | Uniqueness |
|------------|-------------|---------|-----------|
| `ingestion_id` | Ingestion layer, per message received from transport | Identifies this specific delivery of a raw payload from the transport (Kafka message, file line, API call) | Unique per delivery attempt; replayed deliveries have a different `ingestion_id` |
| `event_id` | Normalization layer, once per successfully normalized event | Primary key of the normalized event in AutoSOC | Globally unique; generated once at normalization; never reused |
| `metadata.source_event_id` | Source (extracted by normalization) | The source's own identifier for the event (e.g., Zeek UID, Sysmon EventRecordID) | Unique within a source; not guaranteed globally unique |
| `metadata.raw_hash` | Ingestion layer, from raw payload bytes | Exact payload fingerprint for byte-level duplicate detection | Same payload → same hash |

---

## 3. Event Lifecycle

This section is the authoritative lifecycle reference. Every stage's input, transformation, output, failure behavior, and downstream consumer are defined here.

> **Status label:** Every stage below is marked with its implementation status:
> - `[CONCEPTUAL]` — Architecture agreed; no implementation exists
> - `[PLANNED Phase 2]` — Scheduled for specific Phase 2 week

### Stage 0: Telemetry Source `[CONCEPTUAL]`

**Responsibility:** External to AutoSOC.

| Attribute | Detail |
|-----------|--------|
| **Components** | Sysmon on Windows endpoints, Zeek on network sensors, Suricata on IDS sensors, authentication log agents |
| **Output** | Raw event data in source-native format: Windows XML EVTX, Zeek TSV/JSON, Suricata EVE JSON, syslog |
| **Transport** | Beats (Winlogbeat, Filebeat) → Kafka; direct file tail → Kafka; future cloud/API sources |
| **Failure behavior** | Beats agents buffer locally; Kafka provides durability; source outages are non-fatal |
| **Downstream** | Ingestion Layer |

---

### Stage 1: Ingestion Layer `[PLANNED Phase 2 — Week 4]`

**Responsibility:** Accept raw event payloads from transport, attach envelope metadata, assign `ingestion_id`, route to parsing.

| Attribute | Detail |
|-----------|--------|
| **Input** | Raw bytes from Kafka topic per source type: `autosoc.raw.sysmon`, `autosoc.raw.zeek`, `autosoc.raw.suricata`, `autosoc.raw.auth` |
| **Transformation** | 1. Validate message envelope (source_type present, non-empty payload) 2. Assign `ingestion_id` (UUID v4) 3. Record `ingest_time` (UTC) 4. Compute `raw_hash` (SHA-256 of payload bytes) 5. Publish to parsing queue |
| **Output** | Ingestion envelope: `{ingestion_id, source_type, sensor_id, ingest_time, raw_hash, raw_payload}` |
| **Infrastructure dependency** | Kafka (read from source topics); Redis (optional: ingestion dedup cache for `raw_hash`) |
| **Failure behavior** | Kafka consumer commits offset only after successful handoff to parser; failed envelopes logged to `autosoc.errors.ingestion` dead-letter topic |
| **Downstream** | Parsing Stage |
| **Security** | Input payload size limited to 65,536 bytes; oversized payloads truncated with `raw_truncated: true` before parsing |

---

### Stage 2: Parsing Stage `[PLANNED Phase 2 — Week 5]`

**Responsibility:** Transform raw payload strings into source-native structured dictionaries.

| Attribute | Detail |
|-----------|--------|
| **Input** | Ingestion envelope (Stage 1 output) |
| **Transformation** | Dispatch to source-specific parser based on `source_type`: Sysmon → XML parser, Zeek → TSV/JSON parser (per log type), Suricata → EVE JSON parser, auth → syslog/structured parser. Parser extracts source-native field names as a flat dict. |
| **Output** | `ParsedEvent`: `{ingestion_id, source_type, ingest_time, raw_hash, source_fields: dict}` |
| **Parser contract** | Each parser is a **stateless pure function**: `(raw_string, source_type) → ParsedEvent | ParseError`. No side effects. No external calls. |
| **Failure behavior** | Malformed payloads produce `ParseError{ingestion_id, error_type, raw_payload_ref}`; routed to `autosoc.errors.parse` topic; original payload preserved; never silently discarded |
| **Downstream** | Normalization Stage |

---

### Stage 3: Normalization Stage `[PLANNED Phase 2 — Week 5]`

**Responsibility:** Map `ParsedEvent` source-native fields to the AutoSOC Normalized Security Event schema.

| Attribute | Detail |
|-----------|--------|
| **Input** | `ParsedEvent` from Parsing Stage |
| **Transformation** | 1. Apply source-specific field mapping (see Section 6 of this document) 2. Assign `event_id` (UUID v4) 3. Set `event_category` from `event_type` taxonomy 4. Normalize `timestamp` to UTC ISO 8601 5. Normalize IP addresses to canonical form 6. Normalize `protocol`, `user` fields 7. Assign `severity` from source-specific mapping 8. Classify `event_type` from source event code 9. Compute derived fields: `is_internal_src`, `is_internal_dst`, GeoIP lookup 10. Place unmapped fields in `metadata.source_fields` 11. Set `metadata.pipeline_version` |
| **Output** | `NormalizedSecurityEvent` conforming to Section 2 of this document and `security-event-model.md` |
| **Idempotency** | Re-running normalization on the same `ParsedEvent` must produce the same `NormalizedSecurityEvent` (except `event_id`, which is generated once and must not change on re-processing; use `metadata.source_event_id` for idempotent replay) |
| **Failure behavior** | Schema validation errors (see Stage 4) route events to rejection queue; partial normalization failures (non-required field) log warning and store `null` for the failed field |
| **Downstream** | Validation Stage |

---

### Stage 4: Validation Stage `[PLANNED Phase 2 — Week 5]`

**Responsibility:** Enforce schema and semantic validity on the Normalized Security Event before it enters storage and detection.

> **This is a distinct stage, not embedded in normalization.** Validation is the gatekeeper between normalization and detection. Only validated events proceed to Feature Extraction.

#### 4A. Schema Validation

| Check | Action on Failure |
|-------|------------------|
| `event_id` is valid UUID v4 | Reject: route to `autosoc.errors.validation` |
| `ingestion_id` is valid UUID v4 | Reject |
| `timestamp` parses as ISO 8601 UTC | Reject |
| `source` is in allowed enum | Reject |
| `event_category` is in allowed enum | Reject |
| `event_type` is in taxonomy | Accept with `event_type = "unknown"`, original in `metadata.source_fields.original_event_type`; log warning |
| `host` is non-empty string | Reject |
| `severity` is integer in [1, 5] | Clamp to nearest bound; log warning |
| `source_ip`, `destination_ip` are valid IP or null | Set to null; log warning |
| `source_port`, `destination_port` are integer in [0, 65535] or null | Set to null; log warning |
| `raw_event` is non-empty | Reject |
| `metadata` is a JSON object | Reject |
| `protocol` is in allowed enum or null | Set to `"other"`; log warning |
| `file_hash` matches prefix pattern (`sha256:`, `sha1:`, `md5:`) or is null | Set to null; log warning |

#### 4B. Semantic / Business Validation

| Check | Action on Failure |
|-------|------------------|
| `timestamp` is not in the future (beyond 5-minute skew tolerance) | Accept with warning flag `metadata.timestamp_future: true`; log warning |
| `timestamp` is not older than 30 days (configurable) | Accept with warning flag `metadata.timestamp_stale: true`; log warning |
| `source_ip` and `destination_ip` cannot both be `null` for `network.*` event types | Accept with warning flag `metadata.network_incomplete: true` |
| `process` must be non-null for `process.*` event types | Accept with warning flag `metadata.process_incomplete: true` |
| `source_port` without `source_ip` and vice versa is inconsistent | Accept with warning flag `metadata.port_ip_mismatch: true` |
| Duplicate detection: `raw_hash` matches a recently ingested event within the dedup window | Accept with flag `metadata.possible_duplicate: true`; do NOT silently discard |

#### 4C. Event Disposition

| Disposition | Condition | Storage action |
|-------------|-----------|---------------|
| **Accepted** | Passes all schema checks; passes or accepts-with-warning semantic checks | Written to `events` table in PostgreSQL |
| **Accepted with warnings** | Passes schema; failed one or more semantic checks; has warning flags | Written to `events` table with warning flags populated |
| **Rejected** | Failed one or more schema checks | Routed to `autosoc.errors.validation` dead-letter; NOT stored in `events` table; raw payload preserved for analysis |
| **Unsupported** | Source type is `custom` or unknown; cannot determine normalization mapping | Routed to `autosoc.unsupported` topic for manual inspection |

---

### Stage 5: Feature Extraction `[PLANNED Phase 2 — Week 6]`

**Responsibility:** Derive structured features from validated Normalized Security Events for detection and future ML.

| Attribute | Detail |
|-----------|--------|
| **Input** | Validated `NormalizedSecurityEvent` from Stage 4 |
| **Transformation** | Extract features per category (see Section 4 of this document) |
| **Output** | `FeatureSet` attached as `features` sub-object on the event; optionally persisted to `event_features` table |
| **Failure behavior** | Feature extraction failures for individual features log warning and set that feature to `null`; the event is not rejected |
| **Downstream** | Detection Layer |

---

### Stage 6: Detection Layer `[PLANNED Phase 2 — Week 6]`

**Responsibility:** Evaluate normalized, validated, feature-enriched events against detection mechanisms and produce Detection Results.

| Attribute | Detail |
|-----------|--------|
| **Input** | Validated `NormalizedSecurityEvent` + `FeatureSet` |
| **Mechanisms** | 1. Rule-based (Sigma) — deterministic 2. ML-based (future) 3. Threat Intelligence enrichment (future) 4. Correlation Engine (future) |
| **Output** | `DetectionResult` (see Section 5 of this document) |
| **Failure behavior** | Detection engine failure for one mechanism does not block others; partial results are still forwarded to Alert Generation; engine failures logged with event reference |
| **Downstream** | Alert Generation |

---

### Stage 7: Alert Generation `[PLANNED Phase 2 — Week 7]`

**Responsibility:** Convert Detection Results into deduplicated, enriched Alert objects.

| Attribute | Detail |
|-----------|--------|
| **Input** | `DetectionResult` from Stage 6 |
| **Transformation** | 1. Apply deduplication window (see Section 7) 2. Enrich with MITRE ATT&CK metadata 3. Assign `alert_id` 4. Set `created_at` 5. Set initial `status = "open"` |
| **Output** | `Alert` object (schema in `detection-pipeline.md` §3.6) |
| **Infrastructure dependency** | Redis (deduplication state storage); PostgreSQL (alert persistence) |
| **Failure behavior** | Alert storage failure retried with exponential backoff; detection result preserved until alert successfully written |
| **Downstream** | Triage and Incident Creation |

---

### Stage 8: Triage and Incident Creation `[PLANNED Phase 2 — Week 7]`

**Responsibility:** Group related alerts into Incidents; drive triage with AI assistance (future) and human review.

| Attribute | Detail |
|-----------|--------|
| **Input** | `Alert` objects from Stage 7 |
| **Transformation** | 1. Correlate alerts by host, time window, rule family 2. Group into `Incident` 3. Future: LLM triage agent produces `llm_triage_summary` and `llm_recommended_actions` 4. Queue for analyst review |
| **Output** | `Incident` object (schema in `detection-pipeline.md` §3.7) |
| **Infrastructure dependency** | PostgreSQL (incident persistence); Redis (triage queue); future Qdrant (RAG for playbooks) |
| **Downstream** | SOC Dashboard (Shreyash frontend); Analyst workflow |

---

### Malformed and Rejected Event Handling

The following table is an exhaustive reference for how the pipeline handles imperfect events. **No event is silently discarded.**

| Scenario | Stage | Disposition | Storage location |
|----------|-------|-------------|-----------------|
| Oversized raw payload (>64 KiB) | Ingestion | Truncated; `raw_truncated: true`; continues | `events` table (truncated) |
| Kafka message with no source_type | Ingestion | Rejected | `autosoc.errors.ingestion` |
| XML parse failure (Sysmon) | Parsing | Rejected | `autosoc.errors.parse` |
| JSON parse failure (Suricata) | Parsing | Rejected | `autosoc.errors.parse` |
| Missing required field after normalization | Validation | Rejected | `autosoc.errors.validation` |
| Invalid IP address (non-fatal) | Validation | IP set to null, warning flag | `events` table |
| Out-of-range severity | Validation | Clamped, warning | `events` table |
| Future timestamp | Validation | Warning flag | `events` table |
| Duplicate raw hash (within dedup window) | Validation | Duplicate flag | `events` table |
| Unknown event_type | Validation | `event_type = "unknown"`, warning | `events` table |
| Unknown source type | Parsing/Normalization | Routed to unsupported | `autosoc.unsupported` |
| Feature extraction partial failure | Feature Extraction | Feature set to null, warning | `event_features` table |
| Detection engine crash | Detection | Engine failure logged; event skipped | Error log |

---

## 4. Feature Set Contract

Feature extraction produces a `features` object attached to the event. This section defines the feature schema that detection rules and future ML models will consume.

> **Status:** `[CONCEPTUAL]` — Feature schema defined here; implementation in Phase 2 Week 6.

### 4.1 Feature Categories

```json
{
  "features": {
    "categorical": {
      "event_type":           "<string>",
      "event_category":       "<string>",
      "source":               "<string>",
      "protocol":             "<string | null>",
      "severity":             "<integer>",
      "is_internal_src":      "<boolean | null>",
      "is_internal_dst":      "<boolean | null>"
    },
    "network": {
      "src_ip_private":       "<boolean | null>",
      "dst_ip_private":       "<boolean | null>",
      "dst_port_well_known":  "<boolean | null>",
      "dst_port_suspicious":  "<boolean | null>",
      "geo_country_src":      "<string | null>",
      "geo_country_dst":      "<string | null>",
      "is_external_to_internal": "<boolean | null>"
    },
    "process": {
      "process_name":               "<string | null>",
      "has_encoded_command":        "<boolean | null>",
      "command_line_length":        "<integer | null>",
      "parent_child_suspicious":    "<boolean | null>",
      "is_lolbin":                  "<boolean | null>"
    },
    "file": {
      "has_hash":             "<boolean | null>",
      "hash_known_malware":   "<boolean | null>",
      "file_extension":       "<string | null>"
    },
    "dns": {
      "domain_length":        "<integer | null>",
      "subdomain_count":      "<integer | null>",
      "tld":                  "<string | null>",
      "domain_entropy":       "<float | null>"
    },
    "temporal": {
      "hour_of_day":          "<integer | null>",
      "day_of_week":          "<integer | null>",
      "is_business_hours":    "<boolean | null>"
    }
  }
}
```

### 4.2 Feature Derivation Rules

| Feature | Source fields | Derivation |
|---------|--------------|------------|
| `has_encoded_command` | `command_line` | True if contains `-EncodedCommand`, `-enc`, or base64 patterns |
| `command_line_length` | `command_line` | `len(command_line)` or null |
| `is_lolbin` | `process` | Lookup against known LOLBIN list (certutil, regsvr32, mshta, etc.) |
| `dst_port_well_known` | `destination_port` | True if port in [0, 1023] |
| `dst_port_suspicious` | `destination_port` | True if port in configured suspicious-port list (4444, 1337, etc.) |
| `domain_entropy` | `domain` | Shannon entropy of domain string |
| `parent_child_suspicious` | `process`, `metadata.parent_process` | True if pair is in configured suspicious parent-child list |
| `is_external_to_internal` | `source_ip`, `destination_ip`, `metadata.is_internal_src`, `metadata.is_internal_dst` | True if src is external, dst is internal |

---

## 5. Detection Result Contract

This section defines the formal contract between the Detection Layer and the Alert Generation stage.

> **Status:** `[CONCEPTUAL]` — Contract defined; no detection engine exists.

### 5.1 Detection Result Schema

```json
{
  "detection_id":       "<string: UUID v4>",
  "created_at":         "<string: ISO 8601 UTC>",
  "source_event_id":    "<string: UUID v4>",
  "source_event_ref": {
    "event_id":         "<string: UUID v4>",
    "timestamp":        "<string: ISO 8601 UTC>",
    "host":             "<string>",
    "event_type":       "<string>"
  },
  "detector_type":      "<string: enum>",
  "detector_id":        "<string>",
  "detector_version":   "<string>",
  "severity":           "<integer: 1–5>",
  "confidence":         "<float: 0.0–1.0>",
  "matched_indicators": ["<string>"],
  "evidence":           [
    {
      "field":          "<string>",
      "value":          "<string>",
      "indicator":      "<string>"
    }
  ],
  "mitre_tactics":      ["<string>"],
  "mitre_techniques":   ["<string>"],
  "explanation":        "<string | null>",
  "explanation_data":   "<object | null>",
  "raw_score":          "<float | null>",
  "feature_snapshot":   "<object | null>"
}
```

### 5.2 Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `detection_id` | UUID v4 | Yes | Unique identifier for this detection result |
| `created_at` | ISO 8601 UTC | Yes | Timestamp when detection was produced |
| `source_event_id` | UUID v4 | Yes | The `event_id` of the Normalized Security Event that triggered this detection |
| `source_event_ref` | object | Yes | Denormalized summary of source event for quick lookup without JOIN |
| `detector_type` | enum | Yes | One of: `rule_sigma`, `ml_classification`, `ml_anomaly`, `correlation`, `threat_intel` |
| `detector_id` | string | Yes | Identifier of the specific rule (Sigma rule ID) or model ID |
| `detector_version` | string | Yes | Version of the rule or model that produced this result |
| `severity` | integer [1–5] | Yes | Severity assigned by the detector (may differ from event severity) |
| `confidence` | float [0.0–1.0] | Yes | Confidence score: 1.0 = deterministic rule match; < 1.0 = statistical/ML output |
| `matched_indicators` | array of string | Yes | List of specific field values or patterns that triggered the detection |
| `evidence` | array of object | Yes | Structured evidence: field + value + matched indicator |
| `mitre_tactics` | array of string | No | MITRE ATT&CK tactic IDs (e.g., `"TA0002"`) |
| `mitre_techniques` | array of string | No | MITRE ATT&CK technique IDs (e.g., `"T1059.001"`) |
| `explanation` | string \| null | No | Human-readable explanation of why this detection fired; required for rule-based; optional for ML |
| `explanation_data` | object \| null | No | Machine-readable explanation data (e.g., SHAP values for ML models) for LLM agent consumption |
| `raw_score` | float \| null | No | Raw model output score before threshold application; for ML detectors only |
| `feature_snapshot` | object \| null | No | Snapshot of features used in detection; enables reproducibility and audit |

### 5.3 `detector_type` Values

| Value | Meaning | `confidence` |
|-------|---------|-------------|
| `rule_sigma` | Sigma rule exact match | 1.0 always |
| `ml_classification` | Supervised ML classification | Model probability score |
| `ml_anomaly` | Unsupervised anomaly detection | Normalized anomaly score |
| `correlation` | Multi-event correlation pattern | Rule-defined (0.0–1.0) |
| `threat_intel` | IOC match from TI feed | Match confidence from TI source |

### 5.4 Terminology: Security Event ≠ Detection Result ≠ Alert ≠ Incident

These terms are **not** interchangeable in AutoSOC:

| Term | Definition | Cardinality |
|------|-----------|------------|
| **Security Event** | A single normalized observation from a telemetry source | 1 per raw event |
| **Detection Result** | The output of a single detection mechanism evaluating one event | N per event (multiple rules/models) |
| **Alert** | A deduplicated, enriched notification derived from one or more Detection Results | 1 per unique (detector, host, time window) |
| **Incident** | A correlated group of related Alerts representing a potential attack | 1 per correlated alert cluster |

---

## 6. Source Adapter Contracts

This section defines the conceptual adapter contract for each telemetry source. The source adapter is the boundary between the source-specific world and the AutoSOC parsing stage.

> **Status:** `[CONCEPTUAL]` — Contracts defined; no adapters implemented.

### 6.1 Adapter Responsibility

A source adapter is responsible for:
1. Consuming raw messages from a Kafka topic or file stream
2. Attaching an `ingestion_id` and `ingest_time`
3. Computing `raw_hash`
4. Routing to the correct source-specific parser
5. Producing an `IngestionEnvelope`

A source adapter is **NOT** responsible for:
- Field normalization (that is Normalization Stage)
- Event validation (that is Validation Stage)
- Detection (that is Detection Layer)

### 6.2 Sysmon Adapter Contract

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Windows endpoint telemetry: process activity, network connections, file operations, registry changes, DNS queries |
| **Kafka topic** | `autosoc.raw.sysmon` |
| **Input format** | Windows XML Event Log (`<Event xmlns='...'><System>...</System><EventData>...</EventData></Event>`) |
| **Delivery mechanism** | Winlogbeat agent on Windows endpoint → Kafka |
| **Critical source fields** | `System.EventID`, `System.TimeCreated`, `System.Computer`, `EventData.Image`, `EventData.CommandLine`, `EventData.DestinationIp`, `EventData.SourceIp`, `EventData.QueryName`, `EventData.Hashes` |
| **Supported EventIDs** | 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 22, 23, 25 (see `security-event-model.md` §5.1) |
| **EventIDs explicitly filtered** | 4 (service state), 16 (config change) — not normalized; optionally logged separately |
| **Normalization complexity** | High: multi-hash string parsing (`Hashes` field), XML namespace handling, EventID-conditional field presence |
| **Sensor host injection** | `host` = `System.Computer` (available in Sysmon directly) |
| **Known limitations** | Windows-only; no process memory inspection; filterable by attacker; EventID 3 volume requires tuning |
| **Expected output** | `ParsedEvent` with source_type = `"sysmon"` |

### 6.3 Zeek Adapter Contract

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Network protocol analysis: connection logs, DNS, HTTP, TLS, file downloads |
| **Kafka topic** | `autosoc.raw.zeek` (one topic; `log_type` field distinguishes conn/dns/http/etc.) |
| **Input format** | Tab-separated values (TSV) with Zeek header comments, or JSON (via `@load tuning/json-logs`) |
| **Delivery mechanism** | Filebeat agent reading Zeek log directory → Kafka |
| **Log types handled** | `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, `weird.log`, `notice.log` |
| **Critical source fields** | `ts`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`, `service`, `query` (dns), `host` (http), `server_name` (ssl) |
| **Sensor host injection** | Zeek does NOT include its own hostname; `host` must be injected from deployment configuration (sensor label) |
| **Normalization complexity** | Medium: epoch timestamp conversion; log-type-conditional field mapping; TSV header parsing |
| **Known limitations** | No endpoint process context; connection-level visibility only; encrypted traffic limits application-layer inspection; `uid` needed for cross-log correlation |
| **Expected output** | `ParsedEvent` with source_type = `"zeek"`, `metadata.source_fields.log_type` indicating log file origin |

### 6.4 Suricata Adapter Contract

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Network IDS/IPS: signature-based alert generation, flow data, DNS, HTTP, TLS, file info |
| **Kafka topic** | `autosoc.raw.suricata` |
| **Input format** | EVE JSON: newline-delimited JSON records with `event_type` field (`alert`, `flow`, `dns`, `http`, `tls`, `fileinfo`, `anomaly`) |
| **Delivery mechanism** | Filebeat agent reading `/var/log/suricata/eve.json` → Kafka |
| **Critical source fields** | `timestamp`, `src_ip`, `dest_ip`, `src_port`, `dest_port`, `proto`, `event_type`, `alert.signature_id`, `alert.severity`, `alert.signature`, `host` |
| **Sensor host injection** | Suricata provides `host` field in EVE JSON (sensor hostname); must be validated non-empty |
| **Normalization complexity** | Low-medium: JSON already structured; severity mapping (Suricata 1–4 → AutoSOC 2–5); `event_type` field disambiguation |
| **Alert events** | `event_type: "alert"` events are the primary detection-relevant events; others are telemetry |
| **Known limitations** | Rule-based only (without ML); false positives require tuning; shared Kafka topic requires `event_type` routing in parser |
| **Expected output** | `ParsedEvent` with source_type = `"suricata"` |

### 6.5 Authentication / Security Log Adapter Contract

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Authentication events: login success/failure, privilege escalation, session management |
| **Kafka topic** | `autosoc.raw.auth` |
| **Input format** | Windows Event Log XML (EventID 4624/4625/4648/4769 etc.); Linux PAM syslog; auditd log format |
| **Delivery mechanism** | Winlogbeat (Windows) or Filebeat (Linux) → Kafka |
| **Windows EventIDs handled** | 4624 (Logon), 4625 (Failed Logon), 4634 (Logoff), 4648 (Explicit Credential Use), 4768/4769 (Kerberos), 4776 (NTLM) |
| **Linux auth sources** | `/var/log/auth.log` (PAM), `/var/log/secure`, auditd `type=USER_AUTH` records |
| **Critical source fields** | `EventID` / `type`, `TimeCreated`, `Computer` / `hostname`, `TargetUserName` / `user`, `IpAddress`, `LogonType` |
| **Normalization complexity** | High: Windows and Linux formats are entirely different; LogonType integer-to-string mapping required |
| **Expected event_types** | `auth.logon`, `auth.logoff`, `auth.failure` |
| **Expected output** | `ParsedEvent` with source_type = `"windows_event_log"` or `"auditd"` |

---

## 7. Duplicate Event Strategy

This section documents the duplicate-event policy without implementing deduplication.

### 7.1 Why Duplicates Occur

Duplicates can arise from multiple sources:

| Cause | Description |
|-------|-------------|
| **At-least-once delivery** | Kafka guarantees at-least-once; network issues can cause redelivery |
| **Agent restart** | Beats agents restart from last committed offset; events near the checkpoint may replay |
| **Multiple sensors** | Suricata and Zeek may both observe the same network flow on different sensors |
| **Source redundancy** | Windows Event Forwarding may forward the same event from multiple WEC servers |
| **Pipeline replay** | Manual or automated replay of the ingestion queue for reprocessing |

### 7.2 Identifier Semantics

| Identifier | Meaning | Dedup applicability |
|------------|---------|-------------------|
| `ingestion_id` | This delivery attempt | Different on every delivery; not useful for dedup |
| `event_id` | This AutoSOC normalized event | Assigned once at normalization; stable for a given `ParsedEvent` content |
| `metadata.source_event_id` | Source's own identifier | Useful for detecting source-level duplicates when sources assign stable IDs |
| `metadata.raw_hash` | SHA-256 of raw payload | Exact byte-level duplicate; highest fidelity |
| Correlation ID | Links events in the same transaction | Does NOT imply duplicate; correlation ≠ duplicate |

### 7.3 Deduplication Levels

| Level | Mechanism | When applied | Implementation |
|-------|-----------|-------------|---------------|
| **Level 1 — Exact payload** | `raw_hash` match within configurable window | Validation Stage | Redis cache of recent `raw_hash` values; flag `metadata.possible_duplicate: true`; do NOT reject |
| **Level 2 — Source ID** | `metadata.source_event_id` + `source` match | Validation Stage | Redis cache; flag only |
| **Level 3 — Alert dedup** | `(detector_id, host, time_bucket)` hash | Alert Generation Stage | Redis; increment alert `count` rather than creating new alert |

### 7.4 Policy Decisions

**Decision: Events are flagged, never silently discarded.**  
Duplicate events are marked with `metadata.possible_duplicate: true` and stored. The final deduplication policy (threshold, window size, rejection vs. flagging) is deferred to Phase 2 Week 5. See `Decisions.md` DECISION-005.

**Decision: `event_id` is NOT a deduplication mechanism.**  
`event_id` is a primary key for the AutoSOC event record. If the same raw event is processed twice (e.g., due to pipeline replay), two different `event_id` values will be generated. Deduplication relies on `raw_hash` and `source_event_id`, not on `event_id`.

---

## 8. Architectural Boundaries

This section defines the precise responsibility of each pipeline component and the rules governing their interfaces.

### 8.1 Component Responsibility Summary

| Component | Owner | Responsibility | Must NOT do |
|-----------|-------|----------------|------------|
| **Ingestion Layer** | DJ (infrastructure) | Accept raw events from Kafka; envelope with `ingestion_id`; compute `raw_hash`; route to parser | Parse, normalize, detect, make storage decisions |
| **Source Adapters / Parsers** | Pranjal | Transform raw payloads to source-native dict; stateless pure functions | Normalize fields to AutoSOC schema; make external calls; store data |
| **Normalization** | Pranjal | Map source fields to AutoSOC schema; compute derived fields | Validate semantics; run detection logic; store data directly |
| **Validation** | Pranjal | Enforce schema and semantic rules; assign event disposition; apply dedup flags | Normalize; run detection; modify source fields |
| **Feature Extraction** | Pranjal | Derive features from validated events | Modify the normalized event; run detection; query external services |
| **Detection** | Pranjal | Evaluate rules and models; produce Detection Results | Modify the normalized event; generate alerts directly; store to PostgreSQL directly |
| **Alert Generation** | Pranjal (logic) + DJ (infrastructure) | Deduplicate Detection Results; create Alert objects; store to PostgreSQL | Run detection logic; create incidents directly |
| **Triage / Incident** | Pranjal (logic) + DJ (AI infra) | Correlate alerts; create incidents; interface with AI agents (future) | Ingest raw events; run detection rules |
| **Threat Intelligence** | Pranjal | Enrich events with TI data via `metadata.threat_intel` | Mix TI into basic normalization; replace detection results |
| **AI Investigation** | DJ (future) | LLM-driven triage reasoning; playbook recommendations | Ingest raw events; run detection rules; modify detection results |

### 8.2 Interface Rules

1. **Source adapters are always separate from normalization.** A parser for Sysmon does not apply AutoSOC field names. It produces source-native field names. The normalization stage applies the mapping.

2. **Detection consumes only validated and normalized events.** Detection rules must not handle raw events, partially parsed events, or events that failed validation.

3. **Alerting consumes only Detection Results.** Alert Generation does not read events directly; it reads Detection Results which carry references to the source events.

4. **Threat Intelligence is enrichment, not detection.** TI data populates `metadata.threat_intel` on the normalized event. Detection rules may then inspect `metadata.threat_intel`. TI does not produce Detection Results independently.

5. **AI investigation is downstream of alerting.** The LLM triage agent reads Alerts and Incidents; it does not read raw events directly (it reads normalized events by reference through the event store).

6. **Kafka is the ingestion transport.** All raw events arrive via Kafka topics. No pipeline stage polls files directly (file reading is handled by Beats agents which publish to Kafka).

7. **PostgreSQL is the persistent event store.** Validated normalized events, alerts, incidents, detection results, and audit logs are stored in PostgreSQL.

8. **Redis is for transient state only.** Deduplication caches, session tokens, rate-limit counters, and short-lived queues. Redis state is not the source of truth for any persistent object.

9. **Qdrant is for the RAG layer only.** Qdrant stores vector embeddings of threat reports, playbooks, and investigation knowledge. It is not used for event storage or detection.

---

## 9. Research Evaluation Metadata

AutoSOC is a research platform. Future evaluation will require the following evidence from the data layer.

| Metric | Required evidence from data layer |
|--------|----------------------------------|
| Detection precision | Detection Results with `confidence`, matched events, ground truth labels |
| Recall / false negatives | Complete event corpus with labels vs. detection coverage |
| F1-score | Precision + recall data above |
| False positive rate | Alert corpus with analyst disposition (true positive / false positive / false negative) |
| Investigation quality | `llm_triage_summary` vs. ground truth incident classification |
| Investigation time | Timestamps: alert creation → analyst acknowledge → incident close |
| Agent performance | LLM tool call logs, `explanation_data`, output validation results |
| Explainability | `explanation` and `explanation_data` on Detection Results; SHAP values for ML |
| Provenance | `event_id` → `detection_id` → `alert_id` → `incident_id` chain; `raw_event` preserved |
| Latency | `ingest_time` → `timestamp` delta; normalization time; detection time |
| Throughput | Events/second through each pipeline stage |
| Reliability | Error rates per stage from `autosoc.errors.*` topics |

The event data model is designed to preserve provenance at every step. `raw_event` is never modified. `ingestion_id` and `event_id` are distinct. The full detection chain (`event_id` → `detection_id` → `alert_id` → `incident_id`) must be persisted for research traceability.

---

## 10. Backend Integration Architecture & Service Interfaces (Phase 1 / Day 4)

This section operationalizes the conceptual security data architecture by defining explicit package boundaries, service layer communication protocols, and Python interface contracts within DJ's verified FastAPI backend foundation.

### 10.1 Backend Package & Module Layout Mapping

The security pipeline components map into the existing backend module hierarchy (`backend/app/`) as follows:

| Security Component | Backend Module Path | Key Responsibilities |
|---|---|---|
| **Schemas & Models** | `backend/app/events/schemas.py` | Pydantic v2 schemas: `IngestionEnvelope`, `ParsedEvent`, `NormalizedSecurityEvent`, `EventFeatures`. |
| **Source Adapters** | `backend/app/events/adapters/` | Kafka stream consumers for `autosoc.raw.*`; wraps raw payload in `IngestionEnvelope`. |
| **Parsers** | `backend/app/events/parsers/` | Stateless source-specific parsers (`sysmon.py`, `zeek.py`, `suricata.py`, `auth.py`). |
| **Normalization** | `backend/app/events/normalization/` | Field mapping engine (`normalizer.py`, `mappings/`); transforms `ParsedEvent` to `NormalizedSecurityEvent`. |
| **Validation** | `backend/app/events/validation/` | Schema & business rules validator (`validator.py`, `rules.py`); Redis dedup query; error topic routing. |
| **Feature Extraction** | `backend/app/events/features/` | Feature extraction pipeline (`extractor.py`); derives structured feature sets from normalized events. |
| **Event Persistence** | `backend/app/events/repository.py` | Asynchronous SQLAlchemy/asyncpg data access for PostgreSQL `events` table. |
| **Detection Engine** | `backend/app/detection/` | Detection orchestrator (`engine.py`), Sigma rule compilation and execution (`sigma/`), `DetectionResult` models. |
| **Detection Persistence** | `backend/app/detection/repository.py`| Asynchronous data access for PostgreSQL `detection_results` table. |
| **Alert Generation** | `backend/app/alerts/` | Alert generator (`generator.py`), Redis sliding-window dedup (`deduplication.py`), `Alert` models. |
| **Alert Persistence** | `backend/app/alerts/repository.py` | Asynchronous data access for PostgreSQL `alerts` table. |
| **Incident Management** | `backend/app/incidents/` | Incident grouping (`grouper.py`), lifecycle transitions (`service.py`), `Incident` models. |
| **REST API Routers** | `backend/app/api/v1/` | FastAPI routers (`events.py`, `alerts.py`, `incidents.py`) exposing read/write endpoints to frontend. |

### 10.2 Service Layer Communication Contracts

Future security pipeline components must communicate with backend infrastructure services exclusively through standardized service contracts:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              Security Pipeline Component                               │
└────────────┬─────────────────────────────┬───────────────────────────────┬─────────────┘
             │                             │                               │
             ▼                             ▼                               ▼
    PostgreSQL Service               Redis Service                   Kafka Service
   (`app.db.session`)           (`app.services.redis_client`)    (`app.services.kafka_client`)
  - AsyncSessionLocal           - redis_service.client           - Consumer polling
  - Parameterized ORM writes    - Level 1 & Level 3 dedup TTL    - Dead-letter producer
  - Transaction rollbacks       - Ephemeral rate limits          - Manual offset commits
```

#### 10.2.1 PostgreSQL Database Interface (`backend/app/db/session.py`)
- **Injection:** Via FastAPI dependency injection (`Depends(get_db)`) or context-managed async session (`async with AsyncSessionLocal() as session:`).
- **Security Compliance:** All write operations must use parameterized SQLAlchemy ORM statements or typed models (`REQ-INPUT-011`). Raw string SQL interpolation is forbidden.
- **Bulk Operations:** Ingestion and normalization pipelines must use `session.execute(insert(EventModel), [...])` for batch inserts to sustain the $\ge 10,000$ EPS design target without transaction bottlenecks.

#### 10.2.2 Redis Cache Interface (`backend/app/services/redis_client.py`)
- **Client Instance:** Accessed via `redis_service.client` (asynchronous `redis.asyncio.Redis`).
- **Level 1 Dedup Key:** `autosoc:dedup:raw_hash:<sha256>` with configurable TTL (default 300s). `SETNX` semantics return whether the payload hash was recently observed.
- **Level 3 Alert Dedup Key:** `autosoc:dedup:alert:<detector_id>:<host>:<time_bucket>` with TTL matching the alert window. Atomic `INCR` tracks alert firing counts.
- **Failure Behavior:** If Redis is unreachable, the pipeline logs a warning and proceeds with event processing without dedup flagging. Redis failure must **never** cause dropped events or pipeline termination.

#### 10.2.3 Kafka Message Bus Interface (`backend/app/services/kafka_client.py`)
- **Consumer Model:** Background async workers (or standalone ingestion workers) subscribe to source topics (`autosoc.raw.*`).
- **Message Serialization:** Envelopes and payloads use UTF-8 encoded JSON.
- **Offset Commit Semantics:** **At-least-once delivery with manual offset commit**. The worker commits Kafka offsets *only after* the normalized event is successfully committed to PostgreSQL or the malformed payload is delivered to a dead-letter topic.
- **Dead-Letter Publishing:** Handled via dedicated producer methods on `kafka_service`:
  - `publish_error(topic="autosoc.errors.parse", envelope=...)`
  - `publish_error(topic="autosoc.errors.validation", event=...)`

#### 10.2.4 Qdrant Vector Engine Interface (`backend/app/services/qdrant_client.py`)
- **Isolation:** Real-time event ingestion, parsing, normalization, and rule-based detection have **zero** dependency on Qdrant.
- **Usage Scope:** Qdrant is reserved exclusively for the future RAG knowledge layer (querying threat actor profiles, CTI reports, and remediation playbooks during alert investigation and triage).

### 10.3 Concrete Python Interface Protocols

To enforce strict decoupling across development boundaries, future security components must adhere to the following Python Protocols (PEP 544):

```python
from typing import Protocol, runtime_checkable, Dict, Any, Tuple, Optional, List
from datetime import datetime

@runtime_checkable
class SourceParserProtocol(Protocol):
    """Stateless pure-function parser converting raw payloads to source dictionaries."""
    def parse(self, raw_payload: str, source_type: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Returns (success, parsed_fields_dict, error_message)."""
        ...

@runtime_checkable
class EventNormalizerProtocol(Protocol):
    """Maps parsed source fields into the normalized security event model."""
    def normalize(self, parsed_event: Dict[str, Any], ingestion_envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Returns NormalizedSecurityEvent dictionary with event_id and event_category."""
        ...

@runtime_checkable
class EventValidatorProtocol(Protocol):
    """Validates schema structure and semantic sanity; checks deduplication state."""
    async def validate(self, normalized_event: Dict[str, Any]) -> Tuple[str, List[str]]:
        """Returns disposition ('accepted', 'accepted_with_warnings', 'rejected', 'unsupported')
        and list of warning/error messages."""
        ...

@runtime_checkable
class FeatureExtractorProtocol(Protocol):
    """Derives structured feature sets from validated normalized events."""
    def extract_features(self, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
        """Returns structured EventFeatures dictionary."""
        ...

@runtime_checkable
class DetectionEngineProtocol(Protocol):
    """Evaluates rules/models against normalized events and features."""
    async def evaluate(self, normalized_event: Dict[str, Any], features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Returns list of DetectionResult dictionaries."""
        ...

@runtime_checkable
class AlertGeneratorProtocol(Protocol):
    """Deduplicates detection results and produces actionable Alert records."""
    async def process_detection(self, detection_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Returns Alert dictionary if new alert created, or None if count incremented."""
        ...
```

### 10.4 Infrastructure Dependency & Failure Isolation Matrix

| Subsystem | Primary Infrastructure | Fallback / Isolation Policy |
|---|---|---|
| **Ingestion Layer** | Kafka (`autosoc.raw.*`) | If Kafka broker unreachable, Beats forwarders buffer locally on disk; ingestion workers apply exponential retry. |
| **Parsing & Normalization** | In-Process Compute | Zero external dependencies; CPU-bound; failures isolate to dead-letter topics (`autosoc.errors.parse`). |
| **Validation** | PostgreSQL + Redis | If Redis dedup cache is down, bypass dedup check and write event to PostgreSQL; if PostgreSQL down, do not commit Kafka offset. |
| **Detection (Sigma)** | In-Process Compute | Rules run against memory representations; rule failure logs error without halting pipeline; emits `DetectionResult` to PostgreSQL. |
| **Alert Generation** | PostgreSQL + Redis | If Redis dedup fails, fall back to direct PostgreSQL query or create un-deduplicated alert; alert storage retries with backoff. |
| **Triage & Incidents** | PostgreSQL | Background worker aggregates alerts; failures do not disrupt event ingestion or detection. |

---

*Document created by Pranjal — Day 2. Updated Day 4 (Phase 1 Architecture Preparation) to establish concrete backend service integration boundaries.*
