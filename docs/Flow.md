# AutoSOC — Security Data Flow

> **Purpose:** Documents HOW security data flows through AutoSOC from telemetry source to analyst dashboard. This is the architecture reference, not an implementation guide. All implementation status is explicitly labeled.
>
> **Status labels used throughout this document:**
> - `[CONCEPTUAL]` — Architecture agreed and documented; no implementation
> - `[PLANNED Phase 2 — Week N]` — Scheduled for specific implementation week
> - `[IMPLEMENTED]` — Code exists and is verified working
>
> **Last Updated:** 2026-11-20 (Day 2)

---

## 1. Top-Level Data Flow

```
Telemetry Sources
      │
      │  Raw bytes (XML, JSON, TSV, syslog)
      │  via Beats (Winlogbeat, Filebeat) or direct stream
      ▼
  Kafka (autosoc.raw.*)
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│                    INGESTION LAYER                           │
│  Assign ingestion_id | Record ingest_time | Compute raw_hash│
└───────────────────┬─────────────────────────────────────────┘
                    │  IngestionEnvelope
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                   PARSING STAGE                              │
│  Source-specific stateless parser                            │
│  Sysmon XML → dict | Zeek TSV → dict | Suricata JSON → dict │
└───────────────────┬─────────────────────────────────────────┘
                    │  ParsedEvent (source-native field names)
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                 NORMALIZATION STAGE                          │
│  Apply source → AutoSOC field mapping                        │
│  Assign event_id | Set event_category | Normalize timestamps │
│  Normalize IPs | Assign severity | GeoIP | Internal flags    │
└───────────────────┬─────────────────────────────────────────┘
                    │  NormalizedSecurityEvent
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                  VALIDATION STAGE                            │
│  Schema validation: required fields, types, enum values      │
│  Semantic validation: timestamp sanity, field consistency    │
│  Dedup check: raw_hash + source_event_id cache               │
└──────┬────────────────────────────────────────┬─────────────┘
       │ Accepted (with or without warnings)     │ Rejected
       ▼                                         ▼
  PostgreSQL events table          autosoc.errors.validation (Kafka)
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│               FEATURE EXTRACTION STAGE                       │
│  Derive features: categorical, network, process, DNS,        │
│  file, temporal                                              │
└───────────────────┬─────────────────────────────────────────┘
                    │  NormalizedSecurityEvent + FeatureSet
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                   DETECTION LAYER                            │
│                                                              │
│  ┌─────────────────┐  ┌───────────────┐  ┌──────────────┐  │
│  │  Rule-Based     │  │  ML-Based     │  │ Threat Intel  │  │
│  │  (Sigma)        │  │  (Future)     │  │ (Future)      │  │
│  └────────┬────────┘  └───────┬───────┘  └──────┬───────┘  │
│           └───────────────────┴──────────────────┘          │
│                               │                              │
│                    ┌──────────┴──────────┐                   │
│                    │  Correlation Engine  │  (Future)         │
│                    └──────────┬──────────┘                   │
└───────────────────────────────┼──────────────────────────────┘
                                │  DetectionResult
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                  ALERT GENERATION                            │
│  Dedup: (detector_id, host, time_bucket) → Redis cache      │
│  Create Alert | Enrich with MITRE ATT&CK                    │
└───────────────────┬─────────────────────────────────────────┘
                    │  Alert
                    ▼
┌─────────────────────────────────────────────────────────────┐
│               TRIAGE AND INCIDENT CREATION                   │
│  Correlate alerts → Incident                                 │
│  LLM triage agent (Future)                                   │
│  Human analyst queue                                         │
└───────────────────┬─────────────────────────────────────────┘
                    │  Incident
                    ▼
         PostgreSQL (events, alerts, incidents, detection_results)
                    │
                    ▼
         REST API (FastAPI) + WebSocket/Polling
                    │
                    ▼
         Dashboard (Shreyash — Next.js frontend)
```

---

## 2. Component Detail

### 2.1 Ingestion Layer `[PLANNED Phase 2 — Week 4]`

**Input:** Raw event bytes from Kafka topics:
- `autosoc.raw.sysmon`
- `autosoc.raw.zeek`
- `autosoc.raw.suricata`
- `autosoc.raw.auth`

**Processing:**
1. Validate message envelope (`source_type` present, payload non-empty)
2. Assign `ingestion_id` (UUID v4) — identifies this delivery attempt
3. Record `ingest_time` (UTC ISO 8601) — time received by AutoSOC
4. Compute `raw_hash` (SHA-256 of payload bytes) — exact-duplicate fingerprint
5. Enforce payload size limit (64 KiB; truncate if exceeded)

**Output:** `IngestionEnvelope`:
```json
{
  "ingestion_id": "<UUID v4>",
  "source_type":  "<string>",
  "sensor_id":    "<string>",
  "ingest_time":  "<ISO 8601 UTC>",
  "raw_hash":     "sha256:<hex>",
  "raw_payload":  "<string>"
}
```

**Failure path:** Malformed envelope → `autosoc.errors.ingestion` dead-letter topic. Kafka offset committed only after successful handoff.

**Dependencies:** Kafka (read), Redis (optional dedup cache)

---

### 2.2 Parsing Stage `[PLANNED Phase 2 — Week 5]`

**Input:** `IngestionEnvelope` from Ingestion Layer

**Processing:** Route to source-specific stateless pure-function parser:

| `source_type` | Parser | Input format |
|--------------|--------|-------------|
| `sysmon` | `SysmonParser` | Windows XML EVTX |
| `zeek` | `ZeekParser` | TSV or JSON + log_type |
| `suricata` | `SuricataParser` | EVE JSON |
| `windows_event_log` | `WinEventParser` | Windows XML EVTX |
| `auditd` | `AuditdParser` | Key=value audit.log |

Parser contract: `(raw_string, source_type) → ParsedEvent | ParseError`  
Parsers are **stateless** and **have no external dependencies**.

**Output:** `ParsedEvent`:
```json
{
  "ingestion_id":  "<UUID v4>",
  "source_type":   "<string>",
  "ingest_time":   "<ISO 8601 UTC>",
  "raw_hash":      "sha256:<hex>",
  "source_fields": { "<source-native field name>": "<value>", "..." : "..." }
}
```

**Failure path:** Parse failure → `ParseError{ingestion_id, error_type, raw_payload_ref}` → `autosoc.errors.parse` Kafka topic. Original payload preserved.

---

### 2.3 Normalization Stage `[PLANNED Phase 2 — Week 5]`

**Input:** `ParsedEvent` from Parsing Stage

**Processing:**
1. Apply source-specific field mapping (spec: `security-event-model.md` §5; `security-data-contract.md` §6)
2. Assign `event_id` (UUID v4)
3. Set `event_category` from `event_type` taxonomy
4. Normalize `timestamp` → UTC ISO 8601
5. Normalize IPs → canonical form (IPv4 dotted-decimal, IPv6 RFC 5952)
6. Normalize `protocol` → lowercase enum
7. Normalize `user` → lowercase, strip domain prefix → `metadata.user_domain`
8. Assign `severity` from source-specific mapping
9. Classify `event_type` from source event code
10. Compute `metadata.is_internal_src`, `metadata.is_internal_dst` from subnet config
11. Compute `metadata.geo` from GeoIP lookup (MaxMind GeoLite2)
12. Place unmapped fields in `metadata.source_fields`
13. Set `metadata.pipeline_version`, `metadata.ingest_time`

**Output:** `NormalizedSecurityEvent` conforming to full schema in `security-data-contract.md` §2 and `security-event-model.md`

**Failure path:** Non-required field normalization failure → `null` for that field + warning log. Required field failure → pass to Validation for rejection.

---

### 2.4 Validation Stage `[PLANNED Phase 2 — Week 5]`

**Input:** `NormalizedSecurityEvent` from Normalization Stage

**Processing:**
- Schema validation: 14 checks covering required fields, type correctness, enum membership, format validity
- Semantic validation: 5 checks covering timestamp sanity, field consistency, network completeness
- Deduplication check: `raw_hash` + `source_event_id` against Redis cache

**Output (by disposition):**

| Disposition | Condition | Destination |
|------------|-----------|------------|
| Accepted | All schema checks pass; semantic checks pass or warn | PostgreSQL `events` table |
| Accepted with warnings | Schema passes; semantic warning flags set | PostgreSQL `events` table (with `metadata.possible_duplicate`, `metadata.timestamp_future`, etc.) |
| Rejected | Any required schema check fails | `autosoc.errors.validation` Kafka topic |
| Unsupported | Unknown source type | `autosoc.unsupported` Kafka topic |

**Failure path:** No event is silently discarded. All rejected/unsupported events are routed to Kafka dead-letter topics with the original payload preserved.

**Dependencies:** Redis (dedup cache), PostgreSQL (event write)

---

### 2.5 Feature Extraction Stage `[PLANNED Phase 2 — Week 6]`

**Input:** Validated `NormalizedSecurityEvent` from PostgreSQL or validation output queue

**Processing:** Derive features per schema in `security-data-contract.md` §4:
- Categorical features: from `event_type`, `source`, `protocol`, `severity`
- Network features: from IPs, ports, subnet membership
- Process features: from `process`, `command_line`, `metadata.parent_process`
- DNS features: from `domain` (entropy, length, TLD, subdomain count)
- File features: from `file_hash`
- Temporal features: from `timestamp` (hour, day of week, business hours)

**Output:** `NormalizedSecurityEvent` + `features` sub-object (optionally persisted to `event_features` table)

**Failure path:** Individual feature extraction failure → `null` for that feature + warning log. Event is not rejected.

---

### 2.6 Detection Layer `[PLANNED Phase 2 — Week 6]`

**Input:** Validated `NormalizedSecurityEvent` + `FeatureSet`

#### Rule-Based Detection (Sigma) `[PLANNED Phase 2 — Week 6]`

- Sigma rules authored against AutoSOC normalized field names
- pySigma compiles rules to backend (in-process evaluation or Elasticsearch DSL)
- Initial rule set: 20–50 curated Windows/network rules
- Output: `DetectionResult` with `detector_type = "rule_sigma"`, `confidence = 1.0`

#### ML-Based Detection `[CONCEPTUAL — Post Phase 2]`

- Consumes `NormalizedSecurityEvent` + `FeatureSet`
- Outputs `DetectionResult` with model probability as `confidence`
- Interface: `score(NormalizedEvent) → DetectionResult`
- Not implemented in Phase 2

#### Threat Intelligence Enrichment `[CONCEPTUAL — Post Phase 2]`

- Enriches `metadata.threat_intel` on matched events
- Populates: `ip_score`, `ip_categories`, `domain_score`, `hash_known_malware`
- Does not produce `DetectionResult` independently
- Not implemented in Phase 2

#### Correlation Engine `[CONCEPTUAL — Post Phase 2]`

- Temporal and causal correlation across events
- Multi-source correlation (Sysmon process + Zeek network)
- Requires entity resolution (host name ↔ IP ↔ asset inventory)
- Not implemented in Phase 2

**Output:** `DetectionResult` (schema: `security-data-contract.md` §5)

**Failure path:** Detection engine crash for one mechanism does not block others. Engine failures logged with source event reference.

---

### 2.7 Alert Generation `[PLANNED Phase 2 — Week 7]`

**Input:** `DetectionResult` from Detection Layer

**Processing:**
1. Compute dedup hash: `sha256(detector_id + host + floor(timestamp / window_seconds))`
2. Check Redis for existing alert with same hash
   - Cache hit: increment `alert.count`; do not create new alert
   - Cache miss: create new Alert; write hash to Redis with TTL
3. Enrich Alert with MITRE ATT&CK metadata
4. Set `alert_id`, `created_at`, `status = "open"`
5. Write to PostgreSQL `alerts` table
6. Update `metadata.alert_id` on source event

**Output:** `Alert` (schema: `detection-pipeline.md` §3.6)

**Dependencies:** Redis (dedup state), PostgreSQL (alert write)

**Failure path:** PostgreSQL write failure → retry with exponential backoff. Detection result preserved until alert successfully written.

---

### 2.8 Triage and Incident Creation `[PLANNED Phase 2 — Week 7]`

**Input:** `Alert` objects from Alert Generation

**Processing:**
1. Group alerts: same `host` + within 15-minute window + same rule family → one Incident
2. Set `incident_id`, `created_at`, `status = "new"`
3. Future: LLM triage agent produces `llm_triage_summary`
4. Queue for analyst review

**Output:** `Incident` (schema: `detection-pipeline.md` §3.7)

**Dependencies:** PostgreSQL (incident write), Redis (triage queue), future Qdrant (RAG for playbooks)

---

## 3. Dead Letter and Error Flow

```
Ingestion Layer error    → autosoc.errors.ingestion  (Kafka)
Parsing Stage error      → autosoc.errors.parse       (Kafka)
Validation rejection     → autosoc.errors.validation  (Kafka)
Unsupported source       → autosoc.unsupported        (Kafka)
```

All dead-letter topics preserve the original `ingestion_id` and `raw_payload`. No event is silently lost.

Error topics must be monitored and alerting must be configured on sustained error rates.

---

## 4. Infrastructure Data Flow

```
Kafka           → Source of raw events; dead-letter topics for errors
PostgreSQL      → Persistent store: events, alerts, incidents, detection_results, audit_log
Redis           → Transient state: dedup caches, alert dedup, session tokens, rate limit counters
Qdrant          → Future: vector embeddings for RAG/playbook retrieval (not Phase 2)
FastAPI         → REST API layer exposing events/alerts/incidents to frontend
Next.js         → Dashboard consuming REST API
```

---

## 5. Data Retention and Provenance Chain

Every AutoSOC security event carries a full provenance chain:

```
raw_event (never modified)
  → ingestion_id (delivery identity)
      → event_id (normalized event identity)
          → detection_id (detection result identity)
              → alert_id (alert identity)
                  → incident_id (incident identity)
```

This chain enables:
- Forensic replay from raw event
- Research evaluation traceability
- Audit log correlation
- LLM agent context fetching (agent reads normalized event by `event_id` referenced in alert)

---

## 6. Implementation Status Summary

| Component | Status | Phase |
|-----------|--------|-------|
| Telemetry Sources (Sysmon, Zeek, Suricata) | CONCEPTUAL | External |
| Kafka infrastructure | IMPLEMENTED (Day 1 Docker) | DJ |
| Ingestion Layer | PLANNED | Phase 2 Week 4 |
| Source Parsers | PLANNED | Phase 2 Week 5 |
| Normalization | PLANNED | Phase 2 Week 5 |
| Validation | PLANNED | Phase 2 Week 5 |
| PostgreSQL event storage | PLANNED (DDL pending) | Phase 2 Week 5 |
| Feature Extraction | PLANNED | Phase 2 Week 6 |
| Rule-Based Detection (Sigma) | PLANNED | Phase 2 Week 6 |
| ML-Based Detection | CONCEPTUAL | Post Phase 2 |
| Threat Intelligence Enrichment | CONCEPTUAL | Post Phase 2 |
| Correlation Engine | CONCEPTUAL | Post Phase 2 |
| Alert Generation | PLANNED | Phase 2 Week 7 |
| Triage / Incident Creation | PLANNED | Phase 2 Week 7 |
| LLM Triage Agent | CONCEPTUAL | Post Phase 2 |
| REST API | PLANNED | Phase 2 Week 7 |
| Realtime Dashboard | PLANNED | Phase 2 Week 7 |
| RAG / Qdrant | CONCEPTUAL | Post Phase 2 |
| Attack Graph (Neo4j) | CONCEPTUAL | Later phase |

---

*Flow.md maintained by Pranjal (security data flow). DJ updates the Infrastructure Data Flow section for backend/infra changes. Shreyash updates for frontend integration changes. Must be updated whenever the actual or planned pipeline architecture changes.*
