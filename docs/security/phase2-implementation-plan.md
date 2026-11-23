# AutoSOC — Phase 2 Implementation Plan: Security Data Layer

**Version:** 0.2.0  
**Owner:** Pranjal (Cybersecurity Pipeline)  
**Status:** Active — Day 4 (Phase 1 Architecture Preparation)  
**Last Updated:** 2026-11-21

> **Scope of this document:** This is a planning document for Weeks 4–7 of AutoSOC development (Phase 2 — Security Data Layer). No implementation exists. This plan is intended to make future implementation work unambiguous and to coordinate across DJ (infrastructure), Pranjal (cybersecurity), and Shreyash (frontend).

---

## Overview

| Week | Theme | Owner |
|------|-------|-------|
| Week 4 | Event Ingestion | DJ (infra) + Pranjal (source contracts) |
| Week 5 | Parsing and Normalization | Pranjal (parsers, normalization) + DJ (storage) |
| Week 6 | Feature Extraction and Detection | Pranjal (detection pipeline) |
| Week 7 | Alert, Incident, Search, Realtime Integration | Pranjal + DJ + Shreyash |

---

## Week 4: Event Ingestion

### Objective

Establish controlled ingestion of security events from simulated/dataset sources through Kafka into the AutoSOC pipeline. Prove the transport layer end-to-end.

### Inputs

| Source | Format | Transport |
|--------|--------|-----------|
| Sysmon XML events (from lab Windows VM or dataset replay) | XML EVTX | Winlogbeat → Kafka |
| Zeek logs (from dataset PCAP processing) | TSV / JSON | Filebeat → Kafka |
| Suricata EVE JSON (from dataset PCAP processing) | EVE JSON | Filebeat → Kafka |
| Authentication logs (Windows EventLog or Linux auth.log) | XML / syslog | Winlogbeat/Filebeat → Kafka |

### Kafka Topic Architecture

| Topic | Purpose | Producers | Consumers |
|-------|---------|-----------|----------|
| `autosoc.raw.sysmon` | Raw Sysmon XML payloads | Winlogbeat | Sysmon Parser |
| `autosoc.raw.zeek` | Raw Zeek log lines | Filebeat | Zeek Parser |
| `autosoc.raw.suricata` | Raw Suricata EVE JSON | Filebeat | Suricata Parser |
| `autosoc.raw.auth` | Raw auth log lines | Winlogbeat/Filebeat | Auth Parser |
| `autosoc.errors.ingestion` | Ingestion-layer dead letters | Ingestion Layer | Error handler |
| `autosoc.errors.parse` | Parse-failure dead letters | Parsing Stage | Error handler |
| `autosoc.errors.validation` | Validation-rejection dead letters | Validation Stage | Error handler |
| `autosoc.unsupported` | Unknown/unsupported source events | Parsing/Normalization | Manual review |

### Outputs

Each Kafka message on a source topic carries the ingestion envelope:

```json
{
  "ingestion_id":  "<UUID v4>",
  "source_type":   "<sysmon|zeek|suricata|auth>",
  "sensor_id":     "<string: configured label for this sensor>",
  "ingest_time":   "<ISO 8601 UTC>",
  "raw_hash":      "<sha256:hex of raw_payload bytes>",
  "raw_payload":   "<string: original event>"
}
```

### Infrastructure Dependencies

| Dependency | Role | Owner |
|------------|------|-------|
| Kafka | Message bus; source topics; error topics | DJ |
| Beats (Winlogbeat/Filebeat) | Collect and forward raw events to Kafka | DJ (config), Pranjal (field config) |
| Redis | Optional: ingestion-level dedup cache for `raw_hash` | DJ |
| Docker Compose | Running Kafka and Zookeeper/KRaft locally | DJ |

### Testing Requirements

| Test | Description |
|------|-------------|
| **Ingestion smoke test** | Publish a sample Sysmon, Zeek, and Suricata event manually to respective Kafka topics; confirm message is readable |
| **Envelope validation test** | Confirm all required envelope fields are present on consumed messages |
| **Raw hash test** | Confirm `raw_hash` is consistent for identical payloads and differs for different payloads |
| **Oversized payload test** | Publish a >64 KiB payload; confirm truncation behavior and `raw_truncated: true` |
| **Dead letter test** | Publish a malformed envelope (missing `source_type`); confirm routing to `autosoc.errors.ingestion` |

### Security Requirements

- Kafka brokers must not be exposed externally (`REQ-NET-004`)
- Sensor authentication to Kafka (SASL/PLAIN or mTLS for production; plaintext acceptable for local dev)
- Raw event payload must not be logged in plaintext in application logs (may contain sensitive process arguments)
- Beats agent config must not contain credentials in plaintext files committed to git

---

## Week 5: Parsing and Normalization

### Objective

Convert raw source payloads into validated AutoSOC Normalized Security Events and store them in PostgreSQL.

### Inputs

Ingestion envelopes from Kafka source topics (Week 4 output).

### Parsing Stage

**One stateless parser per source type:**

| Parser | Input | Output |
|--------|-------|--------|
| `SysmonParser` | Sysmon XML string | `ParsedEvent` with Sysmon-native field dict |
| `ZeekParser` | Zeek TSV line or JSON object + log_type | `ParsedEvent` with Zeek-native field dict + `log_type` |
| `SuricataParser` | Suricata EVE JSON string | `ParsedEvent` with Suricata-native field dict |
| `AuthParser` | Windows EventLog XML or Linux auth syslog line | `ParsedEvent` with auth-native field dict + `auth_format` |

Each parser is a **pure function** with no external dependencies: `(raw_string, source_type) → ParsedEvent | ParseError`.

### Normalization Stage

Apply source-specific field mapping (documented in `security-data-contract.md` Section 6 and `security-event-model.md` Section 5).

**Normalization outputs the full Normalized Security Event schema** including `ingestion_id`, `event_id`, `event_category`, all standard fields, and all `metadata.*` fields.

### Validation Stage

Apply all schema and semantic checks from `security-data-contract.md` Section 3 / Stage 4.

Disposition routing:
- Accepted events → PostgreSQL `events` table
- Rejected events → `autosoc.errors.validation` Kafka topic

### Storage Schema (Draft)

PostgreSQL `events` table (design; exact DDL to be finalized by DJ):

```sql
-- Conceptual schema only — not implemented
CREATE TABLE events (
  event_id          UUID PRIMARY KEY,
  ingestion_id      UUID NOT NULL,
  timestamp         TIMESTAMPTZ NOT NULL,
  source            VARCHAR(32) NOT NULL,
  event_category    VARCHAR(32) NOT NULL,
  event_type        VARCHAR(64) NOT NULL,
  host              TEXT NOT NULL,
  user_name         TEXT,
  source_ip         INET,
  destination_ip    INET,
  source_port       SMALLINT,
  destination_port  SMALLINT,
  protocol          VARCHAR(16),
  process           TEXT,
  file_hash         TEXT,
  domain            TEXT,
  command_line      TEXT,
  severity          SMALLINT NOT NULL,
  raw_event         TEXT NOT NULL,
  metadata          JSONB NOT NULL DEFAULT '{}',
  ingested_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_events_timestamp ON events (timestamp);
CREATE INDEX idx_events_host ON events (host);
CREATE INDEX idx_events_source ON events (source);
CREATE INDEX idx_events_event_type ON events (event_type);
CREATE INDEX idx_events_source_ip ON events (source_ip);
CREATE INDEX idx_events_destination_ip ON events (destination_ip);
CREATE INDEX idx_events_severity ON events (severity);
```

> **Note:** This is a conceptual schema to illustrate storage intent. DJ owns the actual DDL and migration files. JSONB for `metadata` allows flexible storage of source-specific fields without schema changes.

### Schema Versioning

- `metadata.pipeline_version` carries the normalization pipeline version string
- Future schema changes to `events` table require a migration; `metadata.pipeline_version` enables identification of events normalized by older pipeline versions
- Parser and normalization code versions are tracked in git; the pipeline version string must be updated with each breaking change to the normalization logic

### Unsupported Event Handling

Events with unknown or unmappable source types are routed to `autosoc.unsupported` Kafka topic. These events are not stored in the `events` table. They are preserved for manual analysis and future source support.

### Testing Requirements

| Test | Description |
|------|-------------|
| **Parse unit tests** | One test per supported EventID/log_type with a sample payload fixture; assert expected `ParsedEvent` output |
| **Normalization unit tests** | One test per source with a `ParsedEvent` fixture; assert expected `NormalizedSecurityEvent` output including all required fields |
| **Validation unit tests** | One test per validation rule (see `security-data-contract.md` §4A and §4B); test both passing and failing cases |
| **Rejection routing test** | Confirm that events failing required field checks do NOT appear in the `events` table |
| **Round-trip test** | Ingest a known sample event; retrieve from PostgreSQL; confirm all fields match expected values |
| **Duplicate detection test** | Ingest identical payload twice; confirm second event has `metadata.possible_duplicate: true` |

### Security Requirements

- Parameterized queries or ORM for all PostgreSQL writes (`REQ-INPUT-011`)
- `command_line` field: sensitive argument redaction must be applied before storage (redaction rules TBD — see `security-event-model.md` §9)
- `raw_event` truncation enforced at 65,536 bytes before storage
- Parser must use `safe_load` equivalent for YAML; XML parser must disable entity expansion (XXE prevention)
- Database connection string must not appear in logs (`REQ-SECRET-008`)

---

## Week 6: Feature Extraction and Detection

### Objective

Prepare validated normalized events for detection; run rule-based detection (Sigma); produce Detection Results.

### Inputs

Validated `NormalizedSecurityEvent` objects from PostgreSQL (Week 5 output) or directly from the validation output queue.

### Feature Extraction

Implement the feature derivation rules from `security-data-contract.md` Section 4.

**Feature sets that can be implemented in Week 6:**
- `categorical.*` — All derivable from normalized event fields
- `network.*` — Derivable from `source_ip`, `destination_ip`, configured subnet list
- `process.*` — Derivable from `process`, `command_line`, `metadata.parent_process`, configured LOLBIN list
- `dns.*` — Derivable from `domain` field (entropy, length, subdomain count, TLD)
- `temporal.*` — Derivable from `timestamp`

**Feature sets requiring behavioral baseline (defer to later phase):**
- `temporal.time_since_last_event_from_host` — Requires event history queries
- `behavioral.*` — Requires rolling-window aggregation infrastructure

### Rule-Based Detection (Sigma)

**Implementation approach for Week 6:**

1. Set up pySigma pipeline targeting in-process evaluation against Python dicts
2. Curate initial Sigma rule set: 20–50 high-confidence Windows rules covering:
   - Encoded PowerShell execution (T1059.001)
   - LOLBIN abuse (T1218)
   - Suspicious parent-child process relationships (T1055)
   - DNS-based C2 patterns (T1071.004)
   - Credential dumping indicators (T1003)
3. Run rules against normalized events from the `events` table
4. Produce `DetectionResult` objects (schema in `security-data-contract.md` Section 5)

> **ML-based detection: DO NOT implement in Week 6.** The rule-based detection path must be stable before ML models are introduced.

### Detection Result Storage

PostgreSQL `detection_results` table (conceptual DDL):

```sql
-- Conceptual schema only — not implemented
CREATE TABLE detection_results (
  detection_id      UUID PRIMARY KEY,
  created_at        TIMESTAMPTZ NOT NULL,
  source_event_id   UUID NOT NULL REFERENCES events(event_id),
  detector_type     VARCHAR(32) NOT NULL,
  detector_id       TEXT NOT NULL,
  detector_version  TEXT NOT NULL,
  severity          SMALLINT NOT NULL,
  confidence        REAL NOT NULL,
  matched_indicators JSONB NOT NULL DEFAULT '[]',
  evidence          JSONB NOT NULL DEFAULT '[]',
  mitre_tactics     TEXT[],
  mitre_techniques  TEXT[],
  explanation       TEXT,
  explanation_data  JSONB,
  raw_score         REAL,
  feature_snapshot  JSONB
);

CREATE INDEX idx_detection_results_event_id ON detection_results (source_event_id);
CREATE INDEX idx_detection_results_detector_id ON detection_results (detector_id);
CREATE INDEX idx_detection_results_severity ON detection_results (severity);
```

### Event Correlation Considerations

Event correlation (linking related events across time and sources) is a **future phase** capability. The following foundation must be preserved in the data model to enable future correlation:

| Correlation anchor | Field | Preserved |
|-------------------|-------|---------|
| Same host | `host` | Yes — required field |
| Same user | `user` | Yes — optional field |
| Same IP pair | `source_ip` + `destination_ip` | Yes — optional fields |
| Same process chain | `metadata.pid` + `metadata.parent_pid` | Yes — source-specific metadata |
| Same Zeek connection | `metadata.source_fields.uid` | Yes — source_fields preserved |
| Time window | `timestamp` | Yes — required field |

### Testing Requirements

| Test | Description |
|------|-------------|
| **Feature unit tests** | One test per feature category; assert correct feature values for known inputs |
| **Sigma rule test** | For each included Sigma rule, test against a fixture event that SHOULD match and one that SHOULD NOT match |
| **Detection result schema test** | Assert all required fields in every `DetectionResult` output |
| **End-to-end detection test** | Inject a known-malicious fixture event; confirm a Detection Result is produced with correct severity and mitre_techniques |
| **No false positive test** | Inject a known-benign fixture event; confirm no Detection Result is produced for applicable rules |

### Security Requirements

- Detection rules (Sigma YAML files) must be parsed with `pyyaml.safe_load` or `ruamel.yaml` in safe mode (`REQ-INPUT-010`)
- Rule directory must be read-only at runtime; no dynamic rule writes during detection
- Detection engine failure must NOT crash the pipeline; errors must be caught and logged with the offending event reference

---

## Week 7: Alert, Incident, Search and Realtime Integration

### Objective

Implement the full alert and incident lifecycle, expose events and alerts via REST API for the frontend, and integrate real-time alert delivery.

### Inputs

Detection Results from PostgreSQL `detection_results` table (Week 6 output).

### Alert Creation

Implement alert deduplication and Alert object creation per `detection-pipeline.md` §3.6.

**Deduplication hash key:** `sha256(detector_id + host + floor(timestamp / dedup_window_seconds))`

**Deduplication implementation:**
- Redis stores `{dedup_hash → alert_id}` with TTL = `dedup_window_seconds`
- On Detection Result: compute hash → check Redis
  - Cache hit: increment `alert.count` in PostgreSQL; do not create new alert
  - Cache miss: create new alert; write to Redis

### Incident Lifecycle

Implement basic alert-to-incident grouping:

**Grouping criteria (Phase 2 baseline):**
- Same `host` within 15-minute time window
- Same rule family (first two segments of `detector_id` namespace)

**Incident status transitions:**
```
new → investigating → contained → closed
         ↓
    false_positive
```

### API Endpoints Required for Frontend Integration

The following REST endpoints are required for Shreyash's frontend. Exact API contract to be defined by DJ (backend) in coordination with Pranjal (data) and Shreyash (UI requirements).

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/events` | GET | List normalized events with filtering (host, source, event_type, time range, severity) |
| `/api/v1/events/{event_id}` | GET | Retrieve single normalized event by ID |
| `/api/v1/alerts` | GET | List alerts with filtering (status, severity, host, time range) |
| `/api/v1/alerts/{alert_id}` | GET | Retrieve single alert including linked events |
| `/api/v1/alerts/{alert_id}/status` | PATCH | Update alert status (analyst action) |
| `/api/v1/incidents` | GET | List incidents |
| `/api/v1/incidents/{incident_id}` | GET | Retrieve incident with linked alerts and events |
| `/api/v1/stats/pipeline` | GET | Pipeline throughput statistics for dashboard |

### Real-Time Alert Delivery

**Decision to be confirmed by DJ:** WebSocket push vs. polling REST.

**If WebSocket:** Server sends alert notification on alert creation; frontend subscribes to `/ws/alerts`.  
**If polling:** Frontend polls `/api/v1/alerts?since=<timestamp>` on a configurable interval.

The choice affects Redis usage (WebSocket connection state) and backend architecture. DJ must confirm this by Week 7 start.

### Search Requirements

For event and alert search to be useful:

- PostgreSQL indexes on `timestamp`, `host`, `source`, `event_type`, `source_ip`, `destination_ip`, `severity` (defined in Week 5 schema above)
- Full-text search on `command_line` and `domain` requires PostgreSQL GIN index on `metadata` JSONB or dedicated text columns
- Filtering must use parameterized queries (`REQ-INPUT-011`)
- Search results must be paginated (cursor-based or offset); no unbounded queries

### Infrastructure Dependencies

| Dependency | Role | Owner |
|------------|------|-------|
| PostgreSQL | Alert and incident persistence; event search | DJ |
| Redis | Alert deduplication state; WebSocket session state (if used) | DJ |
| FastAPI | REST API layer exposing events, alerts, incidents | DJ |
| Kafka | Alert notifications (optional: produce to `autosoc.alerts` topic for downstream consumers) | DJ |

### Testing Requirements

| Test | Description |
|------|-------------|
| **Alert dedup test** | Inject two Detection Results with identical (detector_id, host, time_bucket); confirm only one alert is created; `alert.count = 2` |
| **Alert creation test** | Inject one Detection Result; confirm an Alert is created in PostgreSQL with all required fields |
| **Incident grouping test** | Inject multiple alerts for the same host within the grouping window; confirm they are grouped into one incident |
| **API endpoint tests** | Test each endpoint with valid and invalid parameters; confirm correct HTTP status codes and response schemas |
| **Realtime delivery test** | Confirm alert notification reaches frontend within acceptable latency after Detection Result is produced |
| **Search test** | Execute queries for each indexed field; confirm results are correct and paginated |

### Security Requirements

- All API endpoints must enforce RBAC (`REQ-RBAC-001`, `REQ-RBAC-002`)
- Alert status mutation endpoints require `Analyst` or higher role
- All query parameters validated before database lookup (`REQ-INPUT-001`)
- Pagination limits enforced; no `limit=0` or arbitrarily large page sizes
- Real-time channel (WebSocket if used) requires authentication before connection is accepted
- CSRF protection applied to state-changing browser endpoints (`REQ-INPUT-012`)
- Rate limiting on all endpoints (`REQ-RATE-002`)

---

## Cross-Phase Dependencies

| Dependency | Blocking |
|------------|---------|
| DJ must provision Kafka topics before Week 4 source testing | Week 4 |
| Pranjal must finalize field mappings for all 4 source types before Week 5 parsers | Week 5 |
| DJ must create PostgreSQL `events` table (DDL finalized from Week 5 schema) before normalization writes | Week 5 |
| Pranjal must deliver initial Sigma rule set (20+ rules) before Week 6 detection | Week 6 |
| DJ must expose REST endpoints before Week 7 frontend integration | Week 7 |
| Shreyash must confirm WebSocket vs. polling before Week 7 real-time implementation | Week 7 |

---

## Phase 2 Out of Scope

The following capabilities are explicitly excluded from Phase 2 (Weeks 4–7):

| Capability | Reason |
|------------|--------|
| ML-based detection | Requires labeled training data from dataset evaluation; planned post-Phase 2 |
| Threat intelligence API integration | MISP/OpenCTI/VirusTotal integration requires API key setup and TI feed configuration; planned post-Phase 2 |
| LLM/AI agent triage | Requires stable alert/incident schema and LLM infrastructure; planned post-Phase 2 |
| RAG / knowledge base | Requires Qdrant ingestion pipeline and embedding infrastructure; planned post-Phase 2 |
| Attack graph (Neo4j) | Planned for later phase per architecture decisions |
| Automated response | Requires human-in-the-loop validation before any automation |
| Real endpoint telemetry | Phase 2 uses dataset replay and lab VMs only; production endpoint integration later |

---

*Document created by Pranjal — Day 2. Week-level plans require DJ sign-off on infrastructure timeline before work begins.*
