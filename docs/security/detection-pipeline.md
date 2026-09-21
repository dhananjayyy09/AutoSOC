# AutoSOC — Detection Pipeline Architecture

**Version:** 0.1.0  
**Owner:** Pranjal (Cybersecurity Pipeline)  
**Status:** Draft — Day 1  
**Last Updated:** 2026-09-21

---

## 1. Purpose

This document describes the end-to-end detection pipeline for AutoSOC — from raw telemetry ingestion through alert generation and incident creation. It defines the boundaries between pipeline stages and documents how future ML and AI components will integrate.

> **Day 1 scope:** This is a design and architecture document. No stage implementations exist yet. The goal is to establish clear contracts between stages so that DJ (infrastructure), Pranjal (detection), and Shreyash (visualization) can build toward compatible interfaces.

---

## 2. Pipeline Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           AutoSOC Detection Pipeline                            │
└─────────────────────────────────────────────────────────────────────────────────┘

  [Telemetry Sources]
       │
       │  Raw bytes, XML, JSON, TSV
       ▼
┌─────────────┐
│   INGESTION  │  ← Beats, Kafka, syslog, flat-file tail
│   LAYER      │
└──────┬───────┘
       │  Raw event strings
       ▼
┌─────────────┐
│   PARSING    │  ← Source-specific parsers (Sysmon XML, Zeek TSV, Suricata EVE JSON)
│   STAGE      │
└──────┬───────┘
       │  Parsed key-value maps (source schema)
       ▼
┌─────────────────┐
│  NORMALIZATION   │  ← Apply field mappings → Normalized Security Event (see event model)
│  STAGE           │  ← Assign event_id, ingest_time, pipeline_version
└────────┬─────────┘
         │  Normalized Security Events (JSON)
         ▼
┌─────────────────────┐
│  FEATURE EXTRACTION  │  ← Extract structured features for detection & ML
│  STAGE               │
└──────────┬───────────┘
           │  Feature vectors + enriched events
           ▼
┌──────────────────────────────────────────────────────────────────┐
│                       DETECTION LAYER                             │
│                                                                   │
│  ┌───────────────┐  ┌──────────────┐  ┌────────────────────┐    │
│  │  Rule-Based   │  │  ML-Based    │  │  Threat Intel       │    │
│  │  Detection    │  │  Detection   │  │  Enrichment         │    │
│  │  (Sigma)      │  │  (Future)    │  │  (Future)           │    │
│  └───────┬───────┘  └──────┬───────┘  └─────────┬──────────┘    │
│          │                 │                     │               │
│          └─────────────────┴─────────────────────┘               │
│                            │                                      │
│                    ┌───────┴───────┐                              │
│                    │  Correlation  │  ← Cross-event grouping      │
│                    │  Engine       │  (Future)                    │
│                    └───────┬───────┘                              │
└────────────────────────────┼─────────────────────────────────────┘
                             │  Detection results
                             ▼
                    ┌────────────────┐
                    │  ALERT         │  ← Deduplicated, enriched alert objects
                    │  GENERATION    │
                    └───────┬────────┘
                            │  Alert objects
                            ▼
                    ┌────────────────┐
                    │  TRIAGE &      │  ← LLM agents (future) + analyst queue
                    │  INCIDENT      │
                    │  CREATION      │
                    └───────┬────────┘
                            │  Incidents
                            ▼
                    ┌────────────────┐
                    │  STORAGE &     │  ← Elasticsearch / TimescaleDB / flat files
                    │  INDEXING      │
                    └───────┬────────┘
                            │
                            ▼
                    ┌────────────────┐
                    │  DASHBOARD     │  ← Shreyash's frontend
                    │  (Shreyash)    │
                    └────────────────┘
```

---

## 3. Stage Definitions

### 3.1 Ingestion Layer

**Responsibility:** Transport raw telemetry from sources into the pipeline.

**Inputs:**
- Windows Event Forwarding (WEF) → Winlogbeat/Filebeat
- Zeek log files (tail or Kafka)
- Suricata EVE JSON stream (tail or Kafka)
- Future: cloud trail logs, EDR APIs, SIEM forwarding

**Outputs:** Raw event strings (XML, JSON, TSV) queued for parsing.

**Interface contract (for DJ):**
- Queue must provide at-least-once delivery
- Each message tagged with: `source_type`, `sensor_id`, `received_at`
- Back-pressure mechanism required for burst traffic

**Current status:** To be implemented by DJ (infrastructure).

---

### 3.2 Parsing Stage

**Responsibility:** Transform raw strings into structured key-value maps using source-specific parsers.

**One parser per source:**

| Source | Parser approach | Input format |
|--------|----------------|--------------|
| Sysmon | XML → dict | Windows XML EventLog |
| Zeek | TSV / JSON → dict | Per-log-type schemas |
| Suricata | JSON → dict | EVE JSON (all event types) |
| Windows Event Log | XML → dict | EVTX via Winlogbeat |
| auditd | Key=value string | `audit.log` |

**Outputs:** `ParsedEvent` objects: source schema as a flat dict plus `source_type` and `received_at`.

**Error handling:**
- Malformed events → routed to `parse_error` queue with original raw bytes preserved
- Unknown source type → rejected with error logged

**Interface contract:** Parsers must be stateless, pure functions: `raw_string → ParsedEvent | ParseError`.

---

### 3.3 Normalization Stage

**Responsibility:** Map `ParsedEvent` fields to the AutoSOC Normalized Security Event schema (see `security-event-model.md`).

**Steps:**
1. Apply source-specific field mapping (documented in event model Section 5)
2. Generate `event_id` (UUID v4)
3. Stamp `metadata.ingest_time`
4. Normalize timestamps to UTC ISO 8601
5. Normalize IP addresses to canonical form
6. Normalize `protocol`, `user` fields
7. Assign `severity` from source-specific mapping
8. Classify `event_type` from source event code
9. Place unmapped fields in `metadata.source_fields`
10. Run schema validation (rules in event model Section 8)

**Outputs:** Normalized Security Event JSON objects (conforming to `security-event-model.md`).

**Idempotency:** Normalization must be idempotent — re-running on the same ParsedEvent produces the same NormalizedEvent (except `event_id` which is generated once and preserved on replay via `metadata.source_event_id` lookup).

---

### 3.4 Feature Extraction Stage

**Responsibility:** Derive structured features from normalized events to feed into detection rules and (future) ML models.

**Feature categories:**

| Category | Examples | Used By |
|----------|---------|---------|
| **Categorical** | `event_type`, `source`, `protocol`, `severity` | Rules, ML |
| **Network** | `source_ip`, `destination_ip`, `destination_port`, IP range flags | Rules, ML |
| **Process** | `process` name, `command_line` length, encoded command flag, `parent_process` | Rules, ML |
| **File** | `file_hash` entropy (filename), extension category | Rules, ML |
| **DNS** | Domain length, entropy, number of subdomains, TLD | Rules, ML |
| **Temporal** | Hour of day, day of week, time since last event from same host | ML |
| **Behavioral** | Frequency of event type per host/user in rolling window | ML (future) |

**Day 1:** Define the feature schema in a separate `docs/security/feature-schema.md` (future). Today, document conceptual categories only.

**Outputs:** Enriched event objects with `features` sub-object attached.

---

### 3.5 Detection Layer

The detection layer consists of four distinct detection mechanisms. These are **architecturally separate** with well-defined interfaces but may share results and feed into each other.

---

#### 3.5.1 Rule-Based Detection (Sigma)

**Purpose:** Deterministic, human-authored detection rules expressed in Sigma format, converted to backend-specific query languages.

**Input:** Normalized Security Events  
**Output:** Rule match results: `{rule_id, rule_name, severity, matched_event_id, mitre_techniques}`

**Sigma integration approach:**
- Sigma rules authored against the AutoSOC normalized field names
- `pySigma` used to compile rules to target backends (Elasticsearch, Splunk, OpenSearch)
- Rule set: community Sigma rules (filtered and curated) + AutoSOC-specific rules
- Rule updates: pull from Sigma GitHub releases; review before deployment

**Advantages of Sigma:**
- Vendor-agnostic; compiled to multiple backends
- Community-maintained rule library (thousands of rules)
- MITRE ATT&CK technique tags built into rule format
- Explainable by nature: each rule has a name, description, and author

**Limitations:**
- High false-positive rate without tuning
- Cannot detect novel/unseen attack patterns
- No behavioral baselines; each rule evaluates events in isolation

**Future AutoSOC-specific rules will cover:**
- Encoded PowerShell (`command_line` contains `-EncodedCommand` / `-enc`)
- LOLBIN abuse (living off the land binaries)
- Suspicious DNS (DGA-like domains, high-entropy queries)
- Lateral movement (SMB to new hosts, PsExec artifacts)
- Persistence mechanisms (registry run keys, scheduled tasks)

**Status:** Rule authoring begins Day 2+. Today: architecture only.

---

#### 3.5.2 ML-Based Detection (Future)

**Purpose:** Statistical and learned models that detect anomalous behavior not covered by static rules.

> **Do not implement today.** This section documents the intended architecture for future reference.

**Planned approaches:**

| Approach | Target | Model Family |
|----------|--------|-------------|
| Anomaly detection | Network flows (Zeek conn.log) | Isolation Forest, Autoencoder |
| Classification | Labeled attack events | Random Forest, XGBoost, LightGBM |
| Sequence modeling | Process execution chains | LSTM, Transformer |
| Graph anomaly | Lateral movement (host-to-host graph) | GNN (GraphSAGE) |
| LLM-based | Command-line analysis, log reasoning | Fine-tuned LLM + RAG |

**Interface contract (for future implementation):**
- ML models expose a `score(NormalizedEvent) → DetectionResult` interface
- DetectionResult includes: `model_id`, `score`, `confidence`, `explanation`, `features_used`
- Models are version-controlled and loaded by the pipeline via a model registry
- Explanations must be machine-readable (SHAP values) for the LLM agent to consume

**Datasets for training:** See `docs/research/dataset-plan.md`.

---

#### 3.5.3 Correlation Engine (Future)

**Purpose:** Link related events across time and across sources into attack chains.

> **Do not implement today.**

**Planned capabilities:**
- Temporal correlation: events from the same host within a time window
- Causal correlation: parent-child process chains, network connections spawned by suspicious processes
- Multi-stage correlation: map event sequences to kill chain / ATT&CK tactics
- Cross-source correlation: Sysmon process + Zeek network connection from same host

**Key challenge:** Entity resolution — linking a Sysmon host name to a Zeek `id.orig_h` IP to a Suricata alert requires an asset inventory (future).

---

#### 3.5.4 Threat Intelligence Enrichment (Future)

**Purpose:** Enrich normalized events with external threat intelligence.

> **Do not implement today.**

**Planned TI sources:**
- IP reputation: VirusTotal, AbuseIPDB, Shodan
- Domain reputation: VirusTotal, URLhaus
- File hash lookup: VirusTotal, MalwareBazaar, MISP
- MISP feeds for IOC sets
- OpenCTI for structured threat intelligence

**Enrichment adds to `metadata.threat_intel`:**
```json
{
  "metadata": {
    "threat_intel": {
      "ip_score": 85,
      "ip_categories": ["c2", "tor_exit"],
      "domain_score": null,
      "hash_known_malware": false,
      "sources": ["abuseipdb", "virustotal"]
    }
  }
}
```

---

### 3.6 Alert Generation

**Responsibility:** Convert detection results into deduplicated, enriched Alert objects.

**Alert object schema (draft):**

```json
{
  "alert_id": "<uuid>",
  "created_at": "<ISO 8601 UTC>",
  "rule_id": "<string | null>",
  "model_id": "<string | null>",
  "title": "<string>",
  "description": "<string>",
  "severity": "<integer 1-5>",
  "mitre_tactics": ["<string>"],
  "mitre_techniques": ["<string>"],
  "event_ids": ["<uuid>"],
  "host": "<string>",
  "user": "<string | null>",
  "source_ip": "<string | null>",
  "destination_ip": "<string | null>",
  "status": "open | acknowledged | closed | false_positive",
  "assigned_to": "<string | null>",
  "explanation": "<string | null>",
  "metadata": {}
}
```

**Deduplication strategy (to be finalized):**
- Hash key = `(rule_id OR model_id) + host + 5-minute time bucket`
- Duplicate firing within hash key increments a `count` field rather than creating a new alert
- Dedup window configurable per rule

---

### 3.7 Triage and Incident Creation

**Responsibility:** Group related alerts into Incidents and drive triage decisions.

**Day 1:** Architecture documented. LLM-agent triage is a core AutoSOC differentiator and will be designed in detail by DJ.

**Incident object schema (draft):**

```json
{
  "incident_id": "<uuid>",
  "created_at": "<ISO 8601 UTC>",
  "title": "<string>",
  "summary": "<string>",
  "severity": "<integer 1-5>",
  "status": "new | investigating | contained | closed",
  "alert_ids": ["<uuid>"],
  "affected_hosts": ["<string>"],
  "affected_users": ["<string>"],
  "mitre_tactics": ["<string>"],
  "mitre_techniques": ["<string>"],
  "assigned_analyst": "<string | null>",
  "llm_triage_summary": "<string | null>",
  "llm_recommended_actions": ["<string>"],
  "timeline": []
}
```

**LLM triage flow (future):**
1. Alert group received by triage agent
2. Agent fetches raw events from storage
3. Agent queries RAG store for relevant threat reports / playbooks
4. Agent reasons about attacker intent, affected assets, MITRE mapping
5. Agent outputs: severity assessment, summary, recommended actions, confidence
6. Output written to `llm_triage_summary` and `llm_recommended_actions`
7. Human analyst reviews and acts

---

## 4. Data Flow Contracts

| Boundary | Format | Schema |
|----------|--------|--------|
| Ingestion → Parsing | Raw bytes + metadata envelope | `{source_type, sensor_id, received_at, raw_payload}` |
| Parsing → Normalization | ParsedEvent JSON | Source-native field names + `source_type`, `received_at` |
| Normalization → Feature Extraction | NormalizedEvent JSON | AutoSOC event model (`security-event-model.md`) |
| Feature Extraction → Detection | EnrichedEvent JSON | NormalizedEvent + `features` object |
| Detection → Alert Generation | DetectionResult JSON | `{detector_type, rule_id, model_id, score, event_id, mitre_techniques}` |
| Alert Generation → Triage | Alert JSON | Alert schema (Section 3.6) |
| Triage → Storage | Incident JSON | Incident schema (Section 3.7) |
| Storage → Dashboard | REST API / WebSocket | To be defined by DJ |

---

## 5. Pipeline Quality Requirements

| Requirement | Target | Notes |
|-------------|--------|-------|
| **Throughput** | ≥ 10,000 EPS sustained | Events Per Second; Zeek on busy network generates significant volume |
| **Latency (normalization)** | < 100 ms p99 | Event to normalized output |
| **Latency (detection, rules)** | < 500 ms p99 | Normalized event to alert |
| **Availability** | 99.9% | Detection pipeline must not be a single point of failure |
| **Data loss** | Zero tolerance for alerts; acceptable for low-severity telemetry under extreme load | |
| **False negative rate** | To be evaluated against benchmark datasets | |
| **False positive rate** | Analyst-tunable; target < 5% high-severity FP rate | |

> These are design targets. Actual benchmarks will follow dataset evaluation.

---

## 6. Pipeline Configuration

Each stage will be configurable via YAML. Example (conceptual, not yet implemented):

```yaml
# autosoc-pipeline.yaml (DRAFT)

ingestion:
  sources:
    - type: sysmon
      transport: winlogbeat
      host: "*"
    - type: suricata
      transport: filebeat
      path: /var/log/suricata/eve.json
    - type: zeek
      transport: filebeat
      path: /var/log/zeek/

normalization:
  timezone_default: UTC
  ip_redact_internal: false
  max_raw_event_bytes: 65536

detection:
  rules:
    enabled: true
    sigma_rules_path: ./rules/sigma/
    backends: [elasticsearch]
  ml:
    enabled: false  # Day 1: off
  threat_intel:
    enabled: false  # Day 1: off

alerts:
  dedup_window_seconds: 300
  min_severity_to_alert: 2
```

---

## 7. Open Questions / Blockers

| # | Question | Owner | Priority |
|---|---------|-------|---------|
| 1 | What message queue does DJ plan to use? (Kafka, Redis Streams, RabbitMQ) | DJ | High |
| 2 | What storage backend for normalized events? (Elasticsearch, OpenSearch, TimescaleDB) | DJ | High |
| 3 | How will Winlogbeat/Filebeat be configured for lab testing? | DJ | High |
| 4 | What is the deployment environment for Day 1 pipeline tests? (Docker? local?) | DJ | Medium |
| 5 | Does Shreyash need real-time alert push (WebSocket) or polling REST API? | Shreyash | Medium |
| 6 | What is the alert → incident grouping logic? (time window? host? rule family?) | Pranjal + DJ | Medium |
| 7 | Will ML models be deployed as microservices or in-process? | DJ | Low (future) |

---

*Document maintained by Pranjal. Architecture review by DJ required before implementation begins.*
