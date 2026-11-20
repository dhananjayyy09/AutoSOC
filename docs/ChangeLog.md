# AutoSOC — ChangeLog

> **Purpose:** Records WHAT changed in the AutoSOC repository. Every file creation, modification, deletion, or substantial restructuring must have an entry. Entries must be specific — never vague.
>
> **Format:**
> - **Date:** Calendar date (YYYY-MM-DD) and development day
> - **Task:** One-line description of the work
> - **Files:** Files changed
> - **What changed:** Specific changes made
> - **Reason:** Why the change was made
> - **Verification:** How correctness was confirmed
> - **Status:** COMPLETE / IN PROGRESS / SUPERSEDED

---

## 2026-11-20 (Day 2)

---

### CL-001 — Create security-data-contract.md

| Attribute | Detail |
|-----------|--------|
| **Task** | Create the master Security Data Contract for the AutoSOC Day 2 security data architecture |
| **Files created** | `docs/security/security-data-contract.md` |
| **What changed** | New document created. Contains: (1) Data model hierarchy (Raw Event → Parsed Event → Normalized Security Event → Feature Set → Detection Result → Alert → Incident). (2) Complete Normalized Security Event field table with classification, type, owner, and validation expectation for every field including new Day 2 fields `ingestion_id`, `event_category`, `metadata.raw_hash`. (3) Event category taxonomy. (4) `ingestion_id` vs `event_id` vs `source_event_id` disambiguation. (5) Complete event lifecycle with 8 stages: Telemetry Source, Ingestion, Parsing, Normalization, Validation, Feature Extraction, Detection, Alert Generation, Triage — each with input, transformation, output, failure behavior, infrastructure dependency, downstream consumer, and implementation status. (6) Malformed and rejected event handling table. (7) Feature Set contract with feature schema and derivation rules. (8) Detection Result contract with full schema. (9) `detector_type` enum definition. (10) Terminology disambiguation (Security Event ≠ Detection Result ≠ Alert ≠ Incident). (11) Source adapter contracts for Sysmon, Zeek, Suricata, Authentication logs. (12) Duplicate event strategy with identifier semantics and three deduplication levels. (13) Architectural boundaries with component responsibility table and 9 interface rules. (14) Research evaluation metadata table. |
| **Reason** | Day 2 objective: formalize the security data architecture so Phase 2 implementation is unambiguous. Existing Day 1 documentation (security-event-model.md, detection-pipeline.md) lacked: a single consolidated contract, the Validation stage as explicit lifecycle stage, `ingestion_id`/`event_category` fields, the Detection Result contract, the Feature Set contract, source adapter contracts, and a deduplication strategy. |
| **Verification** | Document reviewed for internal consistency: all field classifications are explicit; all lifecycle stages have input/output/failure; event hierarchy is consistent; infrastructure references match Day 1 decisions (Kafka, PostgreSQL, Redis, Qdrant, no Elasticsearch/TimescaleDB as current dependencies) |
| **Status** | COMPLETE |

---

### CL-002 — Create phase2-implementation-plan.md

| Attribute | Detail |
|-----------|--------|
| **Task** | Create the Phase 2 (Weeks 4–7) security data layer implementation plan |
| **Files created** | `docs/security/phase2-implementation-plan.md` |
| **What changed** | New document created. Covers: Week 4 (Event Ingestion) — Kafka topic architecture, ingestion envelope schema, infrastructure dependencies, testing requirements, security requirements. Week 5 (Parsing and Normalization) — per-source parser contracts, normalization steps, validation routing, conceptual PostgreSQL events table DDL with indexes, schema versioning strategy, testing and security requirements. Week 6 (Feature Extraction and Detection) — feature implementation plan, Sigma rule-based detection approach, conceptual detection_results DDL, correlation anchor fields, testing and security requirements. Week 7 (Alert/Incident/Search/Realtime) — alert dedup implementation, incident grouping criteria, required API endpoints for frontend, search requirements with indexing strategy, WebSocket vs. polling decision item, testing and security requirements. Cross-phase dependencies table. Out-of-scope capabilities table (ML, TI APIs, LLM, RAG, attack graph). |
| **Reason** | Day 2 objective: prepare Phase 2 implementation so work is unambiguous. No implementation was performed. This is a planning document. |
| **Verification** | Reviewed for consistency with security-data-contract.md and Day 1 infrastructure decisions. No new infrastructure introduced. No scope expansion beyond agreed architecture. |
| **Status** | COMPLETE |

---

### CL-003 — Create ChangeLog.md, Decisions.md, Flow.md

| Attribute | Detail |
|-----------|--------|
| **Task** | Initialize mandatory traceability documentation |
| **Files created** | `docs/ChangeLog.md`, `docs/Decisions.md`, `docs/Flow.md` |
| **What changed** | Three new files created in `docs/`. ChangeLog.md: records what changed. Decisions.md: records why architecture decisions were made. Flow.md: documents how the security data flows through the pipeline. |
| **Reason** | Mandatory from Day 2 onward per project requirements. These files did not exist in the Day 1 baseline. Initialized with Day 2 entries only — no fabricated Day 1 historical entries. |
| **Verification** | Files created with accurate Day 2 content only. No Day 1 history invented. |
| **Status** | COMPLETE |

---

### CL-004 — Update security-event-model.md

| Attribute | Detail |
|-----------|--------|
| **Task** | Add Day 2 fields (`ingestion_id`, `event_category`, `metadata.raw_hash`) and update document status |
| **Files modified** | `docs/security/security-event-model.md` |
| **What changed** | (1) Added `ingestion_id` field (UUID v4, Required, Ingestion layer) to core schema JSON block and Section 4 field definitions. (2) Added `event_category` field (string enum, Required, Normalization layer) to core schema JSON block and Section 4 field definitions. (3) Added `metadata.raw_hash` to the standard `metadata` sub-keys table. (4) Updated document version to 0.2.0 and status to "Active — Day 2". (5) Updated open issues to mark `ingestion_id`/`event_category`/`raw_hash` as resolved by this update. |
| **Reason** | Day 2 architecture review identified three missing fields: `ingestion_id` (needed to distinguish delivery attempts from events), `event_category` (needed for efficient high-level filtering), `metadata.raw_hash` (needed for exact-duplicate detection). These fields are referenced throughout security-data-contract.md and must be in the authoritative schema document. |
| **Verification** | Reviewed updated event model for consistency with security-data-contract.md field table. All three fields now consistently defined in both documents. |
| **Status** | COMPLETE |

---

### CL-005 — Update detection-pipeline.md

| Attribute | Detail |
|-----------|--------|
| **Task** | Add explicit Validation stage to pipeline diagram and stage definitions; update document status |
| **Files modified** | `docs/security/detection-pipeline.md` |
| **What changed** | (1) Added Validation stage between Normalization and Feature Extraction in the ASCII pipeline diagram. (2) Added Section 3.3.5 (Validation Stage) as an explicit pipeline stage definition between Normalization and Feature Extraction. (3) Updated Data Flow Contracts table to include the Normalization → Validation → Feature Extraction boundaries. (4) Updated document version to 0.1.2 and Last Updated to 2026-11-20. |
| **Reason** | The Day 1 detection-pipeline.md listed schema validation as step 10 inside the Normalization stage, but it was not represented as an independent stage in the pipeline diagram or stage definitions. security-data-contract.md defines Validation as a distinct, critical stage (the gatekeeper between normalization and detection). The pipeline diagram must reflect the agreed architecture. |
| **Verification** | Reviewed updated diagram and stage definitions; Validation now appears explicitly between Normalization and Feature Extraction in both the diagram and the stage definition list. Data flow contracts table updated consistently. |
| **Status** | COMPLETE |

---

### CL-006 — Update README.md

| Attribute | Detail |
|-----------|--------|
| **Task** | Add Day 2 status entries and new document references |
| **Files modified** | `README.md` |
| **What changed** | (1) Added Day 2 status section with completed items. (2) Added new files (`security-data-contract.md`, `phase2-implementation-plan.md`, `ChangeLog.md`, `Decisions.md`, `Flow.md`) to the repository layout section. |
| **Reason** | README must reflect the current repository state so all developers can discover new files. |
| **Verification** | Reviewed README after edit; new files listed; no Day 1 items modified. |
| **Status** | COMPLETE |

---

*ChangeLog maintained by Pranjal (security/data) for Pranjal's files. DJ updates this file for infrastructure/backend changes. Shreyash updates for frontend changes. All entries must be made in the same task as the change.*
