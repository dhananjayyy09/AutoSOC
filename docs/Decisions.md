# AutoSOC — Architecture Decisions

> **Purpose:** Records WHY meaningful architectural decisions were made. This is not a log of documentation edits — only decisions with real trade-offs that another developer needs to understand to make future implementation choices correctly.
>
> **Format:**
> - **Decision ID and title**
> - **Date:** Calendar date (YYYY-MM-DD) and development day
> - **Status:** ACCEPTED / SUPERSEDED / DEFERRED
> - **Decision:** One-sentence statement of what was decided
> - **Context:** Why a decision was needed
> - **Reasoning:** Why this option was chosen
> - **Alternatives considered:** What else was evaluated
> - **Trade-offs:** What is gained and what is given up
> - **Consequences:** What must be true for this decision to hold

---

## DECISION-001 — `ingestion_id` is distinct from `event_id`

| Attribute | Detail |
|-----------|--------|
| **Date** | 2026-11-20 (Day 2) |
| **Status** | ACCEPTED |
| **Decision** | AutoSOC assigns two separate UUIDs per event: `ingestion_id` (assigned at ingestion, per delivery attempt) and `event_id` (assigned at normalization, per successfully normalized event). |
| **Context** | The pipeline uses Kafka with at-least-once delivery semantics. Beats agents can replay events on restart. Pipeline replay for reprocessing is a planned capability. Without separating delivery identity from event identity, it is impossible to distinguish "the same event delivered twice" from "two different events" or to trace which pipeline run produced a given normalized event. |
| **Reasoning** | `ingestion_id` identifies a delivery attempt — it changes on replay. `event_id` identifies the normalized event in AutoSOC — it is stable once assigned. This allows deduplication at the ingestion level (using `raw_hash`) and at the event level (using `source_event_id`) without conflating the two concerns. It also makes audit trails clear: a researcher can trace which ingestion attempt produced which event. |
| **Alternatives considered** | (1) Use only `event_id`, assigned at ingestion. Problem: cannot distinguish replay events; replay would produce the same ID twice, violating primary key constraints, or require complex idempotency logic at ingestion. (2) Use only `source_event_id` from the source. Problem: not all sources assign stable event IDs (Zeek UIDs are session-local, not globally unique). |
| **Trade-offs** | Gains: clean audit trail; replay safety; deduplication clarity. Costs: two UUID fields to manage; normalization must handle `ingestion_id` passthrough correctly. |
| **Consequences** | The `events` table must have both `event_id` (primary key) and `ingestion_id` (not unique; can appear multiple times in replay scenarios). Deduplication logic relies on `raw_hash` and `metadata.source_event_id`, not on `event_id` or `ingestion_id`. |

---

## DECISION-002 — `event_category` added as a required field above `event_type`

| Attribute | Detail |
|-----------|--------|
| **Date** | 2026-11-20 (Day 2) |
| **Status** | ACCEPTED |
| **Decision** | A new required field `event_category` is added to the Normalized Security Event schema as a high-level grouping above `event_type`. |
| **Context** | The Day 1 schema had only `event_type` (e.g., `process.create`, `network.dns`, `auth.failure`). Detection rules, dashboards, and future ML features frequently need to filter by broad category (all process events, all network events) without parsing the dot-notation subtype. Without `event_category`, every consumer must implement its own parsing of `event_type` prefixes, leading to inconsistent behavior. |
| **Reasoning** | A flat, explicit category field is simpler and faster to filter on than string prefix matching. It also survives future changes to the `event_type` taxonomy without breaking category-level filters. The taxonomy is deterministic: each `event_type` maps to exactly one `event_category`, so the field adds no ambiguity. |
| **Alternatives considered** | (1) Parse `event_category` from the `event_type` prefix at query time. Problem: requires all consumers (Sigma rules, dashboard filters, ML feature extractors) to implement the same parsing logic; brittle if `event_type` naming conventions change. (2) Use only `event_type` with a lookup table. Problem: requires the lookup table everywhere; PostgreSQL can't index a function result efficiently without a generated column. |
| **Trade-offs** | Gains: efficient database index on `event_category`; simpler rule authoring; consistent consumer behavior. Costs: one additional required field; normalization must set it correctly; schema migration needed for `events` table. |
| **Consequences** | Normalization must derive `event_category` from `event_type` using the taxonomy table in `security-data-contract.md` §2.3. Future `event_type` additions must include an `event_category` assignment. The `events` table must index `event_category`. |

---

## DECISION-003 — Validation is a distinct pipeline stage, separate from Normalization

| Attribute | Detail |
|-----------|--------|
| **Date** | 2026-11-20 (Day 2) |
| **Status** | ACCEPTED |
| **Decision** | Validation is implemented as a distinct pipeline stage after Normalization, not as the final step of Normalization. |
| **Context** | The Day 1 `detection-pipeline.md` listed schema validation as step 10 inside Normalization. This conflation creates several problems: (1) Normalization has a single responsibility — mapping fields; embedding validation creates mixed concerns. (2) Validation has distinct disposition logic (reject, accept-with-warning, accept) that is not part of field mapping. (3) Future schema validators may be implemented by a different team member or as a separate service; they need a clear input contract (a fully normalized event) rather than a partially normalized event. (4) Research evaluation needs to distinguish events that passed normalization from events that passed validation — these are different quality gates. |
| **Reasoning** | Single Responsibility Principle applied to pipeline stages. Normalization outputs a "best-effort" normalized event. Validation inspects the normalized event as a whole and makes a disposition decision. This separation allows normalization to be stateless and pure while validation can apply cross-field semantic checks that require the full event. |
| **Alternatives considered** | (1) Keep validation inside Normalization as the final step. Problem: mixed concerns; harder to test independently; validation logic changes affect normalization unit tests. (2) Validate before normalization. Problem: schema checks are impossible before normalization because raw events have source-specific field names; semantic checks require normalized fields. |
| **Trade-offs** | Gains: clean separation of concerns; independent testability; clear input/output contracts for each stage; research-useful distinction between normalization failures and validation failures. Costs: one more pipeline stage to implement and operate; events must be fully normalized before validation can run. |
| **Consequences** | The pipeline diagram must show Validation between Normalization and Feature Extraction (corrected in `detection-pipeline.md`). Detection receives only validated events. The `autosoc.errors.validation` dead-letter topic must exist. |

---

## DECISION-004 — Detection consumes normalized and validated events, not raw or parsed events

| Attribute | Detail |
|-----------|--------|
| **Date** | 2026-11-20 (Day 2) |
| **Status** | ACCEPTED |
| **Decision** | All detection mechanisms (rule-based, ML-based, correlation, threat intelligence enrichment) consume Normalized Security Events that have passed the Validation stage. Detection never operates on raw payloads, ParsedEvents, or events that failed validation. |
| **Context** | Early detection-pipeline design left the input to detection somewhat ambiguous. This decision closes that ambiguity. |
| **Reasoning** | (1) Rules authored against the normalized schema must receive normalized data — writing rules against source-specific field names (e.g., Sysmon `EventData.Image` instead of `process`) breaks cross-source detection. (2) ML models trained on normalized feature vectors cannot receive un-normalized input. (3) Validation ensures required fields are present and IPs are valid — detection rules can rely on these invariants. (4) Events that failed validation may have missing required fields; running detection on them would produce unreliable results. |
| **Alternatives considered** | (1) Run detection on raw events before normalization. Problem: requires separate rule sets per source; no cross-source detection possible. (2) Run detection on partially validated events. Problem: rules cannot rely on field invariants; false positives from corrupted fields. |
| **Trade-offs** | Gains: source-agnostic detection rules; reliable field invariants for rules; clean input contract. Costs: rejected events never enter detection (acceptable — if an event fails required field validation, it cannot be reliably detected against). |
| **Consequences** | Parsers, normalization, and validation must all complete before detection begins. The latency budget (normalization < 100 ms + validation overhead < 10 ms) must leave enough budget for detection < 500 ms p99. |

---

## DECISION-005 — Duplicate events are flagged, not silently discarded

| Attribute | Detail |
|-----------|--------|
| **Date** | 2026-11-20 (Day 2) |
| **Status** | ACCEPTED (deduplication window size and rejection threshold: DEFERRED to Phase 2 Week 5) |
| **Decision** | Events identified as probable duplicates (matching `raw_hash` within the dedup window, or matching `source_event_id` from the same source) are accepted into the `events` table with `metadata.possible_duplicate: true`. They are never silently discarded. |
| **Context** | At-least-once Kafka delivery and pipeline replay scenarios mean duplicate events are expected. The question is how to handle them: reject, discard, or flag. |
| **Reasoning** | Silently discarding events has unacceptable consequences for a security platform: (1) A forensic analyst replaying a pipeline to investigate an incident would find events missing from the event store with no explanation. (2) Research evaluation requires a complete event corpus — silent discards would cause false negatives in recall calculations. (3) The deduplication window and threshold require operational tuning; discarding events before the policy is tuned risks losing real events. Flagging is reversible; discarding is not. |
| **Alternatives considered** | (1) Reject duplicates at the Validation stage (do not store). Problem: pipeline replay loses events; forensic gaps; irreversible. (2) Reject at the Kafka consumer before normalization. Problem: source_event_id is not known until after parsing; raw_hash can be computed at ingestion but window management is complex. (3) Merge duplicate events into one record. Problem: complex merging logic; unclear which raw_event to preserve; loses delivery timing information. |
| **Trade-offs** | Gains: no data loss; reversible; forensic completeness; replay safety. Costs: duplicate events consume storage; downstream alerting must handle duplicates (handled by alert deduplication at a higher level). |
| **Consequences** | Redis dedup cache stores recent `raw_hash` and `source_event_id` values with TTL. The dedup window size (default: 5 minutes) must be configurable. Alert deduplication (Section 7 of `security-data-contract.md`) handles the case where duplicate events trigger duplicate detection results. |

---

## DECISION-006 — Source adapters are separate from normalization

| Attribute | Detail |
|-----------|--------|
| **Date** | 2026-11-20 (Day 2) |
| **Status** | ACCEPTED |
| **Decision** | Source-specific parsing logic (transforming raw payloads to source-native field dicts) is implemented separately from normalization logic (mapping source-native fields to the AutoSOC schema). |
| **Context** | The pipeline has two distinct problems: (1) understanding a source's native format (Sysmon XML, Zeek TSV, Suricata JSON) and (2) translating that format into the common AutoSOC schema. These are different levels of abstraction and change at different rates. |
| **Reasoning** | Separating these concerns means: (1) Adding a new telemetry source requires only a new parser + a new normalization mapping, without touching existing parsers. (2) Parsers can be tested with raw fixture data independently of the normalization schema. (3) The normalization layer has a stable, well-defined input contract (`ParsedEvent` with source-native fields), making it easier to test and document. (4) If the AutoSOC schema changes (e.g., a field is renamed), only the normalization mapping changes — parsers are unaffected. |
| **Alternatives considered** | (1) Combined parse-and-normalize in one function per source. Problem: schema changes break all combined functions; cannot reuse parsing logic for other consumers; harder to test; impossible to replay at different normalization versions. |
| **Trade-offs** | Gains: modularity; independent testability; supports schema evolution; easier to add new sources. Costs: two stages instead of one; `ParsedEvent` intermediate object to define and maintain. |
| **Consequences** | Parsers output source-native field names (e.g., `EventData.Image`, not `process`). Normalization receives `ParsedEvent` and applies the mapping. Field mapping tables in `security-event-model.md` §5 and `security-data-contract.md` §6 are the normalization spec, not the parser spec. |

---

## DECISION-007 — `metadata.raw_hash` is added as a derived required field

| Attribute | Detail |
|-----------|--------|
| **Date** | 2026-11-20 (Day 2) |
| **Status** | ACCEPTED |
| **Decision** | A SHA-256 hash of the raw event payload bytes is computed at ingestion and stored as `metadata.raw_hash` on every event. |
| **Context** | The deduplication strategy (DECISION-005) requires a mechanism to detect exact payload duplicates. The `source_event_id` is not always available (some sources do not assign stable IDs). A content hash of the raw payload is the only universally applicable exact-duplicate detection mechanism. |
| **Reasoning** | SHA-256 is collision-resistant and fast to compute. The hash is computed at ingestion before any parsing or normalization, so it reflects the actual raw payload. Computing it once and storing it avoids re-computing during validation and dedup checks. |
| **Alternatives considered** | (1) Hash the normalized event fields instead. Problem: normalization is not fully deterministic across pipeline versions (e.g., derived field changes); normalized hash would vary for the same raw event across versions. (2) Use `source_event_id` alone. Problem: not all sources assign stable IDs; Zeek UIDs are session-local. |
| **Trade-offs** | Gains: universally applicable; source-agnostic; computed once; enables exact dedup. Costs: 64-byte hex string stored on every event; SHA-256 computation at ingestion adds minor latency. |
| **Consequences** | Ingestion layer must compute SHA-256 of raw payload bytes before forwarding to parsing. `events` table does not need an index on `metadata.raw_hash` for general queries but should have it in the JSONB for dedup lookups. Redis dedup cache keys on `raw_hash`. |

---

## DECISION-008 — PostgreSQL is the primary event store; not Elasticsearch, OpenSearch, or TimescaleDB

| Attribute | Detail |
|-----------|--------|
| **Date** | 2026-10-07 (Day 1 cleanup) — recorded here for completeness |
| **Status** | ACCEPTED |
| **Decision** | Normalized events, alerts, detection results, and incidents are stored in PostgreSQL. Elasticsearch, OpenSearch, and TimescaleDB are deferred. |
| **Context** | Day 1 documentation contained ambiguous references to multiple storage backends as if they were concurrently selected. This was clarified during Day 1 cleanup. Recorded here as an authoritative architecture decision. |
| **Reasoning** | PostgreSQL is already provisioned in the Day 1 Docker infrastructure. For Phase 2 (Weeks 4–7), PostgreSQL with JSONB for `metadata` provides sufficient query capability without additional operational complexity. Elasticsearch/OpenSearch would require separate infrastructure and expertise. TimescaleDB is a PostgreSQL extension that can be adopted later without data migration if time-series performance becomes a bottleneck. |
| **Alternatives considered** | Elasticsearch (deferred), OpenSearch (deferred), TimescaleDB (deferred). See `security-tools.md` §9 for full evaluation. |
| **Trade-offs** | Gains: operational simplicity; single database; JSONB flexibility; transaction support. Costs: PostgreSQL full-text search is less powerful than Elasticsearch; may hit performance limits at very high event volumes (>10,000 EPS sustained). Mitigation: TimescaleDB extension available; Elasticsearch can be added as a separate read path later. |
| **Consequences** | All storage schemas must be PostgreSQL-compatible. Full-text search must use PostgreSQL GIN indexes or pg_trgm. Performance targets from `detection-pipeline.md` §5 must be validated against PostgreSQL under load. |

---

## DECISION-009 — Deduplication policy details deferred to Phase 2 Week 5

| Attribute | Detail |
|-----------|--------|
| **Date** | 2026-11-20 (Day 2) |
| **Status** | DEFERRED |
| **Decision** | The specific deduplication window size, Redis TTL, and threshold for `metadata.possible_duplicate` flagging are deferred to Phase 2 Week 5 implementation. |
| **Context** | The principle (flag, never discard) is decided (DECISION-005). The operational parameters require experimentation with actual event volumes and pipeline latencies that are not yet measurable. |
| **Reasoning** | Setting parameters without empirical data would be arbitrary. During Week 5 implementation, the team will observe actual event rates and pipeline latencies and set parameters accordingly. |
| **Consequences** | The `security-data-contract.md` notes deduplication window as "configurable." Configuration must be documented when implemented. |

---

*Decisions maintained by Pranjal for security/data decisions. DJ documents infrastructure and backend decisions. Decisions affecting multiple components require joint entry.*
