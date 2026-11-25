-- AutoSOC Day 6 Migration 001: Raw Security Event Envelopes
-- Creates the raw_event_envelopes table for persisting validated IngestionEnvelope
-- payloads prior to Phase 2 parsing and normalization.
--
-- Idempotent PostgreSQL DDL matching app.events.models.RawEventEnvelope.

CREATE TABLE IF NOT EXISTS raw_event_envelopes (
    id                  SERIAL PRIMARY KEY,
    ingestion_id        VARCHAR(36) NOT NULL,
    source_type         VARCHAR(32) NOT NULL,
    sensor_id           VARCHAR(255) NOT NULL,
    ingest_time         VARCHAR(64) NOT NULL,
    raw_hash            VARCHAR(71) NOT NULL,
    raw_payload         TEXT NOT NULL,
    payload_size_bytes  INTEGER NOT NULL,
    possible_duplicate  BOOLEAN NOT NULL DEFAULT FALSE,
    processing_status   VARCHAR(32) NOT NULL DEFAULT 'accepted',
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_raw_event_envelopes_ingestion_id UNIQUE (ingestion_id)
);

-- Index supporting duplicate raw_hash detection on ingestion (Contract §7.3)
CREATE INDEX IF NOT EXISTS ix_raw_event_envelopes_raw_hash
    ON raw_event_envelopes (raw_hash);

-- Composite index supporting deterministic descending retrieval of recent envelopes
CREATE INDEX IF NOT EXISTS idx_raw_event_envelopes_received_at_id
    ON raw_event_envelopes (received_at DESC, id DESC);
