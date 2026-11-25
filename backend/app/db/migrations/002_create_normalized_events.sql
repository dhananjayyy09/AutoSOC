-- AutoSOC Day 7 Migration 002: Normalized Security Events
-- Creates the normalized_events table linked to raw_event_envelopes via
-- ON DELETE RESTRICT foreign keys so immutable raw source evidence is preserved.
--
-- Idempotent PostgreSQL DDL matching app.events.models.NormalizedEvent.

CREATE TABLE IF NOT EXISTS normalized_events (
    id                      SERIAL PRIMARY KEY,
    event_id                VARCHAR(36),
    raw_envelope_id         INTEGER NOT NULL,
    ingestion_id            VARCHAR(36) NOT NULL,
    event_timestamp         VARCHAR(64),
    source_type             VARCHAR(32) NOT NULL,
    sensor_id               VARCHAR(255) NOT NULL,
    event_category          VARCHAR(32),
    event_type              VARCHAR(64),
    host                    TEXT,
    user_name               TEXT,
    source_ip               VARCHAR(45),
    destination_ip          VARCHAR(45),
    source_port             INTEGER,
    destination_port        INTEGER,
    protocol                VARCHAR(16),
    process                 TEXT,
    file_hash               TEXT,
    domain                  TEXT,
    command_line            TEXT,
    severity                INTEGER,
    metadata                JSONB NOT NULL DEFAULT '{}'::jsonb,
    normalization_status    VARCHAR(32) NOT NULL,
    normalization_errors    JSONB NOT NULL DEFAULT '[]'::jsonb,
    normalization_warnings  JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_normalized_events_event_id UNIQUE (event_id),
    CONSTRAINT uq_normalized_events_ingestion_id UNIQUE (ingestion_id),
    CONSTRAINT fk_normalized_events_raw_envelope
        FOREIGN KEY (raw_envelope_id) REFERENCES raw_event_envelopes(id) ON DELETE RESTRICT,
    CONSTRAINT fk_normalized_events_ingestion_id
        FOREIGN KEY (ingestion_id) REFERENCES raw_event_envelopes(ingestion_id) ON DELETE RESTRICT
);

-- Index supporting raw_envelope_id foreign-key lookups
CREATE INDEX IF NOT EXISTS ix_normalized_events_raw_envelope_id
    ON normalized_events (raw_envelope_id);

-- Index supporting filtering by normalization_status (normalized, failed, etc.)
CREATE INDEX IF NOT EXISTS ix_normalized_events_status
    ON normalized_events (normalization_status);

-- Composite index supporting deterministic descending retrieval of recent normalized events
CREATE INDEX IF NOT EXISTS idx_normalized_events_created_at_id
    ON normalized_events (created_at DESC, id DESC);
