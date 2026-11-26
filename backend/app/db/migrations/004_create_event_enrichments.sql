-- AutoSOC Day 9 Migration 004: Normalized Event Enrichments
-- Stores separate, deterministic security enrichment records linked to
-- normalized_events via ON DELETE RESTRICT foreign keys so neither raw
-- envelopes nor normalized event records are modified or orphaned.

CREATE TABLE IF NOT EXISTS event_enrichments (
    id                      SERIAL PRIMARY KEY,
    enrichment_id           VARCHAR(36) NOT NULL,
    normalized_event_row_id INTEGER NOT NULL,
    event_id                VARCHAR(36) NOT NULL,
    ingestion_id            VARCHAR(36) NOT NULL,
    provider                VARCHAR(64) NOT NULL,
    enrichment_status       VARCHAR(32) NOT NULL,
    enrichment_data         JSONB NOT NULL DEFAULT '{}'::jsonb,
    provenance              JSONB NOT NULL DEFAULT '{}'::jsonb,
    enrichment_warnings     JSONB NOT NULL DEFAULT '[]'::jsonb,
    enrichment_errors       JSONB NOT NULL DEFAULT '[]'::jsonb,
    attempt_count           INTEGER NOT NULL DEFAULT 1,
    enriched_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_event_enrichments_enrichment_id UNIQUE (enrichment_id),
    CONSTRAINT uq_event_enrichments_norm_row_id UNIQUE (normalized_event_row_id),
    CONSTRAINT uq_event_enrichments_event_id UNIQUE (event_id),
    CONSTRAINT uq_event_enrichments_ingestion_id UNIQUE (ingestion_id),
    CONSTRAINT fk_event_enrichments_norm_row
        FOREIGN KEY (normalized_event_row_id) REFERENCES normalized_events(id) ON DELETE RESTRICT,
    CONSTRAINT fk_event_enrichments_event_id
        FOREIGN KEY (event_id) REFERENCES normalized_events(event_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_event_enrichments_status
    ON event_enrichments (enrichment_status);

CREATE INDEX IF NOT EXISTS idx_event_enrichments_provider
    ON event_enrichments (provider);

CREATE INDEX IF NOT EXISTS idx_event_enrichments_created_at_id
    ON event_enrichments (created_at DESC, id DESC);
