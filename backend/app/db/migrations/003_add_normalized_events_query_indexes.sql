-- AutoSOC Day 8 Migration 003: Normalized Events Query Indexes
-- Adds B-tree indexes supporting server-side filtering, time-range queries,
-- and deterministic sorting in the Event Explorer & Query API.

CREATE INDEX IF NOT EXISTS idx_normalized_events_event_timestamp
    ON normalized_events (event_timestamp DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_normalized_events_source_type
    ON normalized_events (source_type);

CREATE INDEX IF NOT EXISTS idx_normalized_events_category_type
    ON normalized_events (event_category, event_type);

CREATE INDEX IF NOT EXISTS idx_normalized_events_severity
    ON normalized_events (severity);
