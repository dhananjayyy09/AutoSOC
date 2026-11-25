"""
AutoSOC - Security Event Persistence Models (SQLAlchemy 2.0)

Stores validated raw ingestion envelopes prior to Phase 2 parsing and normalization.
Preserves original raw_payload content verbatim and maintains ingestion_id uniqueness
and raw_hash indexing per docs/security/security-data-contract.md §2.4 & §7.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.db.base import Base

_JSONB_VARIANT = JSON().with_variant(JSONB(), "postgresql")


class RawEventEnvelope(Base):
    """
    SQLAlchemy model for raw security-event envelopes accepted at the ingestion boundary.
    Distinct from the future normalized `events` table to avoid Phase 2 schema collisions.
    """

    __tablename__ = "raw_event_envelopes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ingestion_id: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False, index=True
    )
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    sensor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    ingest_time: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_hash: Mapped[str] = mapped_column(String(71), nullable=False, index=True)
    raw_payload: Mapped[str] = mapped_column(Text, nullable=False)
    payload_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    possible_duplicate: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    processing_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="accepted"
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    __table_args__ = (
        # Supports deterministic descending retrieval of recent envelopes
        Index("idx_raw_event_envelopes_received_at_id", "received_at", "id"),
    )


class NormalizedEvent(Base):
    """
    SQLAlchemy model for normalized security events derived from RawEventEnvelope.
    Preserves raw evidence in `raw_event_envelopes` via restricted foreign keys and
    records normalization success, warnings, or failure without modifying raw payloads.
    """

    __tablename__ = "normalized_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[Optional[str]] = mapped_column(
        String(36), unique=True, nullable=True, index=True
    )
    raw_envelope_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("raw_event_envelopes.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    ingestion_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("raw_event_envelopes.ingestion_id", ondelete="RESTRICT"),
        unique=True,
        nullable=False,
        index=True,
    )

    event_timestamp: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    sensor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_category: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    event_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    host: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    user_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    process: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    domain: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    command_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Named `event_metadata` in Python to avoid shadowing SQLAlchemy DeclarativeBase.metadata
    event_metadata: Mapped[Dict[str, Any]] = mapped_column(
        "metadata", _JSONB_VARIANT, nullable=False, default=dict
    )

    normalization_status: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )
    normalization_errors: Mapped[List[str]] = mapped_column(
        _JSONB_VARIANT, nullable=False, default=list
    )
    normalization_warnings: Mapped[List[str]] = mapped_column(
        _JSONB_VARIANT, nullable=False, default=list
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    __table_args__ = (
        # Supports deterministic descending retrieval of recent normalized events
        Index("idx_normalized_events_created_at_id", "created_at", "id"),
    )
