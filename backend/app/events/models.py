"""
AutoSOC - Security Event Persistence Models (SQLAlchemy 2.0)

Stores validated raw ingestion envelopes prior to Phase 2 parsing and normalization.
Preserves original raw_payload content verbatim and maintains ingestion_id uniqueness
and raw_hash indexing per docs/security/security-data-contract.md §2.4 & §7.
"""

from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.db.base import Base


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
