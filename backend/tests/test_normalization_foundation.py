"""
AutoSOC Day 7 Tests - Backend Normalization Foundation
====================================================
Unit, repository, service, error-handling, and API tests for:
  - NormalizedEvent SQLAlchemy model & 002_create_normalized_events.sql migration
  - NormalizationService (SourceParserProtocol + EventNormalizerProtocol + EventValidatorProtocol)
  - Post-persist normalization integration on POST /api/v1/events/ingest
  - Bounded retrieval on GET /api/v1/events/normalized and GET /api/v1/events/normalized/{event_id}

Note on test isolation:
  Tests in this module use mocked/in-memory AsyncSession doubles (`InMemoryDay7Session`
  and `AsyncMock`) via FastAPI's `dependency_overrides[get_db]`. Live PostgreSQL
  DDL and round-trip persistence are verified separately against the running container.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from main import app
from app.db.session import get_db
from app.events.models import NormalizedEvent, RawEventEnvelope
from app.events.normalization_service import NormalizationService
from app.events.schemas import SourceTypeEnum
from app.events.validation import compute_raw_hash

client = TestClient(app)


class InMemoryDay7Session:
    """
    In-memory AsyncSession double tracking both `raw_event_envelopes` and
    `normalized_events`, enforcing unique constraints and FK references.
    """

    def __init__(self) -> None:
        self.raw_rows: List[RawEventEnvelope] = []
        self.normalized_rows: List[NormalizedEvent] = []
        self._pending: Optional[Any] = None
        self._next_raw_id = 1
        self._next_norm_id = 1
        self.rolled_back = False

    async def scalar(self, stmt: Any) -> Any:
        compiled = str(stmt)
        params = stmt.compile().params
        target_val = next(iter(params.values()), None)
        if "FROM normalized_events" in compiled:
            if "WHERE normalized_events.ingestion_id" in compiled:
                return next(
                    (n for n in self.normalized_rows if n.ingestion_id == target_val),
                    None,
                )
            if "WHERE normalized_events.event_id" in compiled:
                return next(
                    (n for n in self.normalized_rows if n.event_id == target_val),
                    None,
                )
            return None
        if "FROM raw_event_envelopes" in compiled:
            if "WHERE raw_event_envelopes.ingestion_id" in compiled:
                # Differentiate select(RawEventEnvelope.id) vs select(RawEventEnvelope)
                select_clause = compiled.split("FROM", 1)[0]
                if "raw_event_envelopes.raw_payload" not in select_clause:
                    return next(
                        (r.id for r in self.raw_rows if r.ingestion_id == target_val),
                        None,
                    )
                return next(
                    (r for r in self.raw_rows if r.ingestion_id == target_val),
                    None,
                )
            if "WHERE raw_event_envelopes.raw_hash" in compiled:
                return next(
                    (r.id for r in self.raw_rows if r.raw_hash == target_val),
                    None,
                )
        return None

    async def scalars(self, stmt: Any) -> MagicMock:
        compiled = str(stmt)
        params = stmt.compile().params
        limit_val = next(iter(params.values()), 20)
        if "FROM normalized_events" in compiled:
            ordered = sorted(
                self.normalized_rows,
                key=lambda r: (r.created_at, r.id),
                reverse=True,
            )[:limit_val]
        else:
            ordered = sorted(
                self.raw_rows,
                key=lambda r: (r.received_at, r.id),
                reverse=True,
            )[:limit_val]
        result = MagicMock()
        result.all.return_value = ordered
        return result

    def add(self, obj: Any) -> None:
        self._pending = obj

    async def commit(self) -> None:
        if isinstance(self._pending, RawEventEnvelope):
            if any(r.ingestion_id == self._pending.ingestion_id for r in self.raw_rows):
                raise IntegrityError("INSERT", {}, Exception("unique ingestion_id"))
            self._pending.id = self._next_raw_id
            self._next_raw_id += 1
            if self._pending.received_at is None:
                self._pending.received_at = datetime.now(timezone.utc)
            self.raw_rows.append(self._pending)
            self._pending = None
        elif isinstance(self._pending, NormalizedEvent):
            # Enforce FK integrity against raw_event_envelopes
            if not any(
                r.id == self._pending.raw_envelope_id
                and r.ingestion_id == self._pending.ingestion_id
                for r in self.raw_rows
            ):
                raise IntegrityError("INSERT", {}, Exception("FK violation"))
            if any(
                n.ingestion_id == self._pending.ingestion_id
                for n in self.normalized_rows
            ):
                raise IntegrityError("INSERT", {}, Exception("unique ingestion_id"))
            self._pending.id = self._next_norm_id
            self._next_norm_id += 1
            if self._pending.created_at is None:
                self._pending.created_at = datetime.now(timezone.utc)
            self.normalized_rows.append(self._pending)
            self._pending = None

    async def refresh(self, obj: Any) -> None:
        pass

    async def rollback(self) -> None:
        self._pending = None
        self.rolled_back = True


@pytest.fixture()
def day7_db():
    session = InMemoryDay7Session()

    async def _override():
        yield session

    app.dependency_overrides[get_db] = _override
    yield session
    app.dependency_overrides.pop(get_db, None)


def _suricata_envelope(
    ingestion_id: str = "aaaa1111-1111-4111-8111-111111111111",
    *,
    with_optional_fields: bool = True,
) -> Dict[str, Any]:
    raw_obj: Dict[str, Any] = {
        "timestamp": "2026-11-25T10:00:00Z",
        "event_type": "alert",
        "host": "sensor-lan01",
        "alert": {"severity": 2, "signature": "ET TEST Signature"},
    }
    if with_optional_fields:
        raw_obj.update(
            {
                "src_ip": "192.168.1.45",
                "dest_ip": "185.220.101.34",
                "src_port": 54321,
                "dest_port": 443,
                "proto": "TCP",
                "flow_id": 987654,
            }
        )
    raw_payload = json.dumps(raw_obj)
    return {
        "ingestion_id": ingestion_id,
        "source_type": "suricata",
        "sensor_id": "sensor-lan01",
        "ingest_time": "2026-11-25T10:00:01Z",
        "raw_hash": compute_raw_hash(raw_payload),
        "raw_payload": raw_payload,
    }


# ---------------------------------------------------------------------------
# 1. Successful normalization and persistence (end-to-end mocked DB)
# ---------------------------------------------------------------------------

def test_ingest_suricata_normalizes_and_persists_successfully(day7_db):
    payload = _suricata_envelope(with_optional_fields=True)
    resp = client.post("/api/v1/events/ingest", json=payload)

    assert resp.status_code == 201
    body = resp.json()
    assert body["ingestion_id"] == payload["ingestion_id"]
    assert body["normalization_status"] == "normalized"
    assert UUID(body["event_id"])  # valid UUID assigned

    assert len(day7_db.raw_rows) == 1
    assert len(day7_db.normalized_rows) == 1
    raw_rec = day7_db.raw_rows[0]
    norm_rec = day7_db.normalized_rows[0]

    # Raw payload remains verbatim
    assert raw_rec.raw_payload == payload["raw_payload"]
    # FK relationship integrity
    assert norm_rec.raw_envelope_id == raw_rec.id
    assert norm_rec.ingestion_id == raw_rec.ingestion_id
    assert norm_rec.event_id == body["event_id"]
    assert norm_rec.event_category == "alert"
    assert norm_rec.event_type == "alert.ids"
    assert norm_rec.source_ip == "192.168.1.45"
    assert norm_rec.destination_ip == "185.220.101.34"
    assert norm_rec.source_port == 54321
    assert norm_rec.destination_port == 443
    assert norm_rec.protocol == "tcp"
    assert norm_rec.severity == 3  # Suricata 2 -> AutoSOC 3


# ---------------------------------------------------------------------------
# 2. Missing optional fields stay None (never invented)
# ---------------------------------------------------------------------------

def test_normalization_preserves_none_for_absent_optional_fields(day7_db):
    payload = _suricata_envelope(
        ingestion_id="bbbb1111-1111-4111-8111-111111111111",
        with_optional_fields=False,
    )
    resp = client.post("/api/v1/events/ingest", json=payload)

    assert resp.status_code == 201
    assert resp.json()["normalization_status"] == "normalized"

    norm_rec = day7_db.normalized_rows[0]
    assert norm_rec.user_name is None
    assert norm_rec.source_ip is None
    assert norm_rec.destination_ip is None
    assert norm_rec.source_port is None
    assert norm_rec.destination_port is None
    assert norm_rec.protocol is None
    assert norm_rec.process is None
    assert norm_rec.file_hash is None
    assert norm_rec.domain is None
    assert norm_rec.command_line is None


# ---------------------------------------------------------------------------
# 3. Unsupported event format recorded cleanly without losing raw event
# ---------------------------------------------------------------------------

def test_normalization_service_records_unsupported_without_losing_raw(day7_db):
    async def _run():
        raw = RawEventEnvelope(
            id=1,
            ingestion_id="cccc1111-1111-4111-8111-111111111111",
            source_type=SourceTypeEnum.CUSTOM.value,
            sensor_id="custom-sensor",
            ingest_time="2026-11-25T10:00:00Z",
            raw_hash="sha256:" + ("c" * 64),
            raw_payload="custom raw line",
            payload_size_bytes=15,
            possible_duplicate=False,
            processing_status="accepted",
            received_at=datetime.now(timezone.utc),
        )
        day7_db.raw_rows.append(raw)

        service = NormalizationService()
        norm = await service.normalize_and_persist(day7_db, raw)
        assert norm.normalization_status == "unsupported"
        assert norm.event_id is None
        assert len(norm.normalization_errors) == 1
        assert "unsupported" in norm.normalization_errors[0].lower()
        assert len(day7_db.raw_rows) == 1

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 4. Invalid normalized output rejected by schema check & recorded as failed
# ---------------------------------------------------------------------------

def test_normalization_service_records_failed_on_invalid_normalized_output(day7_db):
    class BrokenNormalizer:
        def normalize(
            self, parsed_event: Dict[str, Any], ingestion_envelope: Dict[str, Any]
        ) -> Dict[str, Any]:
            return {
                "event_id": "dddd1111-1111-4111-8111-111111111111",
                "ingestion_id": ingestion_envelope["ingestion_id"],
                "timestamp": "2026-11-25T10:00:00Z",
                "source": "suricata",
                "event_category": "invalid_category",  # violates EventCategoryEnum
                "event_type": "alert.ids",
                "host": "sensor-01",
                "severity": 99,  # violates [1, 5]
                "raw_event": ingestion_envelope["raw_payload"],
                "metadata": {},
            }

    async def _run():
        payload = _suricata_envelope()
        raw = RawEventEnvelope(
            id=1,
            ingestion_id=payload["ingestion_id"],
            source_type="suricata",
            sensor_id="sensor-lan01",
            ingest_time=payload["ingest_time"],
            raw_hash=payload["raw_hash"],
            raw_payload=payload["raw_payload"],
            payload_size_bytes=len(payload["raw_payload"]),
            possible_duplicate=False,
            processing_status="accepted",
            received_at=datetime.now(timezone.utc),
        )
        day7_db.raw_rows.append(raw)

        service = NormalizationService(normalizer=BrokenNormalizer())
        norm = await service.normalize_and_persist(day7_db, raw)

        assert norm.normalization_status == "failed"
        assert norm.event_id is None
        assert norm.severity is None
        assert len(norm.normalization_errors) >= 2
        assert day7_db.raw_rows[0].raw_payload == payload["raw_payload"]

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 5. Normalization failure after raw persistence preserves raw event
# ---------------------------------------------------------------------------

def test_ingest_normalization_failure_does_not_erase_raw_event(day7_db):
    # Minimal Sysmon XML lacks TimeCreated and severity -> fails NormalizedSecurityEvent validation
    raw_xml = "<Event><System><EventID>1</EventID><Computer>host-01</Computer></System></Event>"
    payload = {
        "ingestion_id": "eeee1111-1111-4111-8111-111111111111",
        "source_type": "sysmon",
        "sensor_id": "host-01",
        "ingest_time": "2026-11-25T10:00:00Z",
        "raw_hash": compute_raw_hash(raw_xml),
        "raw_payload": raw_xml,
    }
    resp = client.post("/api/v1/events/ingest", json=payload)

    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "accepted"
    assert body["normalization_status"] == "failed"
    assert body["event_id"] is None

    # Raw event remains intact in PostgreSQL session
    assert len(day7_db.raw_rows) == 1
    assert day7_db.raw_rows[0].raw_payload == raw_xml
    # Failed normalization outcome is recorded
    assert len(day7_db.normalized_rows) == 1
    assert day7_db.normalized_rows[0].normalization_status == "failed"
    assert len(day7_db.normalized_rows[0].normalization_errors) >= 1


def test_ingest_unexpected_normalization_exception_still_returns_201_raw_persisted(day7_db):
    payload = _suricata_envelope(ingestion_id="ffff1111-1111-4111-8111-111111111111")
    with patch(
        "app.api.v1.endpoints.events._default_normalization_service.normalize_and_persist",
        new_callable=AsyncMock,
        side_effect=RuntimeError("transient normalizer failure"),
    ):
        resp = client.post("/api/v1/events/ingest", json=payload)

    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "accepted"
    assert body["normalization_status"] == "failed"
    assert body["event_id"] is None
    assert len(day7_db.raw_rows) == 1


# ---------------------------------------------------------------------------
# 6. Duplicate ingestion behavior & idempotent normalize_and_persist
# ---------------------------------------------------------------------------

def test_duplicate_ingestion_id_still_409_and_duplicate_hash_normalizes(day7_db):
    p1 = _suricata_envelope(ingestion_id="12121212-1111-4111-8111-111111111111")
    p2 = _suricata_envelope(ingestion_id="13131313-1111-4111-8111-111111111111")

    r1 = client.post("/api/v1/events/ingest", json=p1)
    r1_dup_id = client.post("/api/v1/events/ingest", json=p1)
    r2_dup_hash = client.post("/api/v1/events/ingest", json=p2)

    assert r1.status_code == 201
    assert r1_dup_id.status_code == 409
    assert r2_dup_hash.status_code == 201
    assert r2_dup_hash.json()["possible_duplicate"] is True
    assert r2_dup_hash.json()["normalization_status"] == "normalized"
    assert len(day7_db.raw_rows) == 2
    assert len(day7_db.normalized_rows) == 2
    assert r1.json()["event_id"] != r2_dup_hash.json()["event_id"]


def test_normalize_by_ingestion_id_is_idempotent(day7_db):
    async def _run():
        payload = _suricata_envelope(ingestion_id="14141414-1111-4111-8111-111111111111")
        raw = RawEventEnvelope(
            id=1,
            ingestion_id=payload["ingestion_id"],
            source_type="suricata",
            sensor_id="sensor-lan01",
            ingest_time=payload["ingest_time"],
            raw_hash=payload["raw_hash"],
            raw_payload=payload["raw_payload"],
            payload_size_bytes=len(payload["raw_payload"]),
            possible_duplicate=False,
            processing_status="accepted",
            received_at=datetime.now(timezone.utc),
        )
        day7_db.raw_rows.append(raw)

        service = NormalizationService()
        first = await service.normalize_by_ingestion_id(day7_db, payload["ingestion_id"])
        second = await service.normalize_by_ingestion_id(day7_db, payload["ingestion_id"])
        assert first is not None
        assert second is not None
        assert first.event_id == second.event_id
        assert len(day7_db.normalized_rows) == 1

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 7. Database relationship integrity & migration alignment
# ---------------------------------------------------------------------------

def test_normalized_event_fk_integrity_enforced():
    async def _run():
        session = InMemoryDay7Session()
        orphan = NormalizedEvent(
            event_id="15151515-1111-4111-8111-111111111111",
            raw_envelope_id=999,
            ingestion_id="16161616-1111-4111-8111-111111111111",
            source_type="suricata",
            sensor_id="sensor-01",
            normalization_status="normalized",
        )
        session.add(orphan)
        with pytest.raises(IntegrityError):
            await session.commit()

    asyncio.run(_run())


def test_sql_migration_002_matches_orm_columns_and_fks():
    migration_path = (
        Path(__file__).resolve().parent.parent
        / "app"
        / "db"
        / "migrations"
        / "002_create_normalized_events.sql"
    )
    sql = migration_path.read_text(encoding="utf-8")
    for col in NormalizedEvent.__table__.columns:
        assert col.name in sql, f"Column {col.name} missing from 002 migration"
    assert "REFERENCES raw_event_envelopes(id) ON DELETE RESTRICT" in sql
    assert "REFERENCES raw_event_envelopes(ingestion_id) ON DELETE RESTRICT" in sql


# ---------------------------------------------------------------------------
# 8. Retrieval of normalized events (ordering, limits, detail, no raw payload)
# ---------------------------------------------------------------------------

def test_normalized_events_retrieval_ordering_limits_and_detail(day7_db):
    base_time = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)
    for idx in range(3):
        day7_db.normalized_rows.append(
            NormalizedEvent(
                id=idx + 1,
                event_id=f"17171717-1111-4111-8111-11111111111{idx}",
                raw_envelope_id=idx + 1,
                ingestion_id=f"18181818-1111-4111-8111-11111111111{idx}",
                event_timestamp="2026-11-25T12:00:00Z",
                source_type="zeek",
                sensor_id=f"zeek-{idx}",
                event_category="network",
                event_type="network.dns",
                host=f"zeek-{idx}",
                severity=2,
                event_metadata={"pipeline_version": "0.2.0-day7"},
                normalization_status="normalized",
                normalization_errors=[],
                normalization_warnings=[],
                created_at=base_time + timedelta(seconds=idx),
            )
        )

    list_resp = client.get("/api/v1/events/normalized", params={"limit": 2})
    assert list_resp.status_code == 200
    body = list_resp.json()
    assert body["limit"] == 2
    assert body["count"] == 2
    # Most recent first
    assert body["items"][0]["event_id"].endswith("2")
    assert body["items"][1]["event_id"].endswith("1")
    # Sensitive raw_payload / raw_event not exposed in retrieval response
    assert "raw_payload" not in body["items"][0]
    assert "raw_event" not in body["items"][0]

    # Single detail lookup
    detail_resp = client.get(f"/api/v1/events/normalized/{body['items'][0]['event_id']}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["sensor_id"] == "zeek-2"

    # Not found -> 404 standardized format
    missing_resp = client.get("/api/v1/events/normalized/00000000-0000-4000-8000-000000000000")
    assert missing_resp.status_code == 404
    assert missing_resp.json() == {"message": "Not found"}


@pytest.mark.parametrize("bad_limit", [0, -1, 101, "abc"])
def test_normalized_retrieval_invalid_limit_returns_422(day7_db, bad_limit):
    resp = client.get("/api/v1/events/normalized", params={"limit": bad_limit})
    assert resp.status_code == 422
    assert resp.json()["message"] == "Validation error"
