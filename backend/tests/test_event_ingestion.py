"""
AutoSOC Day 6 Tests - Security Event Ingestion Foundation
=======================================================
Unit, schema validation, repository, error-handling, and API tests for:
  - POST /api/v1/events/ingest
  - GET /api/v1/events/ingested

Note on test isolation:
  All tests in this module use an explicit mocked/in-memory AsyncSession
  via FastAPI's `dependency_overrides[get_db]` so they verify application logic
  deterministically without requiring a live PostgreSQL instance.
  Live PostgreSQL verification is tracked and reported separately.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError, OperationalError

from main import app
from app.db.session import get_db
from app.events.models import RawEventEnvelope
from app.events.repository import (
    DuplicateIngestionIdError,
    EventPersistenceError,
    list_recent_envelopes,
    persist_raw_envelope,
)
from app.events.schemas import IngestionEnvelope, SourceTypeEnum
from app.events.validation import compute_raw_hash


def _valid_envelope_payload(
    ingestion_id: str = "11111111-1111-4111-8111-111111111111",
    source_type: str = "sysmon",
    sensor_id: str = "sensor-win-01",
    ingest_time: str = "2026-11-25T10:00:00Z",
    raw_hash: Optional[str] = None,
    raw_payload: str = "<Event><System><EventID>1</EventID></System></Event>",
) -> Dict[str, Any]:
    return {
        "ingestion_id": ingestion_id,
        "source_type": source_type,
        "sensor_id": sensor_id,
        "ingest_time": ingest_time,
        "raw_hash": raw_hash if raw_hash is not None else compute_raw_hash(raw_payload),
        "raw_payload": raw_payload,
    }


class InMemoryFakeSession:
    """
    Deterministic async SQLAlchemy session double that simulates persistence,
    unique ingestion_id constraints, raw_hash lookups, ordering, and rollbacks.
    """

    def __init__(self) -> None:
        self.rows: List[RawEventEnvelope] = []
        self._pending: Optional[RawEventEnvelope] = None
        self._next_id = 1
        self.committed = False
        self.rolled_back = False

    async def scalar(self, stmt: Any) -> Any:
        compiled = str(stmt)
        params = stmt.compile().params
        if "raw_event_envelopes.ingestion_id" in compiled:
            target_id = next(iter(params.values()))
            for row in self.rows:
                if row.ingestion_id == target_id:
                    return row.id
            return None
        if "raw_event_envelopes.raw_hash" in compiled:
            target_hash = next(iter(params.values()))
            for row in self.rows:
                if row.raw_hash == target_hash:
                    return row.id
            return None
        return None

    async def scalars(self, stmt: Any) -> MagicMock:
        params = stmt.compile().params
        limit_val = next(iter(params.values()), 20)
        ordered = sorted(
            self.rows,
            key=lambda r: (r.received_at, r.id),
            reverse=True,
        )[:limit_val]
        result = MagicMock()
        result.all.return_value = ordered
        return result

    def add(self, obj: RawEventEnvelope) -> None:
        self._pending = obj

    async def commit(self) -> None:
        if self._pending is not None:
            if any(r.ingestion_id == self._pending.ingestion_id for r in self.rows):
                raise IntegrityError("INSERT", {}, Exception("unique violation"))
            self._pending.id = self._next_id
            self._next_id += 1
            if self._pending.received_at is None:
                self._pending.received_at = datetime.now(timezone.utc)
            self.rows.append(self._pending)
            self._pending = None
        self.committed = True

    async def refresh(self, obj: RawEventEnvelope) -> None:
        pass

    async def rollback(self) -> None:
        self._pending = None
        self.rolled_back = True


@pytest.fixture()
def fake_db():
    session = InMemoryFakeSession()

    async def _override_get_db():
        yield session

    app.dependency_overrides[get_db] = _override_get_db
    yield session
    app.dependency_overrides.pop(get_db, None)


# Use non-lifespan TestClient for fast unit/API tests (lifespan is tested in test_health.py)
client = TestClient(app)


# ---------------------------------------------------------------------------
# 1. Valid event ingestion & persistence
# ---------------------------------------------------------------------------

def test_ingest_valid_envelope_persists_and_returns_201(fake_db):
    payload = _valid_envelope_payload()
    response = client.post("/api/v1/events/ingest", json=payload)

    assert response.status_code == 201
    body = response.json()
    assert body["ingestion_id"] == payload["ingestion_id"]
    assert body["source_type"] == "sysmon"
    assert body["status"] == "accepted"
    assert body["possible_duplicate"] is False
    assert body["received_at"].endswith("Z")

    # Verify verbatim persistence in session
    assert fake_db.committed is True
    assert len(fake_db.rows) == 1
    persisted = fake_db.rows[0]
    assert persisted.raw_payload == payload["raw_payload"]
    assert persisted.payload_size_bytes == len(payload["raw_payload"].encode("utf-8"))
    assert persisted.sensor_id == payload["sensor_id"]
    assert persisted.raw_hash == payload["raw_hash"]


# ---------------------------------------------------------------------------
# 2. Invalid schema & missing required fields (422 Standardized Error)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "missing_field",
    ["ingestion_id", "source_type", "sensor_id", "ingest_time", "raw_hash", "raw_payload"],
)
def test_ingest_missing_required_field_returns_422(fake_db, missing_field):
    payload = _valid_envelope_payload()
    del payload[missing_field]

    response = client.post("/api/v1/events/ingest", json=payload)

    assert response.status_code == 422
    body = response.json()
    assert body["message"] == "Validation error"
    assert isinstance(body["errors"], list)
    assert any(missing_field in err["field"] for err in body["errors"])
    assert len(fake_db.rows) == 0


def test_ingest_invalid_source_type_returns_422(fake_db):
    payload = _valid_envelope_payload(source_type="unknown_agent")
    response = client.post("/api/v1/events/ingest", json=payload)

    assert response.status_code == 422
    assert response.json()["message"] == "Validation error"
    assert len(fake_db.rows) == 0


def test_ingest_invalid_uuid_and_hash_and_timestamp_returns_422(fake_db):
    payload = _valid_envelope_payload(
        ingestion_id="not-a-uuid",
        ingest_time="invalid-time",
        raw_hash="md5:1234",
    )
    response = client.post("/api/v1/events/ingest", json=payload)

    assert response.status_code == 422
    body = response.json()
    assert body["message"] == "Validation error"
    fields = {err["field"] for err in body["errors"]}
    assert "body -> ingestion_id" in fields
    assert "body -> ingest_time" in fields
    assert "body -> raw_hash" in fields


def test_ingest_empty_or_oversized_raw_payload_returns_422_without_leaking_payload(fake_db):
    empty_payload = _valid_envelope_payload(raw_payload="")
    oversized_secret = "<Event>SENSITIVE_SECRET_" + ("X" * 65_540) + "</Event>"
    oversized_payload = _valid_envelope_payload(raw_payload=oversized_secret)

    r_empty = client.post("/api/v1/events/ingest", json=empty_payload)
    r_large = client.post("/api/v1/events/ingest", json=oversized_payload)

    assert r_empty.status_code == 422
    assert r_large.status_code == 422
    assert "SENSITIVE_SECRET" not in r_large.text
    assert len(fake_db.rows) == 0


def test_ingest_hash_mismatch_and_unsupported_custom_rejected_422(fake_db):
    mismatch_payload = _valid_envelope_payload(raw_hash="sha256:" + ("0" * 64))
    r_mismatch = client.post("/api/v1/events/ingest", json=mismatch_payload)
    assert r_mismatch.status_code == 422
    assert r_mismatch.json()["errors"][0]["type"] == "hash_mismatch"

    custom_payload = _valid_envelope_payload(source_type="custom", raw_payload="raw custom line")
    r_custom = client.post("/api/v1/events/ingest", json=custom_payload)
    assert r_custom.status_code == 422
    assert r_custom.json()["errors"][0]["type"] == "unsupported_source_type"

    bad_sysmon = _valid_envelope_payload(source_type="sysmon", raw_payload="not xml payload")
    r_sysmon = client.post("/api/v1/events/ingest", json=bad_sysmon)
    assert r_sysmon.status_code == 422
    assert r_sysmon.json()["errors"][0]["type"] == "malformed_payload"


def test_ingest_future_skew_returns_201_accepted_with_warnings(fake_db):
    future_ts = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat().replace("+00:00", "Z")
    payload = _valid_envelope_payload(ingest_time=future_ts)
    resp = client.post("/api/v1/events/ingest", json=payload)

    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "accepted_with_warnings"
    assert len(body["warnings"]) == 1
    assert "skew tolerance" in body["warnings"][0]


# ---------------------------------------------------------------------------
# 3. Duplicate event identifiers per Security Data Contract §2.4 & §7.4
# ---------------------------------------------------------------------------

def test_duplicate_ingestion_id_returns_409_conflict(fake_db):
    payload = _valid_envelope_payload(
        ingestion_id="22222222-2222-4222-8222-222222222222"
    )
    first = client.post("/api/v1/events/ingest", json=payload)
    second = client.post("/api/v1/events/ingest", json=payload)

    assert first.status_code == 201
    assert second.status_code == 409
    assert second.json() == {
        "message": "Duplicate ingestion_id: event envelope already exists"
    }
    assert len(fake_db.rows) == 1


def test_duplicate_raw_hash_with_new_ingestion_id_is_flagged_and_stored(fake_db):
    shared_payload = "<Event><System><EventID>4624</EventID></System></Event>"
    shared_hash = compute_raw_hash(shared_payload)
    p1 = _valid_envelope_payload(
        ingestion_id="33333333-3333-4333-8333-333333333331",
        raw_hash=shared_hash,
        raw_payload=shared_payload,
    )
    p2 = _valid_envelope_payload(
        ingestion_id="33333333-3333-4333-8333-333333333332",
        raw_hash=shared_hash,
        raw_payload=shared_payload,
    )

    r1 = client.post("/api/v1/events/ingest", json=p1)
    r2 = client.post("/api/v1/events/ingest", json=p2)

    assert r1.status_code == 201
    assert r1.json()["possible_duplicate"] is False

    # Contract §7.4: duplicate raw payload is flagged, never silently discarded
    assert r2.status_code == 201
    assert r2.json()["possible_duplicate"] is True
    assert len(fake_db.rows) == 2
    assert fake_db.rows[1].possible_duplicate is True


# ---------------------------------------------------------------------------
# 4. Database failure handling (rollback & sanitized 500 error)
# ---------------------------------------------------------------------------

def test_ingest_database_failure_rolls_back_and_sanitizes_500():
    failing_session = AsyncMock()
    failing_session.scalar = AsyncMock(return_value=None)
    failing_session.add = MagicMock()
    failing_session.commit = AsyncMock(
        side_effect=OperationalError(
            "INSERT INTO raw_event_envelopes",
            {},
            Exception("postgresql://autosoc:secret_pass@localhost:5432 connection refused"),
        )
    )
    failing_session.rollback = AsyncMock()

    async def _override_failing_db():
        yield failing_session

    app.dependency_overrides[get_db] = _override_failing_db
    try:
        payload = _valid_envelope_payload()
        response = client.post("/api/v1/events/ingest", json=payload)

        assert response.status_code == 500
        assert response.json() == {"message": "Internal Server Error"}
        assert "secret_pass" not in response.text
        assert "OperationalError" not in response.text
        failing_session.rollback.assert_awaited_once()
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_retrieval_database_failure_returns_sanitized_500():
    failing_session = AsyncMock()
    failing_session.scalars = AsyncMock(
        side_effect=OperationalError("SELECT", {}, Exception("db connection dropped"))
    )

    async def _override_failing_db():
        yield failing_session

    app.dependency_overrides[get_db] = _override_failing_db
    try:
        response = client.get("/api/v1/events/ingested")

        assert response.status_code == 500
        assert response.json() == {"message": "Internal Server Error"}
        assert "db connection dropped" not in response.text
    finally:
        app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# 5. Bounded retrieval ordering and limits
# ---------------------------------------------------------------------------

def test_retrieval_deterministic_ordering_and_bounded_payload_preview(fake_db):
    base_time = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)
    long_payload = "A" * 500

    for idx in range(3):
        rec = RawEventEnvelope(
            id=idx + 1,
            ingestion_id=f"44444444-4444-4444-8444-44444444444{idx}",
            source_type=SourceTypeEnum.ZEEK.value,
            sensor_id=f"zeek-{idx}",
            ingest_time="2026-11-25T12:00:00Z",
            raw_hash="sha256:" + f"{idx}" * 64,
            raw_payload=long_payload if idx == 2 else f"short-{idx}",
            payload_size_bytes=len(long_payload) if idx == 2 else len(f"short-{idx}"),
            possible_duplicate=False,
            processing_status="accepted",
            received_at=base_time + timedelta(seconds=idx),
        )
        fake_db.rows.append(rec)

    resp = client.get("/api/v1/events/ingested", params={"limit": 2})

    assert resp.status_code == 200
    data = resp.json()
    assert data["limit"] == 2
    assert data["count"] == 2
    # Most recent first (id=3, then id=2)
    assert data["items"][0]["ingestion_id"].endswith("2")
    assert data["items"][1]["ingestion_id"].endswith("1")
    # Unbounded raw payload is NOT returned; preview is bounded to 256 + "..."
    assert data["items"][0]["payload_size_bytes"] == 500
    assert len(data["items"][0]["raw_payload_preview"]) == 259
    assert data["items"][0]["raw_payload_preview"].endswith("...")


@pytest.mark.parametrize("bad_limit", [0, -1, 101, "abc"])
def test_retrieval_invalid_limit_returns_422(fake_db, bad_limit):
    resp = client.get("/api/v1/events/ingested", params={"limit": bad_limit})

    assert resp.status_code == 422
    assert resp.json()["message"] == "Validation error"


def test_retrieval_empty_returns_empty_list(fake_db):
    resp = client.get("/api/v1/events/ingested")

    assert resp.status_code == 200
    assert resp.json() == {"items": [], "count": 0, "limit": 20}


def test_ingest_malformed_json_returns_422(fake_db):
    resp = client.post(
        "/api/v1/events/ingest",
        content="{bad json",
        headers={"Content-Type": "application/json"},
    )

    assert resp.status_code == 422
    assert resp.json()["message"] == "Validation error"


def test_sql_migration_matches_orm_table_columns():
    from pathlib import Path
    migration_path = (
        Path(__file__).resolve().parent.parent
        / "app"
        / "db"
        / "migrations"
        / "001_create_raw_event_envelopes.sql"
    )
    sql = migration_path.read_text(encoding="utf-8")
    for col_name in RawEventEnvelope.__table__.columns.keys():
        assert col_name in sql, f"Column {col_name} missing from SQL migration"


# ---------------------------------------------------------------------------
# 6. Direct repository unit checks (async)
# ---------------------------------------------------------------------------

def test_repository_persist_and_list_async():
    import asyncio

    async def _run():
        session = InMemoryFakeSession()
        env = IngestionEnvelope(**_valid_envelope_payload())
        rec = await persist_raw_envelope(session, env)
        assert rec.id == 1
        items = await list_recent_envelopes(session, limit=10)
        assert len(items) == 1
        assert items[0].ingestion_id == env.ingestion_id

        with pytest.raises(DuplicateIngestionIdError):
            await persist_raw_envelope(session, env)

    asyncio.run(_run())
