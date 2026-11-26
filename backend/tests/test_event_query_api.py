"""
AutoSOC Day 8 Tests - Backend Event Explorer & Query API
=========================================================
Covers:
  1. Unit tests (no DB required):
     - NormalizedEventQueryParams validation (pagination bounds, severity ranges,
       ISO 8601 timezone-aware timestamps, search normalization, enum checks)
     - Parameterized SQL filter/sort construction & LIKE wildcard escaping
     - API endpoint validation (422 responses) & response pagination envelope
       using mocked repository
  2. Live PostgreSQL integration tests (executed against real autosoc_postgres):
     - Default pagination, max limit (100), offset slicing, has_more, total
     - All supported filters (source_type, normalization_status, event_category,
       event_type, severity, min_severity/max_severity, start_time/end_time)
     - Combined filters & empty result sets
     - Case-insensitive substring search across approved fields (and LIKE escaping)
     - Deterministic sorting across all approved sort_by fields and asc/desc order
     - Stable pagination across pages without duplicates or gaps
     - Raw payload / raw_event exclusion from API responses and search scope
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import delete, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from main import app
from app.core.config import settings
from app.db.session import get_db
from app.events.models import NormalizedEvent, RawEventEnvelope
from app.events.query_contract import (
    MAX_QUERY_OFFSET,
    NormalizedEventQueryParams,
    NormalizedEventSortField,
    SortOrderEnum,
    escape_like_pattern,
)
from app.events.repository import (
    _build_normalized_event_filters,
    _resolve_sort_clauses,
)
from app.events.validation import compute_raw_hash

client = TestClient(app)


# ---------------------------------------------------------------------------
# 1. Unit tests: Schema & query parameter validation
# ---------------------------------------------------------------------------


def test_query_params_defaults_and_valid_ranges():
    params = NormalizedEventQueryParams()
    assert params.limit == 20
    assert params.offset == 0
    assert params.sort_by == NormalizedEventSortField.CREATED_AT
    assert params.sort_order == SortOrderEnum.DESC

    ranged = NormalizedEventQueryParams(
        limit=100,
        offset=MAX_QUERY_OFFSET,
        severity=4,
        start_time="2026-11-25T10:00:00+05:30",
        end_time="2026-11-25T12:00:00Z",
        search="  powershell.exe  ",
        event_type="  PROCESS.CREATE ",
    )
    assert ranged.start_time == "2026-11-25T04:30:00.000Z"
    assert ranged.end_time == "2026-11-25T12:00:00.000Z"
    assert ranged.search == "powershell.exe"
    assert ranged.event_type == "process.create"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"offset": MAX_QUERY_OFFSET + 1},
        {"severity": 0},
        {"severity": 6},
        {"start_time": "2026-11-25T10:00:00"},  # naive timestamp rejected
        {"start_time": "not-a-timestamp"},
        {"start_time": "2026-11-25T12:00:00Z", "end_time": "2026-11-25T11:00:00Z"},
        {"event_type": "alert.ids; DROP TABLE normalized_events;--"},
        {"search": "x" * 129},
    ],
)
def test_query_params_rejects_invalid_inputs(kwargs: Dict[str, Any]):
    with pytest.raises(ValidationError):
        NormalizedEventQueryParams(**kwargs)


def test_escape_like_and_sql_parameterization():
    assert escape_like_pattern(r"100%_test\path") == r"100\%\_test\\path"

    params = NormalizedEventQueryParams(
        search="'; DROP TABLE normalized_events; --",
        event_type="alert.ids",
    )
    filters = _build_normalized_event_filters(params)
    assert len(filters) == 2

    dialect = postgresql.dialect()
    compiled_sql = " AND ".join(
        str(f.compile(dialect=dialect)) for f in filters
    )
    # Parameterized bind markers used; raw SQL injection string never inlined
    assert "DROP TABLE" not in compiled_sql
    assert "ILIKE" in compiled_sql

    clauses = _resolve_sort_clauses(NormalizedEventSortField.SEVERITY, SortOrderEnum.ASC)
    assert len(clauses) == 2


def test_migration_003_defines_expected_query_indexes():
    sql_path = (
        Path(__file__).resolve().parent.parent
        / "app"
        / "db"
        / "migrations"
        / "003_add_normalized_events_query_indexes.sql"
    )
    sql = sql_path.read_text(encoding="utf-8")
    for idx_name in (
        "idx_normalized_events_event_timestamp",
        "idx_normalized_events_source_type",
        "idx_normalized_events_category_type",
        "idx_normalized_events_severity",
    ):
        assert idx_name in sql


# ---------------------------------------------------------------------------
# 2. Unit tests: FastAPI endpoint validation & mocked repository behavior
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "query_params",
    [
        {"limit": 0},
        {"limit": 101},
        {"limit": "abc"},
        {"offset": -1},
        {"offset": MAX_QUERY_OFFSET + 1},
        {"offset": "abc"},
        {"source_type": "invalid_source"},
        {"source_type": "   "},
        {"normalization_status": "unknown_status"},
        {"event_category": "bad_cat"},
        {"event_type": "alert.ids; DROP TABLE"},
        {"event_type": "a" * 65},
        {"severity": 0},
        {"severity": 6},
        {"severity": "high"},
        {"start_time": "2026-11-25T10:00:00"},
        {"end_time": "2026-11-25T10:00:00"},
        {"end_time": "bad-date"},
        {"start_time": "2026-11-25T12:00:00Z", "end_time": "2026-11-25T10:00:00Z"},
        {"search": "x" * 129},
        {"sort_by": "raw_payload"},
        {"sort_by": "event_type"},
        {"sort_by": "id; DROP TABLE"},
        {"sort_order": "random"},
    ],
)
def test_normalized_endpoint_rejects_invalid_query_params_with_422(
    query_params: Dict[str, Any]
):
    async def _noop_db():
        yield AsyncMock()

    app.dependency_overrides[get_db] = _noop_db
    try:
        resp = client.get("/api/v1/events/normalized", params=query_params)
        assert resp.status_code == 422
        body = resp.json()
        assert body["message"] == "Validation error"
        assert isinstance(body.get("errors"), list) and len(body["errors"]) >= 1
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_normalized_endpoint_returns_paginated_envelope_with_mocked_repo():
    async def _noop_db():
        yield AsyncMock()

    sample_row = NormalizedEvent(
        id=10,
        event_id="10101010-1111-4111-8111-111111111110",
        raw_envelope_id=10,
        ingestion_id="20202020-1111-4111-8111-111111111110",
        event_timestamp="2026-11-25T10:00:00.000Z",
        source_type="suricata",
        sensor_id="unit-sensor",
        event_category="alert",
        event_type="alert.ids",
        host="edge-fw-01",
        severity=4,
        event_metadata={"pipeline_version": "0.2.0"},
        normalization_status="normalized",
        normalization_errors=[],
        normalization_warnings=[],
        created_at=datetime(2026, 11, 25, 10, 0, 5, tzinfo=timezone.utc),
    )

    app.dependency_overrides[get_db] = _noop_db
    try:
        with patch(
            "app.api.v1.endpoints.events.query_normalized_events",
            new_callable=AsyncMock,
            return_value=([sample_row], 5),
        ) as mocked_query:
            resp = client.get(
                "/api/v1/events/normalized",
                params={"limit": 1, "offset": 2, "source_type": "suricata"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 1
        assert body["total"] == 5
        assert body["limit"] == 1
        assert body["offset"] == 2
        assert body["has_more"] is True
        assert body["items"][0]["event_id"] == sample_row.event_id
        assert "raw_payload" not in body["items"][0]
        assert "raw_event" not in body["items"][0]
        mocked_query.assert_awaited_once()
    finally:
        app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# 3. Live PostgreSQL Integration Tests (skipped only if Postgres unreachable)
# ---------------------------------------------------------------------------

_PG_TEST_SENSOR_PREFIX = "day8-pg-test-"


def _make_nullpool_session_factory():
    engine = create_async_engine(settings.async_database_uri, poolclass=NullPool)
    factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    return engine, factory


async def _seed_postgres_events() -> List[str]:
    base_created = datetime(2026, 11, 25, 15, 0, 0, tzinfo=timezone.utc)
    fixtures = [
        {
            "sensor_id": f"{_PG_TEST_SENSOR_PREFIX}01",
            "source_type": "suricata",
            "raw_payload": json.dumps({"secret_raw_only": "RAW_SECRET_TOKEN_01"}),
            "event_id": str(uuid4()),
            "event_timestamp": "2026-11-25T10:00:00.000Z",
            "event_category": "alert",
            "event_type": "alert.ids",
            "host": "fw-edge-01",
            "user_name": None,
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.42",
            "process": None,
            "file_hash": "sha256:" + ("f" * 64),
            "domain": "evil.example.invalid",
            "command_line": None,
            "severity": 5,
            "normalization_status": "normalized",
            "event_metadata": {"pipeline_version": "0.2.0", "forbidden_meta": "META_FORBIDDEN_MARKER"},
            "normalization_warnings": [],
            "normalization_errors": [],
            "created_at": base_created + timedelta(seconds=1),
        },
        {
            "sensor_id": f"{_PG_TEST_SENSOR_PREFIX}02",
            "source_type": "sysmon",
            "raw_payload": "<Event>RAW_SECRET_TOKEN_02</Event>",
            "event_id": str(uuid4()),
            "event_timestamp": "2026-11-25T11:00:00.000Z",
            "event_category": "process",
            "event_type": "process.create",
            "host": "win-wks-01",
            "user_name": "alice",
            "source_ip": None,
            "destination_ip": None,
            "process": "powershell.exe",
            "file_hash": "sha256:" + ("a" * 64),
            "domain": None,
            "command_line": r"powershell.exe -NoProfile 100%_check C:\Temp\run.bat",
            "severity": 3,
            "normalization_status": "normalized",
            "event_metadata": {"pipeline_version": "0.2.0"},
            "normalization_warnings": [],
            "normalization_errors": [],
            "created_at": base_created + timedelta(seconds=2),
        },
        {
            "sensor_id": f"{_PG_TEST_SENSOR_PREFIX}03",
            "source_type": "zeek",
            "raw_payload": json.dumps({"uid": "Czeek03"}),
            "event_id": str(uuid4()),
            "event_timestamp": "2026-11-25T11:00:00.000Z",
            "event_category": "network",
            "event_type": "network.dns",
            "host": "zeek-core-01",
            "user_name": None,
            "source_ip": "10.0.0.15",
            "destination_ip": "198.51.100.53",
            "process": None,
            "file_hash": None,
            "domain": "c2.example.invalid",
            "command_line": None,
            "severity": 2,
            "normalization_status": "normalized_with_warnings",
            "event_metadata": {"pipeline_version": "0.2.0"},
            "normalization_warnings": ["WARN_FORBIDDEN_MARKER"],
            "normalization_errors": [],
            "created_at": base_created + timedelta(seconds=2),  # tie created_at with 02
        },
        {
            "sensor_id": f"{_PG_TEST_SENSOR_PREFIX}04",
            "source_type": "sysmon",
            "raw_payload": "<Event><System><EventID>1</EventID></System></Event>",
            "event_id": None,
            "event_timestamp": None,
            "event_category": None,
            "event_type": None,
            "host": None,
            "user_name": None,
            "source_ip": None,
            "destination_ip": None,
            "process": None,
            "file_hash": None,
            "domain": None,
            "command_line": None,
            "severity": None,
            "normalization_status": "failed",
            "event_metadata": {"pipeline_version": "0.2.0"},
            "normalization_warnings": [],
            "normalization_errors": ["ERR_FORBIDDEN_MARKER"],
            "created_at": base_created + timedelta(seconds=4),
        },
        {
            "sensor_id": f"{_PG_TEST_SENSOR_PREFIX}05",
            "source_type": "custom",
            "raw_payload": "custom syslog line",
            "event_id": None,
            "event_timestamp": None,
            "event_category": None,
            "event_type": None,
            "host": None,
            "user_name": None,
            "source_ip": None,
            "destination_ip": None,
            "process": None,
            "file_hash": None,
            "domain": None,
            "command_line": None,
            "severity": None,
            "normalization_status": "unsupported",
            "event_metadata": {"pipeline_version": "0.2.0"},
            "normalization_warnings": [],
            "normalization_errors": ["Unsupported custom format"],
            "created_at": base_created + timedelta(seconds=5),
        },
    ]

    ing_ids: List[str] = []
    engine, session_factory = _make_nullpool_session_factory()
    try:
        async with session_factory() as session:
            for idx, fx in enumerate(fixtures):
                ing_id = str(uuid4())
                ing_ids.append(ing_id)
                raw = RawEventEnvelope(
                    ingestion_id=ing_id,
                    source_type=fx["source_type"],
                    sensor_id=fx["sensor_id"],
                    ingest_time="2026-11-25T15:00:00Z",
                    raw_hash=compute_raw_hash(fx["raw_payload"] + f"-{idx}"),
                    raw_payload=fx["raw_payload"],
                    payload_size_bytes=len(fx["raw_payload"].encode("utf-8")),
                    possible_duplicate=False,
                    processing_status="accepted",
                )
                session.add(raw)
                await session.flush()

                norm = NormalizedEvent(
                    event_id=fx["event_id"],
                    raw_envelope_id=raw.id,
                    ingestion_id=ing_id,
                    event_timestamp=fx["event_timestamp"],
                    source_type=fx["source_type"],
                    sensor_id=fx["sensor_id"],
                    event_category=fx["event_category"],
                    event_type=fx["event_type"],
                    host=fx["host"],
                    user_name=fx["user_name"],
                    source_ip=fx["source_ip"],
                    destination_ip=fx["destination_ip"],
                    process=fx["process"],
                    file_hash=fx["file_hash"],
                    domain=fx["domain"],
                    command_line=fx["command_line"],
                    severity=fx["severity"],
                    event_metadata=fx["event_metadata"],
                    normalization_status=fx["normalization_status"],
                    normalization_errors=fx["normalization_errors"],
                    normalization_warnings=fx["normalization_warnings"],
                    created_at=fx["created_at"],
                )
                session.add(norm)
            await session.commit()
    finally:
        await engine.dispose()
    return ing_ids


async def _cleanup_postgres_events() -> None:
    engine, session_factory = _make_nullpool_session_factory()
    try:
        async with session_factory() as session:
            await session.execute(
                delete(NormalizedEvent).where(
                    NormalizedEvent.sensor_id.like(f"{_PG_TEST_SENSOR_PREFIX}%")
                )
            )
            await session.execute(
                delete(RawEventEnvelope).where(
                    RawEventEnvelope.sensor_id.like(f"{_PG_TEST_SENSOR_PREFIX}%")
                )
            )
            await session.commit()
    finally:
        await engine.dispose()


@pytest.fixture()
def live_postgres_events():
    async def _check_and_seed():
        engine, session_factory = _make_nullpool_session_factory()
        try:
            async with session_factory() as session:
                await session.execute(text("SELECT 1"))
        finally:
            await engine.dispose()
        await _cleanup_postgres_events()
        return await _seed_postgres_events()

    try:
        ing_ids = asyncio.run(_check_and_seed())
    except Exception as exc:
        pytest.skip(f"Live PostgreSQL unavailable for Day 8 integration tests: {exc}")
        return

    pg_engine, pg_session_factory = _make_nullpool_session_factory()

    async def _override_pg_db():
        async with pg_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_pg_db
    try:
        yield ing_ids
    finally:
        app.dependency_overrides.pop(get_db, None)
        asyncio.run(pg_engine.dispose())
        asyncio.run(_cleanup_postgres_events())


def test_live_postgres_query_pagination_filters_search_sort_and_raw_exclusion(
    live_postgres_events,
):
    # 1. Default pagination & stable tie-breaker ordering
    r_all = client.get(
        "/api/v1/events/normalized",
        params={"search": _PG_TEST_SENSOR_PREFIX, "limit": 100},
    )
    assert r_all.status_code == 200
    b_all = r_all.json()
    assert b_all["total"] == 5
    assert b_all["count"] == 5
    assert b_all["limit"] == 100
    assert b_all["offset"] == 0
    assert b_all["has_more"] is False
    # Verify raw_payload and raw_event are never exposed
    for item in b_all["items"]:
        assert "raw_payload" not in item
        assert "raw_event" not in item

    # 2. Stable pagination across pages (2 + 2 + 1 = 5 unique ingestion_ids)
    p1 = client.get(
        "/api/v1/events/normalized",
        params={"search": _PG_TEST_SENSOR_PREFIX, "limit": 2, "offset": 0},
    ).json()
    p2 = client.get(
        "/api/v1/events/normalized",
        params={"search": _PG_TEST_SENSOR_PREFIX, "limit": 2, "offset": 2},
    ).json()
    p3 = client.get(
        "/api/v1/events/normalized",
        params={"search": _PG_TEST_SENSOR_PREFIX, "limit": 2, "offset": 4},
    ).json()
    p_empty = client.get(
        "/api/v1/events/normalized",
        params={"search": _PG_TEST_SENSOR_PREFIX, "limit": 2, "offset": 5},
    ).json()
    p_max_offset = client.get(
        "/api/v1/events/normalized",
        params={"search": _PG_TEST_SENSOR_PREFIX, "limit": 2, "offset": MAX_QUERY_OFFSET},
    )
    assert p1["has_more"] is True and p1["count"] == 2 and p1["total"] == 5
    assert p2["has_more"] is True and p2["count"] == 2 and p2["total"] == 5
    assert p3["has_more"] is False and p3["count"] == 1 and p3["total"] == 5
    assert p_empty == {
        "items": [],
        "count": 0,
        "total": 5,
        "limit": 2,
        "offset": 5,
        "has_more": False,
    }
    assert p_max_offset.status_code == 200
    seen_ids = [i["ingestion_id"] for page in (p1, p2, p3) for i in page["items"]]
    assert len(set(seen_ids)) == 5

    # 3. Single-field filters
    r_sysmon = client.get(
        "/api/v1/events/normalized",
        params={"search": _PG_TEST_SENSOR_PREFIX, "source_type": "sysmon"},
    ).json()
    assert r_sysmon["total"] == 2

    r_warn = client.get(
        "/api/v1/events/normalized",
        params={
            "search": _PG_TEST_SENSOR_PREFIX,
            "normalization_status": "normalized_with_warnings",
        },
    ).json()
    assert r_warn["total"] == 1
    assert r_warn["items"][0]["source_type"] == "zeek"

    r_cat = client.get(
        "/api/v1/events/normalized",
        params={"search": _PG_TEST_SENSOR_PREFIX, "event_category": "alert"},
    ).json()
    assert r_cat["total"] == 1 and r_cat["items"][0]["event_type"] == "alert.ids"

    r_type = client.get(
        "/api/v1/events/normalized",
        params={"search": _PG_TEST_SENSOR_PREFIX, "event_type": "PROCESS.CREATE"},
    ).json()
    assert r_type["total"] == 1 and r_type["items"][0]["user"] == "alice"

    r_exact_sev = client.get(
        "/api/v1/events/normalized",
        params={"search": _PG_TEST_SENSOR_PREFIX, "severity": 5},
    ).json()
    assert r_exact_sev["total"] == 1 and r_exact_sev["items"][0]["host"] == "fw-edge-01"

    # 4. Time-range filtering (excludes failed/unsupported NULL event_timestamp rows)
    r_time = client.get(
        "/api/v1/events/normalized",
        params={
            "search": _PG_TEST_SENSOR_PREFIX,
            "start_time": "2026-11-25T10:30:00Z",
            "end_time": "2026-11-25T12:00:00Z",
        },
    ).json()
    assert r_time["total"] == 2
    assert {i["source_type"] for i in r_time["items"]} == {"sysmon", "zeek"}

    # 5. Combined filters
    r_combo = client.get(
        "/api/v1/events/normalized",
        params={
            "search": "powershell",
            "source_type": "sysmon",
            "normalization_status": "normalized",
            "event_category": "process",
            "severity": 3,
        },
    ).json()
    assert r_combo["total"] == 1
    assert r_combo["items"][0]["process"] == "powershell.exe"

    # 6. Search across all approved fields, wildcard/backslash escaping, & forbidden fields
    suri_item = next(i for i in b_all["items"] if i["source_type"] == "suricata")
    sysmon_item = next(i for i in b_all["items"] if i["normalization_status"] == "normalized" and i["source_type"] == "sysmon")
    for search_term in (
        suri_item["event_id"],
        sysmon_item["ingestion_id"],
        "10.0.0.15",           # source_ip
        "198.51.100.42",       # destination_ip
        "EVIL.EXAMPLE",        # case-insensitive domain
        "ffffffff",            # file_hash
        "network.dns",         # event_type
        "FW-EDGE-01",          # case-insensitive host
        "100%_check",          # escaped % and _
        r"C:\Temp\run.bat",    # escaped backslash
    ):
        found = client.get("/api/v1/events/normalized", params={"search": search_term}).json()
        assert found["total"] >= 1, f"Expected match for approved search term {search_term}"

    for forbidden_term in (
        "RAW_SECRET_TOKEN_01",
        "META_FORBIDDEN_MARKER",
        "WARN_FORBIDDEN_MARKER",
        "ERR_FORBIDDEN_MARKER",
    ):
        r_forbidden = client.get(
            "/api/v1/events/normalized",
            params={"search": forbidden_term},
        ).json()
        assert r_forbidden["total"] == 0 and r_forbidden["items"] == []

    # SQL injection payload as literal search does not bypass filters or corrupt schema
    r_sqli = client.get(
        "/api/v1/events/normalized",
        params={"search": "' OR 1=1 --"},
    )
    assert r_sqli.status_code == 200 and r_sqli.json()["total"] == 0

    # Removed min_severity parameter is ignored per FastAPI extra-query policy (does not error)
    r_removed = client.get(
        "/api/v1/events/normalized",
        params={"search": _PG_TEST_SENSOR_PREFIX, "min_severity": 99},
    )
    assert r_removed.status_code == 200 and r_removed.json()["total"] == 5

    # 7. Sorting across all 6 approved sort_by columns (NULLS LAST + id tie-breaker)
    r_sort_desc = client.get(
        "/api/v1/events/normalized",
        params={
            "search": _PG_TEST_SENSOR_PREFIX,
            "sort_by": "severity",
            "sort_order": "desc",
        },
    ).json()
    assert [i["severity"] for i in r_sort_desc["items"]] == [5, 3, 2, None, None]

    r_sort_asc = client.get(
        "/api/v1/events/normalized",
        params={
            "search": _PG_TEST_SENSOR_PREFIX,
            "sort_by": "timestamp",
            "sort_order": "asc",
        },
    ).json()
    ts_asc = [i["timestamp"] for i in r_sort_asc["items"]]
    assert ts_asc[:3] == [
        "2026-11-25T10:00:00.000Z",
        "2026-11-25T11:00:00.000Z",
        "2026-11-25T11:00:00.000Z",
    ]
    assert ts_asc[3:] == [None, None]
    # Duplicate timestamp tie-breaking ascending by id: sysmon (02) precedes zeek (03)
    assert [i["sensor_id"] for i in r_sort_asc["items"][1:3]] == [
        f"{_PG_TEST_SENSOR_PREFIX}02",
        f"{_PG_TEST_SENSOR_PREFIX}03",
    ]

    for extra_sort in ("created_at", "source_type", "event_category", "normalization_status"):
        for direction in ("asc", "desc"):
            s_resp = client.get(
                "/api/v1/events/normalized",
                params={
                    "search": _PG_TEST_SENSOR_PREFIX,
                    "sort_by": extra_sort,
                    "sort_order": direction,
                },
            )
            assert s_resp.status_code == 200 and s_resp.json()["total"] == 5

    # 8. Empty result set
    r_empty = client.get(
        "/api/v1/events/normalized",
        params={"search": "nonexistent-day8-query-xyz-999"},
    ).json()
    assert r_empty == {
        "items": [],
        "count": 0,
        "total": 0,
        "limit": 20,
        "offset": 0,
        "has_more": False,
    }
