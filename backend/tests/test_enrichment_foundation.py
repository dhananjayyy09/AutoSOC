"""
AutoSOC Day 9 Tests - Backend Event Enrichment Foundation
=======================================================
Covers:
  1. Unit & Service Tests (in-memory / mocked AsyncSession):
     - EventEnricherProtocol conformance & deterministic repeated enrichment
     - Successful enrichment persistence, missing/partial fields, malformed IPs
     - Provider exception resilience & non-blocking ingestion behavior
     - Invalid enrichment contract & raw_payload leakage rejection
     - Idempotent enrichment & retryable failures without duplicating records
     - Raw & normalized evidence immutability
     - API list/detail/retry endpoints & 404/422 validation
     - Migration 004 DDL & index alignment with EventEnrichment ORM model
  2. Live PostgreSQL Integration Tests (`autosoc_postgres`):
     - End-to-end POST /ingest -> GET /normalized/{event_id}/enrichment ->
       GET /enrichments -> POST /normalized/{event_id}/enrich
     - Retry update in place without duplicating `event_enrichments` rows
     - ON DELETE RESTRICT foreign key enforcement against `normalized_events`
"""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from main import app
from app.core.config import settings
from app.db.session import get_db
from app.events.enrichment_contract import (
    ENRICHMENT_PIPELINE_VERSION,
    EnrichmentStatusEnum,
    NormalizedEventEnrichmentPayload,
)
from app.events.enrichment_service import (
    DeterministicLocalEnricher,
    EnrichmentService,
)
from app.events.models import EventEnrichment, NormalizedEvent, RawEventEnvelope
from app.events.protocols import EventEnricherProtocol
from app.events.validation import compute_raw_hash

client = TestClient(app)


class InMemoryDay9Session:
    """In-memory AsyncSession double supporting raw, normalized, and enrichment tables."""

    def __init__(self) -> None:
        self.raw_rows: List[RawEventEnvelope] = []
        self.normalized_rows: List[NormalizedEvent] = []
        self.enrichment_rows: List[EventEnrichment] = []
        self._pending: Optional[Any] = None
        self._next_raw_id = 1
        self._next_norm_id = 1
        self._next_enrich_id = 1

    async def scalar(self, stmt: Any) -> Any:
        compiled = str(stmt)
        params = stmt.compile().params
        target_val = next(iter(params.values()), None)

        if "FROM event_enrichments" in compiled:
            if "count(" in compiled.lower():
                return len(self.enrichment_rows)
            if "WHERE event_enrichments.event_id" in compiled:
                return next(
                    (e for e in self.enrichment_rows if e.event_id == target_val),
                    None,
                )
            return None

        if "FROM normalized_events" in compiled:
            if "count(" in compiled.lower():
                return len(self.normalized_rows)
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
        if "FROM event_enrichments" in compiled:
            if "WHERE event_enrichments.event_id IN" in compiled:
                id_vals = set()
                for val in params.values():
                    if isinstance(val, (list, tuple, set)):
                        id_vals.update(val)
                    elif isinstance(val, str):
                        id_vals.add(val)
                ordered = [e for e in self.enrichment_rows if e.event_id in id_vals]
            else:
                raw_lim = params.get("param_1", 20)
                limit_val = int(raw_lim) if isinstance(raw_lim, int) else 20
                raw_off = params.get("param_2", 0)
                offset_val = int(raw_off) if isinstance(raw_off, int) else 0
                ordered = sorted(
                    self.enrichment_rows,
                    key=lambda r: (r.created_at, r.id),
                    reverse=True,
                )[offset_val : offset_val + limit_val]
        elif "FROM normalized_events" in compiled:
            raw_lim = params.get("param_1", 20)
            limit_val = int(raw_lim) if isinstance(raw_lim, int) else 20
            raw_off = params.get("param_2", 0)
            offset_val = int(raw_off) if isinstance(raw_off, int) else 0
            ordered = sorted(
                self.normalized_rows,
                key=lambda r: (r.created_at, r.id),
                reverse=True,
            )[offset_val : offset_val + limit_val]
        else:
            raw_lim = params.get("param_1", 20)
            limit_val = int(raw_lim) if isinstance(raw_lim, int) else 20
            raw_off = params.get("param_2", 0)
            offset_val = int(raw_off) if isinstance(raw_off, int) else 0
            ordered = sorted(
                self.raw_rows,
                key=lambda r: (r.received_at, r.id),
                reverse=True,
            )[offset_val : offset_val + limit_val]
        res = MagicMock()
        res.all.return_value = ordered
        return res

    def add(self, obj: Any) -> None:
        self._pending = obj

    async def commit(self) -> None:
        now = datetime.now(timezone.utc)
        if isinstance(self._pending, RawEventEnvelope):
            if any(r.ingestion_id == self._pending.ingestion_id for r in self.raw_rows):
                raise IntegrityError("INSERT", {}, Exception("dup ingestion_id"))
            self._pending.id = self._next_raw_id
            self._next_raw_id += 1
            if self._pending.received_at is None:
                self._pending.received_at = now
            self.raw_rows.append(self._pending)
        elif isinstance(self._pending, NormalizedEvent):
            self._pending.id = self._next_norm_id
            self._next_norm_id += 1
            if self._pending.created_at is None:
                self._pending.created_at = now
            self.normalized_rows.append(self._pending)
        elif isinstance(self._pending, EventEnrichment):
            if self._pending not in self.enrichment_rows:
                if not any(
                    n.id == self._pending.normalized_event_row_id
                    and n.event_id == self._pending.event_id
                    for n in self.normalized_rows
                ):
                    raise IntegrityError("INSERT", {}, Exception("FK normalized_events"))
                if any(e.event_id == self._pending.event_id for e in self.enrichment_rows):
                    raise IntegrityError("INSERT", {}, Exception("unique event_id"))
                self._pending.id = self._next_enrich_id
                self._next_enrich_id += 1
                self.enrichment_rows.append(self._pending)
        self._pending = None

    async def refresh(self, obj: Any) -> None:
        pass

    async def rollback(self) -> None:
        self._pending = None


@pytest.fixture()
def day9_db():
    session = InMemoryDay9Session()

    async def _override():
        yield session

    app.dependency_overrides[get_db] = _override
    yield session
    app.dependency_overrides.pop(get_db, None)


def _sample_norm_event(
    *,
    row_id: int = 1,
    event_id: Optional[str] = "aaaa1111-1111-4111-8111-111111111111",
    ingestion_id: str = "bbbb1111-1111-4111-8111-111111111111",
    source_ip: Optional[str] = "198.51.100.42",
    destination_ip: Optional[str] = "10.0.0.15",
    destination_port: Optional[int] = 443,
    domain: Optional[str] = "sub.evil.example.invalid",
    file_hash: Optional[str] = "sha256:" + ("a" * 64),
    command_line: Optional[str] = "powershell.exe -NoProfile",
) -> NormalizedEvent:
    return NormalizedEvent(
        id=row_id,
        event_id=event_id,
        raw_envelope_id=row_id,
        ingestion_id=ingestion_id,
        event_timestamp="2026-11-26T10:00:00.000Z",
        source_type="suricata",
        sensor_id="sensor-day9-unit",
        event_category="alert",
        event_type="alert.ids",
        host="host-day9",
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        domain=domain,
        file_hash=file_hash,
        command_line=command_line,
        severity=4,
        event_metadata={"pipeline_version": "0.2.0"},
        normalization_status="normalized",
        normalization_errors=[],
        normalization_warnings=[],
        created_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# 1. Unit tests: Deterministic enricher & contract compliance
# ---------------------------------------------------------------------------


def test_deterministic_local_enricher_protocol_and_determinism():
    enricher = DeterministicLocalEnricher()
    assert isinstance(enricher, EventEnricherProtocol)

    norm_dict = {
        "event_id": "aaaa1111-1111-4111-8111-111111111111",
        "ingestion_id": "bbbb1111-1111-4111-8111-111111111111",
        "source_ip": "198.51.100.42",
        "destination_ip": "10.0.0.15",
        "destination_port": 443,
        "domain": "sub.evil.example.invalid",
        "file_hash": "sha256:" + ("a" * 64),
        "command_line": "powershell.exe -NoProfile",
    }
    res1 = asyncio.run(enricher.enrich(norm_dict))
    res2 = asyncio.run(enricher.enrich(norm_dict))
    assert res1 == res2
    assert res1["status"] == "enriched"
    assert res1["provider"] == "autosoc.deterministic_local"
    assert res1["provider_version"] == "0.1.0"
    assert res1["live_lookup_performed"] is False
    assert res1["provenance"]["pipeline_version"] == ENRICHMENT_PIPELINE_VERSION
    assert res1["enrichment_data"]["observable_count"] == 4
    assert all(
        obs["verdict"] == "unknown" for obs in res1["enrichment_data"]["observables"]
    )
    assert res1["enrichment_data"]["context"]["network"]["is_internal_src"] is False
    assert res1["enrichment_data"]["context"]["network"]["is_internal_dst"] is True
    assert res1["enrichment_data"]["context"]["network"]["is_external_to_internal"] is True
    assert res1["enrichment_data"]["context"]["network"]["dst_port_well_known"] is True
    assert res1["enrichment_data"]["context"]["indicators"]["domain_tld"] == "invalid"
    assert res1["enrichment_data"]["context"]["indicators"]["subdomain_count"] == 2
    assert res1["enrichment_data"]["context"]["indicators"]["file_hash_algorithm"] == "sha256"


def test_partial_and_missing_enrichment_data_handled_safely(day9_db):
    async def _run():
        service = EnrichmentService()
        # Missing optional indicators -> valid deterministic record with no_observables
        minimal = _sample_norm_event(
            source_ip=None,
            destination_ip=None,
            destination_port=None,
            domain=None,
            file_hash=None,
            command_line=None,
        )
        day9_db.normalized_rows.append(minimal)
        rec = await service.enrich_normalized_event(day9_db, minimal)
        assert rec is not None
        assert rec.enrichment_status == "no_observables"
        assert rec.enrichment_data["observable_count"] == 0
        assert rec.enrichment_data["observables"] == []
        assert rec.enrichment_data["context"]["network"]["is_internal_src"] is None
        assert rec.enrichment_data["context"]["indicators"]["has_file_hash"] is False

        # Malformed IP produces canonical enriched_partial status with sanitized warning
        malformed_norm = _sample_norm_event(
            row_id=2,
            event_id="cccc1111-1111-4111-8111-111111111111",
            ingestion_id="dddd1111-1111-4111-8111-111111111111",
            source_ip="not-an-ip",
            destination_ip="10.0.0.1",
        )
        day9_db.normalized_rows.append(malformed_norm)
        rec_partial = await service.enrich_normalized_event(day9_db, malformed_norm)
        assert rec_partial is not None
        assert rec_partial.enrichment_status == "enriched_partial"
        assert len(rec_partial.enrichment_warnings) >= 1
        assert rec_partial.enrichment_data["observable_count"] >= 1
        assert rec_partial.enrichment_data["context"]["network"]["is_internal_src"] is None
        assert rec_partial.enrichment_data["context"]["network"]["is_internal_dst"] is True

        # Failed normalization without event_id is safely skipped
        no_event_norm = _sample_norm_event(row_id=3, event_id=None, ingestion_id="eeee1111-1111-4111-8111-111111111111")
        assert await service.enrich_normalized_event(day9_db, no_event_norm) is None

    asyncio.run(_run())


def test_provider_failure_and_invalid_contract_rejected_without_corrupting_evidence(day9_db):
    class RaisingEnricher:
        PROVIDER_NAME = "failing_ti"

        async def enrich(self, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
            raise RuntimeError("TI proxy timeout SECRET_API_KEY_DO_NOT_LEAK")

    class RawLeakEnricher:
        PROVIDER_NAME = "leaky_provider"

        async def enrich(self, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "status": "enriched",
                "provider": "leaky_provider",
                "provenance": {
                    "provider": "leaky_provider",
                    "source_event_id": normalized_event["event_id"],
                    "source_ingestion_id": normalized_event["ingestion_id"],
                },
                "enrichment_data": {
                    "context": {"network": {"geo": {"raw_payload": "SECRET_RAW"}}}
                },
            }

    class InvalidContractEnricher:
        PROVIDER_NAME = "bad_schema_provider"

        async def enrich(self, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "status": "enriched",
                "provider": "bad_schema_provider",
                "provenance": {
                    "provider": "bad_schema_provider",
                    "source_event_id": normalized_event["event_id"],
                    "source_ingestion_id": normalized_event["ingestion_id"],
                },
                "enrichment_data": {
                    "context": {"threat_intel": {"ip_score": 999}},  # violates le=100
                },
            }

    async def _run():
        norm = _sample_norm_event()
        day9_db.normalized_rows.append(norm)

        # 1. Exception does not leak secret string or overwrite normalized event
        failed_rec = await EnrichmentService(enricher=RaisingEnricher()).enrich_normalized_event(day9_db, norm)
        assert failed_rec is not None
        assert failed_rec.enrichment_status == "failed"
        assert "SECRET_API_KEY_DO_NOT_LEAK" not in json.dumps(failed_rec.enrichment_errors)
        assert norm.severity == 4 and norm.host == "host-day9"

        # 2. Retry updates the same record (attempt_count=2) rather than duplicating
        norm2 = _sample_norm_event(
            row_id=2,
            event_id="12121212-1111-4111-8111-111111111111",
            ingestion_id="13131313-1111-4111-8111-111111111111",
        )
        day9_db.normalized_rows.append(norm2)
        rec_leak = await EnrichmentService(enricher=RawLeakEnricher()).enrich_normalized_event(day9_db, norm2)
        assert rec_leak.enrichment_status == "failed"
        assert "forbidden raw payload key" in rec_leak.enrichment_errors[0].lower()

        norm3 = _sample_norm_event(
            row_id=3,
            event_id="14141414-1111-4111-8111-111111111111",
            ingestion_id="15151515-1111-4111-8111-111111111111",
        )
        day9_db.normalized_rows.append(norm3)
        rec_bad = await EnrichmentService(enricher=InvalidContractEnricher()).enrich_normalized_event(day9_db, norm3)
        assert rec_bad.enrichment_status == "failed"
        assert len(rec_bad.enrichment_errors) >= 1

        # Retrying `norm` with working DeterministicLocalEnricher recovers in place
        recovered = await EnrichmentService().enrich_normalized_event(day9_db, norm, retry=True)
        assert recovered.enrichment_id == failed_rec.enrichment_id
        assert recovered.attempt_count == 2
        assert recovered.enrichment_status == "enriched"
        assert len([r for r in day9_db.enrichment_rows if r.event_id == norm.event_id]) == 1

    asyncio.run(_run())


def test_ingest_triggers_enrichment_non_blocking_and_api_retrieval(day9_db):
    raw_obj = {
        "timestamp": "2026-11-26T10:00:00Z",
        "event_type": "alert",
        "src_ip": "198.51.100.42",
        "dest_ip": "10.1.2.3",
        "dest_port": 443,
        "proto": "tcp",
        "alert": {"severity": 2, "signature": "ET TEST"},
    }
    raw_payload = json.dumps(raw_obj)
    env = {
        "ingestion_id": "16161616-1111-4111-8111-111111111111",
        "source_type": "suricata",
        "sensor_id": "day9-sensor-01",
        "ingest_time": "2026-11-26T10:00:05Z",
        "raw_hash": compute_raw_hash(raw_payload),
        "raw_payload": raw_payload,
    }
    resp = client.post("/api/v1/events/ingest", json=env)
    assert resp.status_code == 201
    body = resp.json()
    assert body["normalization_status"] == "normalized"
    assert body["enrichment_status"] == "enriched"
    event_id = body["event_id"]

    # Retrieve enrichment detail and normalized list/detail exposure
    detail = client.get(f"/api/v1/events/normalized/{event_id}/enrichment")
    assert detail.status_code == 200
    d_body = detail.json()
    assert d_body["enrichment_status"] == "enriched"
    assert d_body["provider"] == "autosoc.deterministic_local"
    assert d_body["live_lookup_performed"] is False
    assert d_body["observable_count"] >= 2
    assert len(d_body["observables"]) >= 2
    assert d_body["context"]["network"]["is_external_to_internal"] is True
    assert d_body["enrichment_data"]["context"]["network"]["is_external_to_internal"] is True
    assert "raw_payload" not in d_body and "raw_event" not in d_body

    norm_list_resp = client.get("/api/v1/events/normalized", params={"limit": 10})
    assert norm_list_resp.status_code == 200
    norm_items = norm_list_resp.json()["items"]
    assert len(norm_items) == 1
    assert norm_items[0]["enrichment_status"] == "enriched"
    assert norm_items[0]["enrichment"]["observable_count"] >= 2

    norm_detail_resp = client.get(f"/api/v1/events/normalized/{event_id}")
    assert norm_detail_resp.status_code == 200
    assert norm_detail_resp.json()["enrichment_status"] == "enriched"
    assert norm_detail_resp.json()["enrichment"]["enrichment_id"] == d_body["enrichment_id"]

    # Repeated enrich call without retry is idempotent (attempt_count remains 1)
    re_trigger = client.post(f"/api/v1/events/normalized/{event_id}/enrich")
    assert re_trigger.status_code == 200
    assert re_trigger.json()["attempt_count"] == 1
    assert len(day9_db.enrichment_rows) == 1

    # List enrichments paginated endpoint
    lst = client.get("/api/v1/events/enrichments", params={"limit": 10, "enrichment_status": "enriched"})
    assert lst.status_code == 200
    l_body = lst.json()
    assert l_body["count"] == 1 and l_body["total"] == 1 and l_body["has_more"] is False

    # 404 & 422 checks
    assert client.get("/api/v1/events/normalized/00000000-0000-4000-8000-000000000000/enrichment").status_code == 404
    assert client.post("/api/v1/events/normalized/00000000-0000-4000-8000-000000000000/enrich").status_code == 404
    assert client.get("/api/v1/events/enrichments", params={"provider": "bad; DROP TABLE"}).status_code == 422

    # Enrichment exception during /ingest NEVER blocks 201 ingestion or normalization
    env2 = dict(env, ingestion_id="17171717-1111-4111-8111-111111111111")
    with patch(
        "app.api.v1.endpoints.events._default_enrichment_service.enrich_normalized_event",
        new_callable=AsyncMock,
        side_effect=RuntimeError("transient enrichment failure"),
    ):
        resp2 = client.post("/api/v1/events/ingest", json=env2)
    assert resp2.status_code == 201
    assert resp2.json()["status"] == "accepted"
    assert resp2.json()["normalization_status"] == "normalized"
    assert resp2.json()["enrichment_status"] == "failed"
    assert len(day9_db.raw_rows) == 2
    assert len(day9_db.normalized_rows) == 2


def test_migration_004_matches_orm_columns_and_fks():
    migration_path = (
        Path(__file__).resolve().parent.parent
        / "app"
        / "db"
        / "migrations"
        / "004_create_event_enrichments.sql"
    )
    sql = migration_path.read_text(encoding="utf-8")
    for col in EventEnrichment.__table__.columns:
        assert col.name in sql, f"Column {col.name} missing from 004 migration"
    assert "REFERENCES normalized_events(id) ON DELETE RESTRICT" in sql
    assert "REFERENCES normalized_events(event_id) ON DELETE RESTRICT" in sql


# ---------------------------------------------------------------------------
# 2. Live PostgreSQL Integration Tests (`autosoc_postgres`)
# ---------------------------------------------------------------------------

_PG_DAY9_PREFIX = "day9-pg-test-"


def _make_nullpool_session_factory():
    engine = create_async_engine(settings.async_database_uri, poolclass=NullPool)
    factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    return engine, factory


async def _cleanup_day9_pg() -> None:
    engine, factory = _make_nullpool_session_factory()
    try:
        async with factory() as session:
            await session.execute(
                text(
                    "DELETE FROM event_enrichments WHERE event_id IN "
                    "(SELECT event_id FROM normalized_events WHERE sensor_id LIKE :p AND event_id IS NOT NULL)"
                ),
                {"p": f"{_PG_DAY9_PREFIX}%"},
            )
            await session.execute(
                delete(NormalizedEvent).where(
                    NormalizedEvent.sensor_id.like(f"{_PG_DAY9_PREFIX}%")
                )
            )
            await session.execute(
                delete(RawEventEnvelope).where(
                    RawEventEnvelope.sensor_id.like(f"{_PG_DAY9_PREFIX}%")
                )
            )
            await session.commit()
    finally:
        await engine.dispose()


@pytest.fixture()
def live_postgres_day9():
    async def _check():
        engine, factory = _make_nullpool_session_factory()
        try:
            async with factory() as session:
                await session.execute(text("SELECT 1 FROM event_enrichments LIMIT 1"))
        finally:
            await engine.dispose()
        await _cleanup_day9_pg()

    try:
        asyncio.run(_check())
    except Exception as exc:
        pytest.skip(f"Live PostgreSQL / event_enrichments unavailable: {exc}")
        return

    pg_engine, pg_factory = _make_nullpool_session_factory()

    async def _override_pg_db():
        async with pg_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_pg_db
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_db, None)
        asyncio.run(pg_engine.dispose())
        asyncio.run(_cleanup_day9_pg())


def test_live_postgres_enrichment_e2e_retry_immutability_and_fk_restrict(live_postgres_day9):
    raw_obj = {
        "timestamp": "2026-11-26T10:00:00Z",
        "event_type": "alert",
        "src_ip": "198.51.100.99",
        "dest_ip": "10.0.0.50",
        "dest_port": 22,
        "proto": "tcp",
        "alert": {"severity": 1, "signature": "ET SSH LIVE"},
        "dns": {"rrname": "c2.day9-test.invalid"},
    }
    raw_payload = json.dumps(raw_obj)
    ing_id = str(uuid4())
    resp = client.post(
        "/api/v1/events/ingest",
        json={
            "ingestion_id": ing_id,
            "source_type": "suricata",
            "sensor_id": f"{_PG_DAY9_PREFIX}01",
            "ingest_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "raw_hash": compute_raw_hash(raw_payload),
            "raw_payload": raw_payload,
        },
    )
    assert resp.status_code == 201
    event_id = resp.json()["event_id"]
    assert resp.json()["enrichment_status"] == "enriched"

    # Normalized event columns remain strictly intact while exposing canonical enrichment
    norm_before = client.get(f"/api/v1/events/normalized/{event_id}").json()
    assert norm_before["severity"] == 5
    assert norm_before["source_ip"] == "198.51.100.99"
    assert norm_before["enrichment_status"] == "enriched"
    assert norm_before["enrichment"] is not None
    assert norm_before["enrichment"]["observable_count"] >= 3

    # Enrichment record persisted separately in PostgreSQL
    e_resp = client.get(f"/api/v1/events/normalized/{event_id}/enrichment")
    assert e_resp.status_code == 200
    e_body = e_resp.json()
    assert e_body["provider"] == "autosoc.deterministic_local"
    assert e_body["observable_count"] >= 3
    assert e_body["context"]["network"]["is_external_to_internal"] is True
    assert e_body["context"]["network"]["dst_port_well_known"] is True
    assert e_body["context"]["indicators"]["domain_tld"] == "invalid"
    assert e_body["enrichment_data"]["context"]["network"]["is_external_to_internal"] is True
    assert e_body["attempt_count"] == 1

    # Forced retry updates existing record in place without creating duplicate row
    retry_resp = client.post(
        f"/api/v1/events/normalized/{event_id}/enrich",
        params={"force_retry": True},
    )
    assert retry_resp.status_code == 200
    assert retry_resp.json()["enrichment_id"] == e_body["enrichment_id"]
    assert retry_resp.json()["attempt_count"] == 2

    # List endpoint filters cleanly
    lst_resp = client.get(
        "/api/v1/events/enrichments",
        params={"provider": "autosoc.deterministic_local", "enrichment_status": "enriched"},
    )
    assert lst_resp.status_code == 200
    assert lst_resp.json()["total"] >= 1

    # Verify ON DELETE RESTRICT prevents deleting parent normalized_event while enrichment exists
    async def _verify_fk_and_norm_unchanged():
        eng, fac = _make_nullpool_session_factory()
        try:
            async with fac() as session:
                with pytest.raises(IntegrityError):
                    await session.execute(
                        delete(NormalizedEvent).where(NormalizedEvent.event_id == event_id)
                    )
                    await session.commit()
                await session.rollback()
        finally:
            await eng.dispose()

    asyncio.run(_verify_fk_and_norm_unchanged())
    norm_after = client.get(f"/api/v1/events/normalized/{event_id}").json()
    assert norm_after["enrichment"]["attempt_count"] == 2
    assert {k: v for k, v in norm_after.items() if k != "enrichment"} == {
        k: v for k, v in norm_before.items() if k != "enrichment"
    }
