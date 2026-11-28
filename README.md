# AutoSOC — Explainable Multi-Agent AI Platform for Autonomous Security Operations and Threat Hunting

AutoSOC is a research and engineering platform that combines large language models (LLMs), multi-agent orchestration, and classical detection engineering to build an explainable, autonomous Security Operations Center (SOC).

---

## Team

| Developer | Responsibility |
|-----------|----------------|
| **DJ** | Architecture, backend, AI infrastructure, orchestration, DevOps |
| **Pranjal** | Cybersecurity pipeline, detection, threat intelligence, security data, evaluation |
| **Shreyash** | Frontend, dashboard, visualization, UX |

---

## Project Goals

- Autonomous triage of security alerts with LLM-driven reasoning
- Explainable detections grounded in MITRE ATT&CK
- Multi-agent coordination for threat hunting, enrichment, and response
- Normalized security-event model across heterogeneous telemetry sources
- Reproducible evaluation on public IDS/EDR/network datasets

---

## Repository Layout

```
AutoSOC/
├── README.md
├── docs/
│   ├── ChangeLog.md                         # WHAT changed (mandatory Day 2+)
│   ├── Decisions.md                         # WHY architecture decisions were made (mandatory Day 2+)
│   ├── Flow.md                              # HOW security data flows (mandatory Day 2+)
│   ├── security/
│   │   ├── security-event-model.md          # Normalized event schema (v0.2.0)
│   │   ├── security-data-contract.md        # Master security data contract (Day 2)
│   │   ├── detection-pipeline.md            # Full pipeline architecture (v0.1.2)
│   │   ├── security-tools.md                # Tool integration research
│   │   ├── security-baseline.md             # Security requirements baseline
│   │   └── phase2-implementation-plan.md   # Phase 2 Weeks 4–7 implementation plan
│   └── research/
│       ├── dataset-plan.md                  # Dataset evaluation and selection
│       └── literature-tracker.csv           # Research paper tracker
├── backend/                                 # DJ — API, orchestration, infrastructure
├── agents/                                  # DJ — AI agent definitions
├── frontend/                                # Shreyash — dashboard and UI
└── data/                                    # Pranjal — sample data, schemas, loaders
```

---

## Day 1 Status

- [x] Repository initialized — branch `feature/pranjal/day1-security-foundation`
- [x] Security event model documented
- [x] Detection pipeline documented
- [x] Security tools researched
- [x] Dataset plan completed
- [x] Literature tracker seeded
- [x] Security baseline drafted

---

## Day 2 Status — Integrated Baseline

### DJ — Backend and Infrastructure
- [x] FastAPI application foundation with centralized lifespan context management (`backend/main.py`, `backend/app/core/lifespan.py`)
- [x] Centralized configuration via `pydantic-settings` with type-safe environment variable parsing (`backend/app/core/config.py`)
- [x] Centralized logging and global exception handler preventing stack trace leakage (`backend/app/core/exceptions.py`, `backend/app/core/logging.py`)
- [x] PostgreSQL persistence integration using SQLAlchemy and asyncpg connection pooling (`backend/app/db/session.py`)
- [x] Redis caching client abstraction with asynchronous ping (`backend/app/services/redis_client.py`)
- [x] Qdrant vector database client abstraction (*Note: HTTP connectivity on port 6333 restricted in sandboxed development proxy*) (`backend/app/services/qdrant_client.py`)
- [x] Kafka client integration via `confluent_kafka.admin.AdminClient` (`backend/app/services/kafka_client.py`)
- [x] Operational endpoints: `GET /health` (liveness, HTTP 200) and `GET /ready` (readiness, HTTP 200 healthy / HTTP 503 degraded) (`backend/app/api/health.py`)
- [x] Active PostgreSQL `SELECT 1` validation within readiness probe
- [x] Deterministic backend test suite with mocking for dependency state transitions (5/5 tests passing in `backend/tests/`)

### Pranjal — Security Data Architecture
- [x] Security data contract formalized (`docs/security/security-data-contract.md`)
- [x] Event lifecycle documented with all 8 stages, inputs, outputs, failure paths
- [x] Source adapter contracts defined (Sysmon, Zeek, Suricata, Auth logs)
- [x] Detection Result contract defined (formal schema + terminology disambiguation)
- [x] Feature Set contract defined (feature schema + derivation rules)
- [x] Validation stage established as explicit pipeline stage (separate from Normalization)
- [x] Duplicate event strategy documented (flag, never discard)
- [x] Architectural boundaries documented (9 interface rules)
- [x] Phase 2 Weeks 4–7 implementation plan created (`docs/security/phase2-implementation-plan.md`)
- [x] Centralized traceability maintained in `docs/ChangeLog.md`, `docs/Decisions.md` (DECISION-001 through DECISION-009), `docs/Flow.md`
- [x] Security Event Model updated to v0.2.0 (`ingestion_id`, `event_category`, `metadata.raw_hash`)
- [x] Detection Pipeline updated to v0.1.2 (Validation stage in diagram and definitions)

### Shreyash — Frontend Foundation
- [x] Frontend API integration client with timeout and abort handling (`frontend/src/lib/api.ts`)
- [x] Custom `ApiError` preserving HTTP 503 structured degraded detail payloads
- [x] Reusable React hooks for liveness (`useHealthCheck`) and infrastructure readiness (`useReadiness`)
- [x] System status UI component displaying 4-way infrastructure dependency health (PostgreSQL, Redis, Qdrant, Kafka)
- [x] Liveness vs. readiness conceptual separation visually enforced in dashboard
- [x] Manual retry functionality for degraded or unavailable services
- [x] Root package script proxy (`package.json`) delegating `test`, `build`, `lint`, and `dev` to `frontend/`
- [x] Frontend unit and component test suite (4 test suites, 21 tests passing via Jest & React Testing Library)
- [x] Next.js 16 production build verified (15 static routes pre-rendered successfully)
- [x] Frontend-specific traceability documented in `frontend/ChangeLog.md`, `frontend/Decisions.md`, `frontend/Flow.md`

> **Scope Note:** Telemetry ingestion consumers, live source collectors, Sigma/ML detection engines, AI agents, LLMs, RAG vector pipelines, and autonomous remediation are planned for future phases (Phase 2 & Phase 3) and are intentionally not implemented in Day 2.

---

## Getting Started

### 1. Prerequisites
- Python 3.11+ (backend virtual environment at `.venv/`)
- Node.js 20+ and npm (frontend under `frontend/`)
- Docker & Docker Compose (for local PostgreSQL, Redis, Qdrant, Zookeeper, and Kafka)

### 2. Environment Configuration
Copy the environment template and adjust values as needed for local development (never commit real secrets or API keys):
```bash
cp .env.example .env
```

### 3. Start Local Infrastructure
```bash
docker compose up -d
```
Services exposed locally by `docker-compose.yml`:
- **PostgreSQL 15:** `localhost:5432`
- **Redis 7:** `localhost:6379`
- **Qdrant:** `localhost:6333` (HTTP) / `localhost:6334` (gRPC)
- **Zookeeper / Kafka:** `localhost:2181` / `localhost:9092`

Database SQL migrations live in `backend/app/db/migrations/` (`001_create_raw_event_envelopes.sql` through `004_create_event_enrichments.sql`). On application startup, `init_db()` verifies PostgreSQL connectivity and ensures ORM tables exist.

### 4. Start the Backend API
```bash
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
Operational verification endpoints:
- `GET http://127.0.0.1:8000/health` (liveness)
- `GET http://127.0.0.1:8000/ready` (4-way infrastructure readiness)
- `GET http://127.0.0.1:8000/api/v1/system/info` (platform metadata)

### 5. Start the Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```

### 6. Run Tests
```bash
# Backend tests (from backend/)
pytest tests -v -rs

# Frontend tests (from frontend/)
npm test
```

---

## License

Research use only. License TBD.
