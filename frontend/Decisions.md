# AutoSOC Frontend Architecture Decisions

## Day 2 - October 8, 2026 (Updated - Final Verification)

### Readiness vs Liveness Separation

**Decision: Distinct endpoints and hooks for liveness (/health) and readiness (/ready)**
- **Rationale**: Application liveness indicates whether the backend Python/FastAPI process is alive and receiving HTTP requests. Dependency readiness indicates whether all backing infrastructure (PostgreSQL, Redis, Qdrant, Kafka) are connected and operational. Conflating these two concepts causes false negatives where a running backend is reported as dead, or false positives where a running backend cannot process operations due to missing infrastructure.
- **Trade-off**: Requires two API calls and two custom hooks (`useHealthCheck` and `useReadiness`), but provides accurate status breakdown to operators.
- **Impact**: Operators can immediately see whether an outage is at the application process level or at a specific dependency (e.g., PostgreSQL down while Redis is up).

### Error Handling & HTTP 503 Degraded State

**Decision: Custom `ApiError` class with HTTP status code and parsed body preservation**
- **Rationale**: FastAPI returns HTTP 503 with a structured JSON body `{"detail": {"status": "degraded", "postgres": false, ...}}` when a readiness check fails. Generic `fetch` abstractions that only throw a generic `Error` discard the 503 response body, preventing the UI from knowing which specific dependency failed. `ApiError` preserves `status`, `statusText`, and parsed `data`.
- **Trade-off**: Slightly more logic in the API client, but essential for accurate degraded state reporting.
- **Impact**: `checkReadiness()` distinguishes HTTP 200 (Ready), HTTP 503 (Degraded with individual component states), and network failures (Unavailable).

### UI Representation of Readiness

**Decision: Display overall readiness status plus 4-box infrastructure dependency breakdown**
- **Rationale**: In a SOC platform, operations personnel need immediate clarity on dependency health. The UI explicitly displays:
  - `READY` (green, all 4 services ready)
  - `DEGRADED / NOT READY` (amber, partial service failure)
  - `UNAVAILABLE` (red, connection failure)
  - Individual statuses for PostgreSQL, Redis, Qdrant, and Kafka.
- **Trade-off**: Slightly larger card on the login view, but zero fake SOC data or premature dashboard clutter.
- **Impact**: Directly meets Day 2 infrastructure verification requirements while maintaining professional SOC design.

### Font System & Offline Sandboxed Builds

**Decision: Use system font fallbacks in layout instead of build-time Google Fonts fetching**
- **Rationale**: Next.js `next/font/google` attempts to fetch font files from `fonts.googleapis.com` during the production build. In sandboxed development environments or offline production builds without public internet access, this causes hard build failures. Using system sans-serif and monospace font stacks guarantees build determinism and 100% offline capability.
- **Trade-off**: Custom Geist web font is replaced with high-quality system native fonts, but build reliability is 100%.
- **Impact**: Next.js production build succeeds consistently without external network dependencies.

### Testing Strategy & Workspace Root Script

**Decision: Add root `package.json` proxy script while keeping `frontend/package.json` authoritative**
- **Rationale**: Developers or CI runners may execute `npm test` from the repository root `AutoSOC` or from inside `frontend/`. Previously, executing `npm test` from the root returned `Missing script: "test"`. Adding a root proxy script delegating to `npm test --prefix frontend` ensures `npm test` succeeds regardless of working directory.
- **Trade-off**: Minimal root file added, but eliminates developer confusion and CI script failures.
- **Impact**: `npm test` executes cleanly and passes all 21 tests from both root and `frontend/`.
