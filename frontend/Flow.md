# AutoSOC Frontend Flow Documentation

## Day 2 - October 8, 2026 (Updated - Final Verification)

### Application Liveness and Readiness Flow

```
                           +------------------------+
                           |  Frontend Component    |
                           |     (HealthCheck)      |
                           +-----------+------------+
                                       |
                   +-------------------+-------------------+
                   |                                       |
                   v                                       v
        +--------------------+                  +--------------------+
        |   useHealthCheck   |                  |    useReadiness    |
        +----------+---------+                  +----------+---------+
                   |                                       |
                   v                                       v
         ApiClient.get("/health")                ApiClient.get("/ready")
                   |                                       |
                   v                                       v
        +--------------------+                  +--------------------+
        |  GET /health       |                  |  GET /ready        |
        |  Backend Process   |                  |  FastAPI Endpoint  |
        +----------+---------+                  +----------+---------+
                   |                                       |
         +---------+---------+                   +---------+---------+
         |                   |                   |         |         |
      HTTP 200            Network             HTTP 200  HTTP 503  Network
         |                 Fail                  |         |       Fail
         v                   v                   v         v         v
     CONNECTED          UNAVAILABLE            READY   DEGRADED  UNAVAILABLE
                                                           |
                                               Parse detail payload:
                                               - postgres: true/false
                                               - redis: true/false
                                               - qdrant: true/false
                                               - kafka: true/false
```

### Readiness Check Execution Flow

1. **Component Initialization:**
   - `HealthCheck` mounts on the `/login` view.
   - `useHealthCheck` hook initializes: `status: "loading"`.
   - `useReadiness` hook initializes: `state: "loading"`.

2. **Parallel Status Fetching:**
   - `checkHealth()` calls `GET /health` with `cache: "no-store"`.
   - `checkReadiness()` calls `GET /ready` with `cache: "no-store"`.

3. **Readiness Response Processing:**
   - **Case A: HTTP 200 (Healthy)**
     - Backend returns: `{"status": "ok", "postgres": true, "redis": true, "qdrant": true, "kafka": true}`.
     - `checkReadiness` verifies all flags are `true`.
     - `useReadiness` state transitions to `"ready"`.
     - UI displays `READY` in green and all four dependencies as "Ready".
   - **Case B: HTTP 503 (Degraded)**
     - Backend raises `HTTPException(status_code=503, detail={"status": "degraded", ...})`.
     - `ApiClient.get` catches non-OK status, parses JSON body into `ApiError.data`, and throws `ApiError`.
     - `checkReadiness` detects `error.status === 503`, extracts `error.data.detail`, and returns `state: "degraded"` along with the component statuses.
     - UI displays `DEGRADED / NOT READY` in amber and marks failing dependencies as "Not Ready".
   - **Case C: Network Failure / Connection Refused**
     - Request times out (10s) or encounters network error.
     - `checkReadiness` catches error and returns `state: "unavailable"`.
     - UI displays `UNAVAILABLE` in red.

4. **Operator Refresh / Retry Action:**
   - Operator clicks "Refresh" button.
   - `handleRetryAll` triggers `retryLiveness()` and `retryReadiness()`.
   - Spin animation indicates active retry.
   - Both endpoints are re-queried and UI re-renders with fresh state.
