# Sentinel Orchestrator Code Flow

## 1. Runtime Startup

1. `docker compose up` starts:

- `backend` (FastAPI + scheduler loop owner)
- `worker` (Celery workers running scanners)
- `beat` (periodic schedule dispatch)
- infra services (`redis`, `db`, `minio`, etc.)

2. Backend app boot path:

- `app/main.py` -> FastAPI `lifespan`
- DB schema + admin bootstrap
- scheduler startup guard:
  - `acquire_scheduler_process_lock()` ensures only one process owns scheduler
  - `init_scheduler(...)`
  - `start_scheduler_thread()` runs scheduler tick loop

3. Scheduler loop thread:

- `app/main.py` -> `start_scheduler_thread()` -> `CeleryDispatcher.run_once()`
- each tick:
  - drain completion events
  - apply state transitions
  - run invariant/alert checks
  - schedule dispatchable tasks

## 2. Scan Submission Flow

1. API path:

- `app/api/v1/endpoints/scans.py` -> `POST /api/v1/scans/start`
- persists `Scan` row (`PENDING`)
- gets scheduler via `get_scheduler()`
- submits into engine: `ScanSubmitter.submit_scan(...)`

2. Submitter + DAG:

- `engine/services/scan_submitter.py`
  - normalize request
  - compute deterministic target identity (`target_identity`)
  - build DAG (`engine/planner/dag_builder.py`)
  - compute deterministic `dag_shape_signature`
  - write `scan_results/<scan_id>/meta.json`
  - register DAG (`scheduler.register_scan_dag(...)`)

## 3. Deterministic Identity (Phase 1.6)

1. `engine/planner/identity.py`:

- normalizes URL/domain/IP/repo values
- generates stable target ID:
  - `sha256(f"{type}:{normalized_value}")`

2. Stored in scan meta:

- `scan_results/<scan_id>/meta.json`
- fields:
  - `target_identity`
  - `dag_shape_signature`

## 4. Scheduler Operational Intelligence (Phase 1.6)

1. `engine/scheduler/operational_intel.py` writes per-scan artifacts:

- `scheduler_events.jsonl`
- `alerts.jsonl`
- `timeline.json`

2. Required scheduler decision events emitted with context:

- `TASK_ADMITTED`
- `TASK_READY`
- `TASK_BLOCKED`
- `TASK_DISPATCHED`
- `TASK_RUNNING`
- `TASK_COMPLETED`
- `TASK_FAILED`
- `TOKENS_RESERVED`
- `TOKENS_RELEASED`

3. Timeline timestamps per task:

- `admitted_at`
- `ready_at`
- `dispatched_at`
- `running_at`
- `completed_at`

## 5. Runtime Metrics & Alerts

1. `engine/scheduler/metrics.py` snapshot fields:

- `ready_queue_size`
- `in_flight_count`
- `tasks_completed_total`
- `tasks_failed_total`
- `average_task_latency`
- `tokens_in_use_per_tier`
- `blocked_due_to_resource_total`
- `completion_rate_per_minute`

2. Scheduler hard invariants checked each tick:

- READY task must be present in queue
- RUNNING task must be present in in-flight registry
- `used_tokens <= max_tokens`
- scan stall invariant when incomplete tasks exist but queue/in-flight are empty

3. Soft alerts emitted:

- `STALL_DETECTED`
- `TASK_TIMEOUT`
- `HIGH_FAILURE_RATE`
- `RESOURCE_LEAK`
- `STARVATION_RISK`

## 6. Dispatch and Execution

1. Tick dispatch:

- `CeleryDispatcher.run_once()` calls `scheduler.schedule_once(...)`
- for each dispatchable task:
  - mark RUNNING timestamps
  - reserve resources
  - enqueue Celery task

2. Tool tasks:

- `scanner/tasks.py::run_tool_task`
- writes per-tool findings JSONL:
  - `scan_results/<scan_id>/<task_type>/findings.jsonl`

3. Post-process tasks:

- `CORRELATION` -> merges findings
- optional `ATTACK_PATH` -> attacker path analysis
- optional `AI_SUMMARY` -> summary text
- `REPORT` -> JSON + PDF

## 7. Completion Event Path (Cross-Process)

1. Worker callback task:

- `engine/dispatch/scheduler_callbacks.py::scheduler_task_completed`
- publishes event to Redis-backed scheduler event bus

2. Event bus:

- `engine/scheduler/event_bus.py`
- `publish_event(...)` -> Redis list `sentinel:scheduler:events`
- `drain_events(...)` -> backend scheduler thread consumes and clears

3. State transition:

- `engine/scheduler/events.py::drain_scheduler_events`
- applies `TASK_COMPLETED` / `TASK_FAILED` into
  `scheduler.on_task_complete(...)`

## 8. Frontend Observability APIs

### Per-scan observability (owner or admin)

- `GET /api/v1/scans/{scan_id}/observability`
  - overview + latest events/alerts + timeline availability
- `GET /api/v1/scans/{scan_id}/observability/events?limit=200`
- `GET /api/v1/scans/{scan_id}/observability/alerts?limit=200`
- `GET /api/v1/scans/{scan_id}/observability/timeline`

These are intended for scan-focused dashboard pages.

### Global scheduler observability (admin)

- `GET /api/v1/internal/scheduler/metrics`
- `GET /api/v1/internal/scheduler/overview`

These are intended for Grafana-like global operational panels.

## 9. Key Files

- Startup: `app/main.py`
- API submit: `app/api/v1/endpoints/scans.py`
- API internal observability: `app/api/v1/endpoints/internal.py`
- Submitter: `engine/services/scan_submitter.py`
- Identity: `engine/planner/identity.py`
- DAG builder: `engine/planner/dag_builder.py`
- Scheduler core: `engine/scheduler/scheduler.py`
- Operational intelligence: `engine/scheduler/operational_intel.py`
- Metrics: `engine/scheduler/metrics.py`
- Event bus: `engine/scheduler/event_bus.py`
- Dispatcher: `engine/dispatch/celery_dispatch.py`
- Worker tasks: `scanner/tasks.py`
- Reporting writers: `scanner/reporting/json_writer.py`, `scanner/reporting/pdf_writer.py`
- Attack path modeling: `scanner/ai/attack_path.py`
