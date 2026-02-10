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
  - schedule dispatchable tasks

## 2. Scan Submission Flow

1. CLI path:

- `cli/cli.py` -> `start-scan`
- if token exists: submit through API
- if token missing: fallback local mode
- `enable_ai` is now user-controlled (`--enable-ai` / `--disable-ai`)

2. API path:

- `app/api/v1/endpoints/scans.py` -> `POST /api/v1/scans/start`
- persists `Scan` row (`PENDING`)
- gets scheduler via `get_scheduler()`
- submits into engine: `ScanSubmitter.submit_scan(...)`
- passes `enable_ai` through to DAG planning

3. Submitter + DAG:

- `engine/services/scan_submitter.py`
  - normalize request
  - write `scan_results/<scan_id>/meta.json`
  - build DAG (`engine/planner/dag_builder.py`)
  - register DAG (`scheduler.register_scan_dag(...)`)

## 3. Scheduler State Model

Core structures in `engine/scheduler/scheduler.py`:

- `runtime[task_id]` -> task state (`READY`, `RUNNING`, `COMPLETED`, ...)
- `queue` -> priority heap of READY tasks
- `in_flight` -> currently running tasks + consumed cost
- `_dependents` -> reverse DAG edges for unblocking children

Important invariant:

- If a task is `READY`, it must be present in queue or re-queued on backpressure.

## 4. Dispatch and Execution

1. Tick dispatch:

- `CeleryDispatcher.run_once()` calls `scheduler.schedule_once(...)`
- for each dispatchable task:
  - mark `RUNNING`
  - reserve resources
  - enqueue Celery task

2. Tool tasks:

- `scanner/tasks.py::run_tool_task`
- executes tool adapter and writes per-tool findings to
  `scan_results/<scan_id>/<task_type>/findings.jsonl`
- emits `output_paths` as real file paths (not raw tuples/text)
- always emits completion callback (`scheduler.task_completed`)

3. Post-process tasks:

- `CORRELATION` -> aggregates tool findings JSONL files from dependency outputs
- optional `ATTACK_PATH` -> Ollama-based attacker path + AI crawler leak analysis
- optional `AI_SUMMARY` -> summary that includes attack-path context
- `REPORT` -> JSON/PDF outputs

## 5. Completion Event Path (Cross-Process)

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

## 6. Unblocking Logic

1. On completion:

- `on_task_complete(...)`:
  - remove from `in_flight`
  - release resources
  - call `_handle_success(...)` or `_handle_failure(...)`

2. Success path:

- `_handle_success(...)`
  - set completed task state to `COMPLETED`
  - for each dependent:
    - if all dependencies are `COMPLETED`, set dependent to `READY`
    - push dependent into queue

3. Backpressure behavior:

- when queue pop hits resource limit, task is re-queued and tick exits
- prevents READY-task loss and DAG deadlocks

## 7. Why CORRELATION/REPORT Can Stall

Typical causes:

- completion event not reaching backend scheduler
- READY task popped and dropped on resource backpressure
- dispatch payload mismatch for post-process task arguments
- correlation receiving non-path or nested path payloads
- correlator using outdated model/mapper APIs

Current code path addresses these by:

- Redis event bus for cross-process events
- re-queue on backpressure
- explicit kwargs for correlation/report dispatch
- input path normalization in correlator (flatten nested lists/tuples)
- `UnifiedFinding` serialization via `model_dump()`
- JSON-safe serialization via `model_dump(mode="json")` for set/enum fields

## 8. Key Files

- Startup: `app/main.py`
- API submit: `app/api/v1/endpoints/scans.py`
- Submitter: `engine/services/scan_submitter.py`
- DAG builder: `engine/planner/dag_builder.py`
- Scheduler core: `engine/scheduler/scheduler.py`
- Event bus: `engine/scheduler/event_bus.py`
- Event applier: `engine/scheduler/events.py`
- Dispatcher: `engine/dispatch/celery_dispatch.py`
- Worker tasks: `scanner/tasks.py`
- Completion callback: `engine/dispatch/scheduler_callbacks.py`
- Correlator: `scanner/correlation/disk_correlator.py`
- Correlation mapper: `scanner/correlation/mapper.py`
- Attack path modeling: `scanner/ai/attack_path.py`
- AI provider factory: `scanner/ai/provider.py`

## 9. Session Fix Summary (Applied)

1. Scheduler ownership and duplicate process guard:
- `app/main.py`
- `engine/scheduler/runtime.py`

2. Cross-process completion delivery:
- `engine/scheduler/event_bus.py` moved to Redis-backed queue
- `engine/dispatch/scheduler_callbacks.py` publishes events (no direct scheduler mutation in worker)
- `engine/scheduler/events.py` emits via event bus

3. Scheduler consistency and queue safety:
- single `in_flight` registry usage in `engine/scheduler/scheduler.py`
- enum-safe duplicate completion check
- re-queue READY task on resource backpressure

4. Dispatch correctness:
- removed duplicate completion hooks in `engine/dispatch/celery_dispatch.py`
- added required kwargs for `CORRELATION`, `ATTACK_PATH`, `AI_SUMMARY`, `REPORT`

5. Worker/callback hardening:
- fixed callback arg compatibility and `TASK_FAILED` emit typo in `engine/dispatch/callbacks.py`
- fixed DB close flow in `scanner/tasks.py`

6. Correlation pipeline fixes:
- `scanner/correlation/disk_correlator.py` updated to current APIs
- handles missing/empty input files safely
- normalizes nested input path payloads
- serializes findings with `model_dump()`
- `scanner/tasks.py` now writes findings JSONL and passes file paths downstream

7. AI enablement and attack-path stage:
- `ScanCreate.enable_ai` added and propagated from CLI/API submission
- CLI now supports `--enable-ai` (default) and `--disable-ai`
- DAG adds `ATTACK_PATH` before `AI_SUMMARY` when `enable_ai=true`
- `run_attack_path_task` generates `/scan_results/<scan_id>/ai/attack_path.txt`
- AI summary consumes attack-path context
- Provider factory defaults to Ollama (`AI_PROVIDER`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL`)
