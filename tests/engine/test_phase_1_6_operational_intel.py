import json
from pathlib import Path

from engine.planner.dag_builder import dag_shape_signature
from engine.planner.identity import build_target_identity, normalize_target_value
from engine.scheduler.dag import TaskDescriptor
from engine.scheduler.metrics import SchedulerMetrics
from engine.scheduler.policies import DefaultSchedulingPolicy
from engine.scheduler.resources import ResourceBudget
from engine.scheduler.scheduler import ScanScheduler
from engine.services.scan_submitter import ScanSubmitter


class _StubScheduler:
    def __init__(self):
        self.registered = []

    def register_scan_dag(self, scan_id, dag):
        self.registered.append((scan_id, dag))


def test_target_identity_normalization():
    assert normalize_target_value("url", "https://Example.com/") == "example.com"
    assert normalize_target_value("url", "http://example.com:80") == "example.com"
    assert normalize_target_value("ip", "192.168.001.001") == "192.168.1.1"
    assert normalize_target_value("repo", "github.com/org/repo.git") == "github.com/org/repo"

    identity = build_target_identity("url", "https://Example.com/")
    assert identity["normalized"] == "example.com"
    assert len(identity["target_id"]) == 64


def test_submitter_persists_target_identity_and_dag_signature(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr("engine.services.scan_submitter.settings.SCAN_RESULTS_DIR", str(tmp_path / "results"))
    submitter = ScanSubmitter(_StubScheduler())

    scan_id = "scan-phase-1-6-1"
    submitter.submit_scan(
        {
            "scan_id": scan_id,
            "profile": "DEVELOPER",
            "targets": {"source_code_path": str(src)},
            "enable_ai": True,
        }
    )

    meta = json.loads((tmp_path / "results" / scan_id / "meta.json").read_text(encoding="utf-8"))
    assert "target_identity" in meta
    assert "source_code_path" in meta["target_identity"]
    assert "dag_shape_signature" in meta
    assert len(meta["dag_shape_signature"]) == 64


def test_scheduler_emits_operational_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr("engine.scheduler.scheduler.settings.SCAN_RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr("engine.scheduler.scheduler.settings.SCHEDULER_STALL_THRESHOLD_SEC", 0)
    monkeypatch.setattr("engine.scheduler.scheduler.settings.SCHEDULER_TASK_TIMEOUT_SEC", 0)
    monkeypatch.setattr("engine.scheduler.scheduler.settings.SCHEDULER_STARVATION_THRESHOLD_SEC", 0)

    scheduler = ScanScheduler(
        resource_budget=ResourceBudget(max_tokens=10),
        policy=DefaultSchedulingPolicy(),
        max_concurrent_tasks=5,
        max_heavy_tasks=2,
        metrics=SchedulerMetrics(),
    )

    scan_id = "scan-phase-1-6-2"
    task = TaskDescriptor(
        task_id=f"{scan_id}:SAST",
        scan_id=scan_id,
        task_type="SAST",
        cost_units=3,
        dependencies=frozenset(),
        retries_allowed=0,
    )
    scheduler.register_scan_dag(scan_id, [task])
    scheduler.schedule_once(lambda _tid, _td: None)

    base = tmp_path / scan_id
    events = base / "scheduler_events.jsonl"
    alerts = base / "alerts.jsonl"
    timeline = base / "timeline.json"
    assert events.exists()
    assert alerts.exists()
    assert timeline.exists()

    payload = json.loads(timeline.read_text(encoding="utf-8"))
    assert task.task_id in payload["tasks"]
    assert payload["tasks"][task.task_id]["admitted_at"] is not None
    assert payload["tasks"][task.task_id]["running_at"] is not None

    metrics = scheduler.get_metrics_snapshot()
    assert "ready_queue_size" in metrics
    assert "in_flight_count" in metrics
    assert "tokens_in_use_per_tier" in metrics


def test_dag_shape_signature_is_deterministic():
    scan_id_a = "a"
    scan_id_b = "b"
    dag_a = [
        TaskDescriptor(
            task_id=f"{scan_id_a}:SAST",
            scan_id=scan_id_a,
            task_type="SAST",
            cost_units=3,
            dependencies=frozenset(),
            retries_allowed=2,
        ),
        TaskDescriptor(
            task_id=f"{scan_id_a}:REPORT",
            scan_id=scan_id_a,
            task_type="REPORT",
            cost_units=2,
            dependencies=frozenset({f"{scan_id_a}:SAST"}),
            retries_allowed=0,
        ),
    ]
    dag_b = [
        TaskDescriptor(
            task_id=f"{scan_id_b}:SAST",
            scan_id=scan_id_b,
            task_type="SAST",
            cost_units=3,
            dependencies=frozenset(),
            retries_allowed=2,
        ),
        TaskDescriptor(
            task_id=f"{scan_id_b}:REPORT",
            scan_id=scan_id_b,
            task_type="REPORT",
            cost_units=2,
            dependencies=frozenset({f"{scan_id_b}:SAST"}),
            retries_allowed=0,
        ),
    ]
    assert dag_shape_signature(dag_a) == dag_shape_signature(dag_b)
