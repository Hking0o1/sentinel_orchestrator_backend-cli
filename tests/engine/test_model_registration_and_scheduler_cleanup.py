from app.db.base import Base
from app.db import models as _db_models  # noqa: F401
from app.models import scan as _scan_models  # noqa: F401
from engine.scheduler.dag import TaskDescriptor
from engine.scheduler.metrics import SchedulerMetrics
from engine.scheduler.policies import DefaultSchedulingPolicy
from engine.scheduler.resources import ResourceBudget
from engine.scheduler.scheduler import ScanScheduler


def test_users_and_scans_tables_are_registered():
    assert "users" in Base.metadata.tables
    assert "scans" in Base.metadata.tables


def test_scheduler_cleans_runtime_after_scan_completion():
    scheduler = ScanScheduler(
        resource_budget=ResourceBudget(max_tokens=10),
        policy=DefaultSchedulingPolicy(),
        max_concurrent_tasks=5,
        max_heavy_tasks=2,
        metrics=SchedulerMetrics(),
    )

    scan_id = "scan-cleanup-1"
    a = TaskDescriptor(
        task_id=f"{scan_id}:A",
        scan_id=scan_id,
        task_type="SAST",
        cost_units=1,
        dependencies=frozenset(),
        retries_allowed=0,
    )
    b = TaskDescriptor(
        task_id=f"{scan_id}:B",
        scan_id=scan_id,
        task_type="REPORT",
        cost_units=1,
        dependencies=frozenset({a.task_id}),
        retries_allowed=0,
    )
    scheduler.register_scan_dag(scan_id, [a, b])

    scheduler.schedule_once(lambda _tid, _td: None)
    scheduler.on_task_complete(task_id=a.task_id, success=True, output_paths=[])
    scheduler.schedule_once(lambda _tid, _td: None)
    scheduler.on_task_complete(task_id=b.task_id, success=True, output_paths=[])

    assert a.task_id not in scheduler.runtime
    assert b.task_id not in scheduler.runtime
    assert a.task_id not in scheduler.tasks
    assert b.task_id not in scheduler.tasks
    assert scan_id not in scheduler._dags
    assert len(scheduler.queue._heap) == 0
