from __future__ import annotations
import logging
from typing import Dict, Any
from engine.scheduler.types import SchedulerEventType
from engine.scheduler.event_bus import publish_event
from engine.scheduler.runtime import get_scheduler

logger = logging.getLogger("sentinel.scheduler.events")


def emit_scheduler_event(*, event: str, task_id: str, scan_id: str, details: dict):
    logger.info(
        "SCHEDULER_EVENT %s",
        {
            "event": event,
            "task_id": task_id,
            "scan_id": scan_id,
            "details": details,
        },
    )

    scheduler = get_scheduler()

    if event == "TASK_COMPLETED":
        scheduler.on_task_complete(
            task_id=task_id,
            success=True,
            output_paths=details.get("output_paths"),
        )

    elif event == "TASK_FAILED":
        scheduler.on_task_complete(
            task_id=task_id,
            success=False,
            error=details.get("error"),
        )


# -----------------------------
# Convenience wrappers
# -----------------------------

def task_admitted(task_id: str, scan_id: str) -> None:
    emit_scheduler_event(
        SchedulerEventType.TASK_ADMITTED,
        task_id=task_id,
        scan_id=scan_id,
    )


def task_dispatched(task_id: str, scan_id: str) -> None:
    emit_scheduler_event(
        SchedulerEventType.TASK_DISPATCHED,
        task_id=task_id,
        scan_id=scan_id,
    )


def task_completed(
    task_id: str,
    scan_id: str,
    *,
    output_paths: list[str] | None = None,
) -> None:
    emit_scheduler_event(
        SchedulerEventType.TASK_COMPLETED,
        task_id=task_id,
        scan_id=scan_id,
        details={"output_paths": output_paths or []},
    )


def task_failed(
    task_id: str,
    scan_id: str,
    *,
    error: str,
) -> None:
    emit_scheduler_event(
        SchedulerEventType.TASK_FAILED,
        task_id=task_id,
        scan_id=scan_id,
        details={"error": error},
    )
