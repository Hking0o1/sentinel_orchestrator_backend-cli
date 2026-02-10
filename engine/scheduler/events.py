from __future__ import annotations
import logging
from engine.scheduler.types import SchedulerEventType
from .scheduler import ScanScheduler
from .event_bus import drain_events, publish_event

logger = logging.getLogger(__name__)

def emit_scheduler_event(*, event: str, task_id: str, scan_id: str, details: dict | None = None):
    payload = {
        "event": event,
        "task_id": task_id,
        "scan_id": scan_id,
        "details": details or {},
    }
    publish_event(payload)

    logger.info(
        "SCHEDULER_EVENT_EMIT | event=%s | task_id=%s | scan_id=%s",
        event,
        task_id,
        scan_id,
    )

def drain_scheduler_events(scheduler: ScanScheduler) -> int:
    events = drain_events()
    applied = 0

    for event in events:
        logger.error(
            "APPLY EVENT | %s | %s",
            event["event"],
            event["task_id"],
        )

        if event["event"] == "TASK_COMPLETED":
            scheduler.on_task_complete(
                task_id=event["task_id"],
                success=True,
                output_paths=event.get("details", {}).get("output_paths"),
            )
            applied += 1

        elif event["event"] == "TASK_FAILED":
            scheduler.on_task_complete(
                task_id=event["task_id"],
                success=False,
                error=event.get("details", {}).get("error"),
            )
            applied += 1

    return applied



def task_admitted(task_id: str, scan_id: str) -> None:
    emit_scheduler_event(
        event=SchedulerEventType.TASK_ADMITTED.value,
        task_id=task_id,
        scan_id=scan_id,
    )


def task_dispatched(task_id: str, scan_id: str) -> None:
    emit_scheduler_event(
        event=SchedulerEventType.TASK_DISPATCHED.value,
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
        event=SchedulerEventType.TASK_COMPLETED.value,
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
        event=SchedulerEventType.TASK_FAILED.value,
        task_id=task_id,
        scan_id=scan_id,
        details={"error": error},
    )
