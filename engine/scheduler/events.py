from __future__ import annotations
import logging
from typing import Dict, Any
from engine.scheduler.types import SchedulerEventType

logger = logging.getLogger("sentinel.scheduler")


def emit_scheduler_event(
    event_type: SchedulerEventType,
    *,
    task_id: str,
    scan_id: str,
    details: Dict[str, Any] | None = None,
) -> None:
    """
    Centralized scheduler event emission.

    Today: structured logging
    Tomorrow: metrics, DB, websocket, tracing
    """

    payload = {
        "event": event_type.value,
        "task_id": task_id,
        "scan_id": scan_id,
        "details": details or {},
    }

    logger.info("SCHEDULER_EVENT %s", payload)


# ---- Convenience wrappers (keep scheduler code clean) ----

def notify_task_admitted(task_id: str, scan_id: str) -> None:
    emit_scheduler_event(
        SchedulerEventType.TASK_ADMITTED,
        task_id=task_id,
        scan_id=scan_id,
    )


def notify_task_dispatched(task_id: str, scan_id: str) -> None:
    emit_scheduler_event(
        SchedulerEventType.TASK_DISPATCHED,
        task_id=task_id,
        scan_id=scan_id,
    )


def notify_task_completed(task_id: str, scan_id: str) -> None:
    emit_scheduler_event(
        SchedulerEventType.TASK_COMPLETED,
        task_id=task_id,
        scan_id=scan_id,
    )


def notify_task_failed(task_id: str, scan_id: str, error: str) -> None:
    emit_scheduler_event(
        SchedulerEventType.TASK_FAILED,
        task_id=task_id,
        scan_id=scan_id,
        details={"error": error},
    )


def notify_task_blocked(task_id: str, scan_id: str, reason: str) -> None:
    emit_scheduler_event(
        SchedulerEventType.TASK_BLOCKED,
        task_id=task_id,
        scan_id=scan_id,
        details={"reason": reason},
    )
