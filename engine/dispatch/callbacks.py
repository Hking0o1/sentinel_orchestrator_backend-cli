import logging
from typing import Optional, Dict, Any
from engine.scheduler.events import emit_scheduler_event


logger = logging.getLogger("sentinel.dispatch.callbacks")



def notify_task_success(
    *,
    task_id: str,
    scan_id: str,
    output_paths: Dict[str, Any],
    artifacts: Optional[list[str]] = None,
) -> None:
    """
    Worker-safe success callback.
    Emits event ONLY.
    """

    logger.info(
        "TASK SUCCESS | task_id=%s | scan_id=%s | summary=%s",
        task_id,
        scan_id,
        output_paths,
    )

    emit_scheduler_event(
        event_type="TASK_COMPLETED",
        task_id=task_id,
        scan_id=scan_id,
        details={
            "output_paths": output_paths,
        },
    )


def notify_task_failure(
    *,
    task_id: str,
    scan_id: str,
    error: str,
) -> None:
    """
    Worker-safe failure callback.
    Emits event ONLY.
    """

    logger.error(
        "TASK FAILURE | task_id=%s | scan_id=%s | error=%s",
        task_id,
        scan_id,
        error,
    )

    emit_scheduler_event(
        event_type="TASK_FAILED",
        task_id=task_id,
        scan_id=scan_id,
        details={
            "error": error,
        },
    )