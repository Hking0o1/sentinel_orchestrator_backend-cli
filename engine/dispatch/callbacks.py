import logging
from typing import Optional, Dict, Any
from engine.scheduler.events import emit_scheduler_event


logger = logging.getLogger("sentinel.dispatch.callbacks")



def notify_task_success(
    *,
    task_id: str,
    scan_id: Optional[str] = None,
    output_paths: Optional[list[str]] = None,
    output_summary: Optional[Dict[str, Any]] = None,
    findings_path: Optional[str] = None,
    artifacts: Optional[list[str]] = None,
) -> None:
    """
    Worker-safe success callback.
    Emits event ONLY.
    """

    resolved_scan_id = scan_id or task_id.split(":", 1)[0]
    resolved_output_paths = list(output_paths or [])
    if findings_path:
        resolved_output_paths.append(findings_path)
    if artifacts:
        resolved_output_paths.extend(artifacts)

    logger.info(
        "TASK SUCCESS | task_id=%s | scan_id=%s | summary=%s",
        task_id,
        resolved_scan_id,
        output_summary or {"artifact_paths": resolved_output_paths},
    )

    emit_scheduler_event(
        event="TASK_COMPLETED",
        task_id=task_id,
        scan_id=resolved_scan_id,
        details={
            "output_paths": resolved_output_paths,
        },
    )


def notify_task_failure(
    *,
    task_id: str,
    scan_id: Optional[str] = None,
    error: str,
) -> None:
    """
    Worker-safe failure callback.
    Emits event ONLY.
    """

    resolved_scan_id = scan_id or task_id.split(":", 1)[0]

    logger.error(
        "TASK FAILURE | task_id=%s | scan_id=%s | error=%s",
        task_id,
        resolved_scan_id,
        error,
    )

    emit_scheduler_event(
        event="TASK_FAILED",
        task_id=task_id,
        scan_id=resolved_scan_id,
        details={
            "error": error,
        },
    )
