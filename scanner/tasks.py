from celery import shared_task
from typing import Dict, Any

from scanner.tools.registry import get_tool
from scanner.result_adapter import adapt_tool_result

from engine.dispatch.callbacks import (
    notify_task_success,
    notify_task_failure,
)


@shared_task(bind=True, autoretry_for=())
def run_tool_task(
    self,
    task_id: str,
    scan_id: str,
    task_type: str,
    target: str,
    payload: Dict[str, Any] | None = None,
):
    """
    Commit 5: SINGLE UNIT OF EXECUTION

    - Executes exactly one tool
    - No orchestration
    - No DB
    - No retries
    - No AI
    - No reports
    """

    try:
        runner = get_tool(task_type)

        raw_result = runner(
            task_id=task_id,
            scan_id=scan_id,
            target=target,
            **(payload or {}),
        )

        # Normalize tool output
        tool_result = adapt_tool_result(raw_result)

        # Notify scheduler (authoritative)
        notify_task_success(
            task_id=task_id,
            output=tool_result,
        )

    except Exception as exc:
        notify_task_failure(
            task_id=task_id,
            error=str(exc),
        )
