from engine.scheduler.scheduler import ScanScheduler

import logging

_scheduler: ScanScheduler | None = None
logger = logging.getLogger(__name__)

def init_scheduler(scheduler: ScanScheduler):
    global _scheduler
    _scheduler = scheduler


def notify_task_success(task_id: str, artifacts: list[str] | None = None):
    if _scheduler is None:
        return

    _scheduler.on_task_complete(
        task_id=task_id,
        success=True,
        output_paths=artifacts or [],
    )

    


def notify_task_failure(task_id: str, error: str):
    if _scheduler is None:
        return
    assert _scheduler is not None
    logger.error(
        "CALLBACK FAILURE | task_id=%s | error=%s",
        task_id,
        error,
    )
    _scheduler.on_task_complete(
        task_id=task_id,
        success=False,
        error=error,
    )
