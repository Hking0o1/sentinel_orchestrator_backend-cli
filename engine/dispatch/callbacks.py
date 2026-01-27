from engine.scheduler.scheduler import ScanScheduler
from engine.scheduler.runtime import get_scheduler
import logging
import os

logger = logging.getLogger(__name__)

def init_scheduler(scheduler: ScanScheduler):
    global _scheduler
    _scheduler = scheduler


def notify_task_success(task_id: str, output_paths: list[str] | None = None):
        scheduler = get_scheduler()
        scheduler.on_task_complete(
            task_id=task_id,
            success=True,
            output_paths=output_paths,
        )
        logger.error(
            "NOTIFY SUCCESS | task_id=%s | pid=%s",
            task_id,
            os.getpid()
            )
                

def notify_task_failure(task_id: str, error: str):
        scheduler = get_scheduler()
        logger.error(
            "CALLBACK FAILURE | task_id=%s | error=%s",
            task_id,
            error,
        )
        scheduler.on_task_complete(
            task_id=task_id,
            success=False,
            error=error,
        )
    