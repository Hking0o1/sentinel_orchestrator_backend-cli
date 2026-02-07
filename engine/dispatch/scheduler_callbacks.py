from celery import shared_task
from engine.scheduler.runtime import get_scheduler
import logging

logger = logging.getLogger(__name__)

@shared_task(
    name="scheduler.task_completed",
    queue="backend",   # 🔥 CRITICAL
)
def scheduler_task_completed(task_id, success, output_paths=None, error=None):
    scheduler = get_scheduler()
    scheduler.on_task_complete(
        task_id=task_id,
        success=success,
        output_paths=output_paths,
        error=error,
    )
