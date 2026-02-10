import logging

from celery import shared_task

from engine.scheduler.event_bus import publish_event

logger = logging.getLogger(__name__)


@shared_task(name="scheduler.task_completed")
def scheduler_task_completed(task_id, success, output_paths=None, error=None):
    event = "TASK_COMPLETED" if success else "TASK_FAILED"
    details = {"output_paths": output_paths or []} if success else {"error": error}
    publish_event(
        {
            "event": event,
            "task_id": task_id,
            "scan_id": task_id.split(":", 1)[0],
            "details": details,
        }
    )
    logger.info(
        "Scheduler completion callback published | task_id=%s | success=%s",
        task_id,
        success,
    )
