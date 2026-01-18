from celery import Celery
from datetime import timedelta

from config.settings import settings

celery_app = Celery(
    "scanner",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["scanner.tasks"],
)

celery_app.conf.update(
    task_track_started=True,
    broker_connection_retry_on_startup=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    enable_utc=True,
    timezone="UTC",
)

# Beat schedules (keep minimal for now)
celery_app.conf.beat_schedule = {
    "dispatch-scheduled-scans-every-30-mins": {
        "task": "scanner.tasks.dispatch_scheduled_scans",
        "schedule": timedelta(minutes=30),
    }
}
