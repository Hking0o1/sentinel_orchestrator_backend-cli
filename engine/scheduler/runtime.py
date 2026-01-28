"""
Scheduler runtime lifecycle management.

This module owns the singleton ScanScheduler instance.
"""

from typing import Optional
import time
import logging
from .scheduler import ScanScheduler
from .resources import ResourceBudget
from .metrics import SchedulerMetrics
from .policies import DefaultSchedulingPolicy
from config.settings import settings
from engine.scheduler.event_bus import drain_events
from engine.scheduler.types import SchedulerEventType

logger = logging.getLogger(__name__)

_scheduler_thread = None

# Internal singleton
_SCHEDULER: Optional[ScanScheduler] = None


def init_scheduler(
    *,
    max_tokens: int,
    max_concurrent_tasks: int,
) -> ScanScheduler:
    """
    Initialize the global scheduler instance.

    Must be called exactly once at application startup.
    """

    global _SCHEDULER

    if _SCHEDULER is not None:
        raise RuntimeError("Scheduler already initialized")

    budget = ResourceBudget(max_tokens=max_tokens)
    metrics = SchedulerMetrics()
    policy = DefaultSchedulingPolicy()
    max_heavy_tasks = settings.SCHEDULER_MAX_HEAVY_TASKS
    _SCHEDULER = ScanScheduler(
        resource_budget=budget,
        policy=policy,
        metrics=metrics,
        max_concurrent_tasks=max_concurrent_tasks,
        max_heavy_tasks= max_heavy_tasks,
)
    

    return _SCHEDULER



def get_scheduler() -> ScanScheduler:
    """
    Retrieve the initialized scheduler instance.

    Raises:
        RuntimeError if scheduler was not initialized.
    """
    if _SCHEDULER is None:
        raise RuntimeError(
            "Scheduler not initialized. "
            "Call init_scheduler() at application startup."
        )

    return _SCHEDULER


def start_scheduler_loop(dispatch_fn):
    """
    Starts the Sentinel scheduler loop.
    This is the ONLY place where looping happens.
    """

    scheduler = get_scheduler()

    logger.info("Sentinel scheduler loop started")

    while True:
        try:
            events = drain_events()
            for event in events:
                event_type = SchedulerEventType(event["event"])
                task_id = event["task_id"]
                details = event.get("details", {})

                if event_type == SchedulerEventType.TASK_COMPLETED:
                    scheduler.on_task_complete(
                        task_id=task_id,
                        success=True,
                        output_paths=details.get("output_paths"),
                    )

                elif event_type == SchedulerEventType.TASK_FAILED:
                    scheduler.on_task_complete(
                        task_id=task_id,
                        success=False,
                        error=details.get("error"),
                    )

            scheduler.schedule_once(dispatch_fn)

        except Exception:
            logger.exception("Scheduler loop error")

        time.sleep(0.2)
