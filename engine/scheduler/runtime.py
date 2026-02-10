"""
Scheduler runtime lifecycle management.

This module owns the singleton ScanScheduler instance.
"""

from typing import Optional
import time
import logging
import atexit
import os
from .scheduler import ScanScheduler
from .resources import ResourceBudget
from .metrics import SchedulerMetrics
from .policies import DefaultSchedulingPolicy
from config.settings import settings
from engine.scheduler.event_bus import drain_events
from engine.scheduler.types import SchedulerEventType

logger = logging.getLogger(__name__)

_scheduler_thread = None
_scheduler_lock_fd = None

# Internal singleton
_SCHEDULER: Optional[ScanScheduler] = None


def _release_scheduler_process_lock() -> None:
    global _scheduler_lock_fd
    if _scheduler_lock_fd is None:
        return
    try:
        _scheduler_lock_fd.close()
    except Exception:
        logger.exception("Failed to close scheduler process lock file")
    finally:
        _scheduler_lock_fd = None


def acquire_scheduler_process_lock(
    lock_path: str = "/tmp/sentinel_scheduler.lock",
) -> bool:
    """
    Acquire a process-wide lock to ensure only one process owns scheduler startup.

    Returns:
        True if this process owns the scheduler lock, False otherwise.
    """
    global _scheduler_lock_fd

    if _scheduler_lock_fd is not None:
        return True

    lock_dir = os.path.dirname(lock_path)
    if lock_dir:
        os.makedirs(lock_dir, exist_ok=True)

    lock_fd = open(lock_path, "a+")
    try:
        import fcntl  # Unix-only; backend container runs Linux.

        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_fd.close()
        return False
    except Exception:
        lock_fd.close()
        raise

    _scheduler_lock_fd = lock_fd
    atexit.register(_release_scheduler_process_lock)
    return True


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
