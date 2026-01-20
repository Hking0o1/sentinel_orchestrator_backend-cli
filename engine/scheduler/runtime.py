"""
Scheduler runtime lifecycle management.

This module owns the singleton ScanScheduler instance.
"""

from typing import Optional

from .scheduler import ScanScheduler
from .resources import ResourceBudget
from .metrics import SchedulerMetrics
from .policies import DefaultSchedulingPolicy
from config.settings import settings

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
