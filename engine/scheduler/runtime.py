# engine/scheduler/runtime.py

"""
Scheduler runtime lifecycle management.

This module owns the singleton ScanScheduler instance.
"""

from typing import Optional

from engine.scheduler.scheduler import ScanScheduler
from engine.scheduler.resources import ResourceBudget
from engine.scheduler.metrics import SchedulerMetrics
from engine.scheduler.policies import DefaultSchedulingPolicy


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

    _SCHEDULER = ScanScheduler(
        resource_budget=budget,
        scheduling_policy=policy,
        metrics=metrics,
        max_concurrent_tasks=max_concurrent_tasks,
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
