from __future__ import annotations
from enum import Enum
from dataclasses import dataclass
from typing import Optional

class TaskState(str, Enum):
    """
    Lifecycle state of a scheduler task.
    """
    PENDING = "PENDING"        # Known, but not ready
    READY = "READY"            # Eligible for scheduling
    RUNNING = "RUNNING"        # Dispatched to worker
    COMPLETED = "COMPLETED"    # Finished successfully
    FAILED = "FAILED"          # Failed and non-retriable
    BLOCKED = "BLOCKED"        # Permanently blocked by dependency
    RETRY_WAIT = "RETRY_WAIT"  # Waiting before retry


class TaskCostTier(str, Enum):
    """
    Abstract cost classification.
    Used by scheduler policies.
    """
    LIGHT = "LIGHT"
    MEDIUM = "MEDIUM"
    HEAVY = "HEAVY"
    POST_PROCESS = "POST_PROCESS"


class SchedulerEventType(str, Enum):
    """
    Events emitted by the scheduler.
    Used for logging, debugging, and observability.
    """
    TASK_ADMITTED = "TASK_ADMITTED"
    TASK_BLOCKED = "TASK_BLOCKED"
    TASK_READY = "TASK_READY"
    TASK_DISPATCHED = "TASK_DISPATCHED"
    TASK_COMPLETED = "TASK_COMPLETED"
    TASK_FAILED = "TASK_FAILED"
    TOKEN_ACQUIRED = "TOKEN_ACQUIRED"
    TOKEN_RELEASED = "TOKEN_RELEASED"


@dataclass(frozen=True)
class TaskIdentity:
    """
    Immutable identity of a task.
    Must NEVER contain runtime state.
    """
    task_id: str
    scan_id: str
    task_type: str
    cost_tier: TaskCostTier
    max_retries: int


@dataclass
class TaskRuntimeState:
    """
    Mutable runtime state owned by the scheduler ONLY.
    """
    state: TaskState = TaskState.PENDING
    retry_count: int = 0
    last_error: Optional[str] = None
