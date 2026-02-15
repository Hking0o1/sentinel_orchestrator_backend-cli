from typing import List, Optional
from .types import TaskState
from datetime import datetime, timezone


class NonPersistent:
    """
    Marker mixin.
    Any subclass must NEVER be persisted or serialized.
    """
    __persistent__ = False


class TaskRuntimeState(NonPersistent):
    """
    Scheduler-owned runtime state.

    Represents HOW a task is progressing.
    Exists only in memory.
    Safe to discard and rebuild.
    """

    __slots__ = (
        "task_id",
        "state",
        "retry_count",
        "output_paths",
        "last_error",
        "admitted_at",
        "ready_at",
        "dispatched_at",
        "running_at",
        "completed_at",
    )

    def __init__(self, task_id: str):
        self.task_id: str = task_id
        self.state: TaskState = TaskState.PENDING
        self.retry_count: int = 0
        self.output_paths: List[str] = []
        self.last_error: Optional[str] = None
        self.admitted_at: Optional[str] = datetime.now(timezone.utc).isoformat()
        self.ready_at: Optional[str] = None
        self.dispatched_at: Optional[str] = None
        self.running_at: Optional[str] = None
        self.completed_at: Optional[str] = None
        
    def test_runtime_state_is_not_persistent():
        state = TaskRuntimeState("t1")
        assert getattr(state, "__persistent__", True) is False
