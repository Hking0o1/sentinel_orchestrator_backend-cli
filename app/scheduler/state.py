from typing import List, Optional
from .types import TaskState


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
    )

    def __init__(self, task_id: str):
        self.task_id: str = task_id
        self.state: TaskState = TaskState.PENDING
        self.retry_count: int = 0
        self.output_paths: List[str] = []
        self.last_error: Optional[str] = None
        
    def test_runtime_state_is_not_persistent():
        state = TaskRuntimeState("t1")
        assert getattr(state, "__persistent__", True) is False
