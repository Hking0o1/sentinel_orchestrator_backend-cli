from enum import Enum


class TaskState(str, Enum):
    """
    Finite-state machine for task execution.
    Runtime-only. Never persisted. Never exposed.
    """

    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
