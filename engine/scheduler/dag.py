from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True, slots=True)
class TaskDescriptor:
    """
    Immutable execution descriptor.

    Describes WHAT the task is.
    Does NOT describe HOW it runs.
    Must NEVER be mutated.
    Must NEVER be persisted.
    """

    task_id: str
    scan_id: str
    task_type: str
    cost_units: int
    dependencies: FrozenSet[str]
    retries_allowed: int
