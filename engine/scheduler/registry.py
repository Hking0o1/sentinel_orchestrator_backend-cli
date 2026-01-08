class InFlightRegistry:
    """
    Tracks currently running tasks and their resource usage.

    Single source of truth for:
    - what is running
    - how many resources are consumed
    """

    __slots__ = ("_tasks",)

    def __init__(self):
        self._tasks: dict[str, int] = {}  # task_id -> cost_units

    def add(self, task_id: str, cost_units: int) -> None:
        if task_id in self._tasks:
            raise RuntimeError(f"Task already in flight: {task_id}")
        self._tasks[task_id] = cost_units

    def remove(self, task_id: str) -> int:
        if task_id not in self._tasks:
            raise RuntimeError(f"Task not found in flight: {task_id}")
        return self._tasks.pop(task_id)

    def __contains__(self, task_id: str) -> bool:
        return task_id in self._tasks

    def __len__(self) -> int:
        return len(self._tasks)

    def total_consumed_units(self) -> int:
        return sum(self._tasks.values())
