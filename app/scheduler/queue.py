import heapq
import time
from typing import Optional, Tuple


class SchedulerQueue:
    """
    Priority queue for schedulable tasks.

    - Allows stale entries (lazy invalidation)
    - Scheduler validates readiness on pop
    - Never mutates existing heap entries
    """

    def __init__(self):
        self._heap: list[Tuple[int, float, str]] = []

    def push(self, priority: int, task_id: str) -> None:
        """
        Push a task into the queue.

        priority: lower value = higher priority
        timestamp: ensures FIFO ordering for equal priority
        """
        heapq.heappush(self._heap, (priority, time.monotonic(), task_id))

    def pop(self) -> Optional[str]:
        """
        Pop next task_id from queue.

        NOTE:
        Returned task_id may be stale.
        Caller MUST validate runtime state.
        """
        if not self._heap:
            return None

        _, _, task_id = heapq.heappop(self._heap)
        return task_id

    def __len__(self) -> int:
        return len(self._heap)
    
    #test
    def test_queue_fifo_priority():
        q = SchedulerQueue()
        q.push(1, "A")
        q.push(1, "B")
        assert q.pop() == "A"
        assert q.pop() == "B"

