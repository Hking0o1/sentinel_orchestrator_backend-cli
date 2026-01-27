import heapq
import time
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)
class SchedulerQueue:
    """
    Priority queue for schedulable tasks.

    - Allows stale entries (lazy invalidation)
    - Scheduler validates readiness on pop
    - Never mutates existing heap entries
    """

    def __init__(self):
        self._heap: list[Tuple[int, float, str]] = []
        
    def __len__(self) -> int:
        return len(self._heap)
    
    def push(self, priority: int, task_id: str) -> None:
        """
        Push a task into the queue.

        priority: lower value = higher priority
        timestamp: ensures FIFO ordering for equal priority
        """
        logger.error("QUEUE PUSH | priority=%s | task_id=%s", priority, task_id)

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
        
        logger.error("QUEUE POP | task_id=%s", task_id)
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

