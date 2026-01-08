from typing import Dict, Iterable, Callable, Optional

from .dag import TaskDescriptor
from .state import TaskRuntimeState
from .types import TaskState
from .queue import SchedulerQueue
from .resources import ResourceBudget
from .registry import InFlightRegistry
from .metrics import SchedulerMetrics

class ScanScheduler:
    """
    Authoritative scheduler for Sentinel.

    Owns:
    - task FSM
    - DAG dependency resolution
    - resource budgeting
    - retry decisions
    - scheduling order

    Does NOT:
    - execute tasks
    - talk to DB
    - generate reports
    """

    def __init__(self, total_resource_units: int):
        # core primitives
        self.queue = SchedulerQueue()
        self.resources = ResourceBudget(total_resource_units)
        self.in_flight = InFlightRegistry()
        self.metrics = SchedulerMetrics()

        # execution graph
        self.tasks: Dict[str, TaskDescriptor] = {}
        self.runtime: Dict[str, TaskRuntimeState] = {}

        # DAG edges
        self.parents: Dict[str, set[str]] = {}
        self.children: Dict[str, set[str]] = {}
        
    def submit_tasks(self, descriptors: Iterable[TaskDescriptor]) -> None:
        """
        Admit a new scan's tasks into the scheduler.

        Initializes runtime state and DAG edges.
        Does NOT schedule execution.
        """

        for td in descriptors:
            if td.task_id in self.tasks:
                raise RuntimeError(f"Duplicate task_id: {td.task_id}")

            self.tasks[td.task_id] = td
            self.runtime[td.task_id] = TaskRuntimeState(td.task_id)

            self.parents[td.task_id] = set(td.dependencies)
            for parent in td.dependencies:
                self.children.setdefault(parent, set()).add(td.task_id)

        self.metrics.inc("tasks_submitted_total", len(self.tasks))
        
    def initialize_ready_tasks(self) -> None:
        """
        Mark root DAG nodes READY.
        """
        for task_id, parents in self.parents.items():
            if not parents:
                self._transition_to_ready(task_id)
        
    def _transition_to_ready(self, task_id: str) -> None:
        rt = self.runtime[task_id]

        if rt.state != TaskState.PENDING:
            return

        rt.state = TaskState.READY
        self.queue.push(priority=0, task_id=task_id)

        self.metrics.inc("tasks_ready_total")
        self.metrics.set_gauge("ready_queue_size", len(self.queue))
        
    def schedule_once(
        self,
        dispatch_fn: Callable[[str, TaskDescriptor], None]
    ) -> int:
        """
        Attempt to schedule READY tasks.

        dispatch_fn:
            called with (task_id, TaskDescriptor)
            responsible for execution (Celery later)
        """

        scheduled = 0

        while True:
            task_id = self.queue.pop()
            if task_id is None:
                break

            rt = self.runtime[task_id]
            td = self.tasks[task_id]

            # lazy invalidation
            if rt.state != TaskState.READY:
                continue

            if not self.resources.can_allocate(td.cost_units):
                break  # backpressure

            # FSM transition
            rt.state = TaskState.RUNNING
            self.resources.allocate(td.cost_units)
            self.in_flight.add(task_id, td.cost_units)

            self.metrics.inc("tasks_scheduled_total")
            self.metrics.set_gauge("in_flight_tasks", len(self.in_flight))

            dispatch_fn(task_id, td)
            scheduled += 1

        return scheduled
    
    def on_task_complete(
        self,
        task_id: str,
        success: bool,
        output_paths: Optional[list[str]] = None,
        error: Optional[str] = None,
    ) -> None:
        """
        Worker callback.
        The ONLY way execution influences scheduler state.
        """

        rt = self.runtime[task_id]
        td = self.tasks[task_id]

        # resource release
        units = self.in_flight.remove(task_id)
        self.resources.release(units)

        if success:
            self._handle_success(task_id, output_paths)
        else:
            self._handle_failure(task_id, error)
            
    def _handle_success(self, task_id: str, output_paths: Optional[list[str]]) -> None:
        rt = self.runtime[task_id]
        rt.state = TaskState.DONE
        rt.output_paths = output_paths or []

        self.metrics.inc("tasks_completed_total")

        # unlock children
        for child in self.children.get(task_id, []):
            self._evaluate_readiness(child)
            
    def _handle_failure(self, task_id: str, error: Optional[str]) -> None:
        rt = self.runtime[task_id]
        td = self.tasks[task_id]

        rt.retry_count += 1
        rt.last_error = error
        self.metrics.inc("tasks_failed_total")

        if rt.retry_count <= td.retries_allowed:
            rt.state = TaskState.READY
            self.queue.push(priority=rt.retry_count, task_id=task_id)
            self.metrics.inc("tasks_retried_total")
        else:
            rt.state = TaskState.FAILED
            self.metrics.inc("tasks_terminal_failed_total")
            self._block_descendants(task_id)
            
    def _evaluate_readiness(self, task_id: str) -> None:
        rt = self.runtime[task_id]

        if rt.state != TaskState.PENDING:
            return

        for parent in self.parents[task_id]:
            if self.runtime[parent].state != TaskState.DONE:
                return

        self._transition_to_ready(task_id)
        
    def _block_descendants(self, failed_task_id: str) -> None:
        for child in self.children.get(failed_task_id, []):
            rt = self.runtime[child]
            if rt.state in (TaskState.PENDING, TaskState.READY):
                rt.state = TaskState.BLOCKED
                self.metrics.inc("tasks_blocked_total")
                self._block_descendants(child)
                
    #dummy test
    def test_retry_exhaustion_blocks_children():
        # DAG: A -> B
        # A fails permanently
        pass  # expected: B becomes BLOCKED






            
        

