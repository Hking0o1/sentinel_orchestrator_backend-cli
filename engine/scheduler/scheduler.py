from __future__ import annotations
import time
import json
import os 
import logging
from datetime import datetime
from typing import Dict, Iterable, Callable, Optional
from croniter import croniter
from .policies import DefaultSchedulingPolicy
from .dag import TaskDescriptor
from .state import TaskRuntimeState
from .types import TaskState
from .queue import SchedulerQueue
from .resources import ResourceBudget
from .registry import InFlightRegistry
from config.settings import settings

logger = logging.getLogger(__name__)

BASE_COST = {
    "LIGHT": 10,
    "MEDIUM": 20,
    "HEAVY": 40,
    "POST_PROCESS": 60,
}

MEMORY_WEIGHT = 3
RETRY_WEIGHT = 15

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

    def __init__(self, 
        *,
        resource_budget: ResourceBudget,
        policy: DefaultSchedulingPolicy,
        max_concurrent_tasks: int,
        max_heavy_tasks: int,
        metrics: Optional[object])-> None:
        
        # core primitives
        self._dags = {}
        self._dag_states = {}
        self.queue = SchedulerQueue()
        self.resources = ResourceBudget(settings.SCHEDULER_MAX_TOKENS)
        self.in_flight = InFlightRegistry()
        self.metrics = metrics

        # execution graph
        self.tasks: Dict[str, TaskDescriptor] = {}
        self.runtime: Dict[str, TaskRuntimeState] = {}

        # DAG edges
        self.parents: Dict[str, set[str]] = {}
        self.children: Dict[str, set[str]] = {}
        self._policy = policy

        # ---- Concurrency limits ----
        self._max_concurrent_tasks = max_concurrent_tasks
        self._max_heavy_tasks = max_heavy_tasks

        # ---- Internal scheduler state ----
        self._in_flight = InFlightRegistry()

        # task_id -> runtime state (scheduler-owned)
        self._task_state: Dict[str, TaskRuntimeState] = {}
        self._dependents: dict[str, set[str]] = {}
        logger.error(
            "SCHEDULER INIT | pid=%s",
            os.getpid(),
        )
    
    def _state_snapshot(self, prefix: str = ""):
        snapshot = {
            "ready_queue": list(self.queue._heap),
            "runtime": {
                tid: rt.state.name
                for tid, rt in self.runtime.items()
            },
            "inflight": dict(self.in_flight._tasks),
        }

        logger.error(
            "%s SCHEDULER SNAPSHOT:\n%s",
            prefix,
            json.dumps(snapshot, indent=2, default=str),
        )
    
    def register_scan_dag(self, scan_id: str, dag: list[TaskDescriptor]) -> None:
        self._dags[scan_id] = dag
        
        for task in dag:
            self._dependents.setdefault(task.task_id, set())
        logger.error(
            "REGISTER DAG | scan_id=%s | tasks=%s",
            scan_id,
            [t.task_id for t in dag],
        )
        
        for task in dag:
            task_id = task.task_id
            self.tasks[task_id] = task

            rt = TaskRuntimeState(task_id)

            # Build reverse dependency index
            for dep in task.dependencies:
                self._dependents.setdefault(dep, set()).add(task.task_id)
            logger.error(
                "TASK REGISTER | id=%s | deps=%s | cost=%s",
                task.task_id,
                list(task.dependencies),
                task.cost_units,
            )
            if not task.dependencies:
                rt.state = TaskState.READY
                priority = task.cost_units
                self.queue.push(priority, task_id)
            else:
                rt.state = TaskState.BLOCKED

            self.runtime[task_id] = rt
        self._state_snapshot("AFTER DAG REGISTER")

        logger.info(
            "Registered scan DAG | scan_id=%s | tasks=%d",
            scan_id,
            len(dag),
        )
        
        

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
    
    def _compute_priority(self, task_id: str) -> int:
        """
        Compute scheduling priority for a READY task.
        Lower value = higher priority.
        """

        td = self.tasks[task_id]
        rt = self.runtime[task_id]

        base = td.cost_units
        memory_penalty = td.cost_units * MEMORY_WEIGHT
        retry_penalty = rt.retry_count * RETRY_WEIGHT

        return base + memory_penalty + retry_penalty
       
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
        priority = self._compute_priority(task_id)
        self.queue.push(priority=priority, task_id=task_id)

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
        logger.error(
            "SCHEDULER TICK ENTER | ready=%d | inflight=%d",
            len(self.queue),
            len(self._in_flight),
        )

        self._state_snapshot("TICK START")
        scheduled = 0
        print(
            ">>> Scheduler tick | ready:",
            len(self.queue),
            "| inflight:",
            len(self._in_flight),
        )
        
        while True:
            task_id = self.queue.pop()
            if task_id is None:
                break

            rt = self.runtime[task_id]
            td = self.tasks[task_id]

            # lazy invalidation
            if rt.state != TaskState.READY:
                continue

            if not self.resources.can_acquire(td.cost_units):
                break  # backpressure

            # FSM transition
            rt.state = TaskState.RUNNING
            self.resources.acquire(td.cost_units)
            self.in_flight.add(task_id, td.cost_units)

            self.metrics.inc("tasks_scheduled_total")
            self.metrics.set_gauge("in_flight_tasks", len(self.in_flight))
            logger.error(
                "DISPATCH DECISION | task_id=%s | cost=%s",
                task_id,
                td.cost_units,
            )
            dispatch_fn(task_id, td)
            self._state_snapshot("AFTER DISPATCH")
            scheduled += 1
            if (
                not self.queue
                and not self.in_flight
                and all(
                    rt.state in {TaskState.COMPLETED, TaskState.FAILED}
                    for rt in self.runtime.values()
                )
            ):
                logger.info("SCAN COMPLETE")
            logger.info(
                "Task blocked | task_id=%s | cost=%s | reason=%s | inflight=%d | remaining_budget=%d",
                task_id,
                td.cost_units,
                "resource_limit",
                len(self._in_flight),
                self.resources.can_acquire,
            )


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
        logger.error(
            "SCHEDULER CALLBACK RECEIVED | task_id=%s | success=%s",
            task_id,
            success,
        )
        rt = self.runtime[task_id]
        td = self.tasks[task_id]

        # resource release
        units = self.in_flight.remove(task_id)
        self.resources.release(units)
        
        self._state_snapshot("AFTER RESOURCE RELEASE")

        if success:
            self._handle_success(task_id, output_paths)
        else:
            self._handle_failure(task_id, error)

            
    def evaluate_schedules(self, now: datetime):
        for schedule in self._schedules:
            if cron_matches(schedule.cron, now, schedule.last_run_at):
                self.enqueue_scan(schedule.scan_id)
                schedule.last_run_at = now   
                    
    def _handle_success(self, task_id: str, output_paths: list[str] | None):
        rt = self.runtime[task_id]
        rt.state = TaskState.COMPLETED

        if output_paths:
            rt.output_paths.extend(output_paths)

        logger.error(
            "HANDLE SUCCESS | task=%s | dependents=%s",
            task_id,
            list(self._dependents.get(task_id, [])),
        )

        for dependent_id in self._dependents.get(task_id, []):
            dep_td = self.tasks[dependent_id]
            dep_rt = self.runtime[dependent_id]

            logger.error(
                "CHECK DEP | parent=%s -> child=%s | child_state=%s | deps=%s",
                task_id,
                dependent_id,
                dep_rt.state.name,
                list(dep_td.dependencies),
            )

            if dep_rt.state != TaskState.BLOCKED:
                continue

            if all(
                self.runtime[d].state == TaskState.COMPLETED
                for d in dep_td.dependencies
            ):
                dep_rt.state = TaskState.READY
                priority = dep_td.cost_units
                self.queue.push(priority, dependent_id)

                logger.info(
                    "Task unblocked | task_id=%s",
                    dependent_id,
                )

        self._state_snapshot("AFTER UNBLOCK")


   
    def _handle_failure(self, task_id: str, error: Optional[str]) -> None:
        rt = self.runtime[task_id]
        td = self.tasks[task_id]

        rt.retry_count += 1
        rt.last_error = error
        self.metrics.inc("tasks_failed_total")

        if rt.retry_count <= td.retries_allowed:
            rt.state = TaskState.READY
            priority = self._compute_priority(task_id)
            self.queue.push(priority=priority, task_id=task_id)
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
                
    def run(self):
        logger.info("Scheduler loop started")
        while True:
            try:
                self.tick()
            except Exception:
                logger.exception("Scheduler tick failed")
            time.sleep(20000)
    #dummy test
    def test_retry_exhaustion_blocks_children():
        # DAG: A -> B
        # A fails permanently
        pass  # expected: B becomes BLOCKED






            
        

