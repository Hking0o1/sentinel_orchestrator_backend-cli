from __future__ import annotations
import time
import json
import os 
import logging
import heapq
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
        self.resources = resource_budget
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
            "SCHEDULER TICK ENTER | ready=%d | inflight=%d | pid=%d ",
            len(self.queue),
            len(self.in_flight),
            os.getpid(),
        )

        self._state_snapshot("TICK START")
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

            if not self.resources.can_acquire(td.cost_units):
                # Preserve READY task in queue when backpressure hits.
                # Without this, a popped READY task is lost and DAG can stall.
                self.queue.push(self._compute_priority(task_id), task_id)
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
            try:
                dispatch_fn(task_id, td)
            except Exception as exc:
                logger.exception(
                    "Dispatch failed | task_id=%s | type=%s",
                    task_id,
                    td.task_type,
                )
                self.on_task_complete(
                    task_id=task_id,
                    success=False,
                    error=f"Dispatch error: {exc}",
                )
                continue
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
                len(self.in_flight),
                self.resources.available_tokens,
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
        MUST be idempotent and never crash.
        """

        logger.critical(
            "<<<<<< ON_TASK_COMPLETE CALLED | task_id=%s | success=%s >>>>>>>>",
            task_id,
            success,
        )

        # ---- Safety checks (CRITICAL) ----
        if task_id not in self.runtime:
            logger.error("UNKNOWN TASK COMPLETION | task_id=%s", task_id)
            return

        rt = self.runtime[task_id]
        td = self.tasks[task_id]

        # ---- Idempotency guard ----
        if rt.state in {TaskState.COMPLETED, TaskState.FAILED}:
            logger.warning(
                "DUPLICATE COMPLETION EVENT IGNORED | task_id=%s | state=%s",
                task_id,
                rt.state,
            )
            return

        # ---- Resource cleanup (SAFE) ----
        if task_id in self.in_flight:
            try:
                units = self.in_flight.remove(task_id)
                self.resources.release(units)
                logger.info(
                    "INFLIGHT REMOVED | task_id=%s | units=%d",
                    task_id,
                    units,
                )
            except Exception:
                logger.exception(
                    "INFLIGHT CLEANUP FAILED | task_id=%s",
                    task_id,
                )
        else:
            logger.warning(
                "TASK NOT FOUND IN INFLIGHT | task_id=%s",
                task_id,
            )

        self._state_snapshot("AFTER RESOURCE RELEASE")

        # ---- DAG progression (THE MOST IMPORTANT PART) ----
        try:
            if success:
                self._handle_success(task_id, output_paths)
                
            else:
                self._handle_failure(task_id, error)

            self._cleanup_scan_if_terminal(td.scan_id)
        except Exception:
            logger.exception(
                "SCHEDULER STATE TRANSITION FAILED | task_id=%s",
                task_id,
            )


            
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

    def _cleanup_scan_if_terminal(self, scan_id: str) -> None:
        """
        Remove completed scan state from in-memory runtime/queue structures.

        Without cleanup, long-lived scheduler processes accumulate finished tasks
        and stale queue entries.
        """
        scan_task_ids = [
            task_id for task_id, td in self.tasks.items() if td.scan_id == scan_id
        ]
        if not scan_task_ids:
            return

        terminal_states = {TaskState.COMPLETED, TaskState.FAILED, TaskState.BLOCKED}
        if not all(
            self.runtime.get(task_id)
            and self.runtime[task_id].state in terminal_states
            for task_id in scan_task_ids
        ):
            return

        removed = set(scan_task_ids)

        # Drop stale queue entries for this scan.
        self.queue._heap = [entry for entry in self.queue._heap if entry[2] not in removed]
        heapq.heapify(self.queue._heap)

        # Remove runtime/task descriptors/dependency edges.
        for task_id in removed:
            self.runtime.pop(task_id, None)
            self.tasks.pop(task_id, None)
            self._dependents.pop(task_id, None)
            self.parents.pop(task_id, None)
            self.children.pop(task_id, None)

        # Remove any references from remaining dependency sets.
        for deps in self._dependents.values():
            deps.difference_update(removed)
        for deps in self.parents.values():
            deps.difference_update(removed)
        for deps in self.children.values():
            deps.difference_update(removed)

        self._dags.pop(scan_id, None)
        self._dag_states.pop(scan_id, None)

        self.metrics.set_gauge("ready_queue_size", len(self.queue))
        self.metrics.set_gauge("in_flight_tasks", len(self.in_flight))

        logger.info(
            "Scheduler runtime cleaned for completed scan | scan_id=%s | tasks_removed=%d",
            scan_id,
            len(removed),
        )
                
    
    #dummy test
    def test_retry_exhaustion_blocks_children():
        # DAG: A -> B
        # A fails permanently
        pass  # expected: B becomes BLOCKED






            
        

