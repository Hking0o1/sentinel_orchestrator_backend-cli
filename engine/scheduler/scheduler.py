from __future__ import annotations

import heapq
import json
import logging
import os
import time
from collections import defaultdict
from typing import Callable, Dict, Optional

from config.settings import settings
from .dag import TaskDescriptor
from .operational_intel import OperationalIntelligence
from .policies import DefaultSchedulingPolicy
from .queue import SchedulerQueue
from .registry import InFlightRegistry
from .resources import ResourceBudget
from .state import TaskRuntimeState
from .types import SchedulerEventType, TaskState


logger = logging.getLogger(__name__)


class ScanScheduler:
    """
    Authoritative scheduler for Sentinel.
    """

    def __init__(
        self,
        *,
        resource_budget: ResourceBudget,
        policy: DefaultSchedulingPolicy,
        max_concurrent_tasks: int,
        max_heavy_tasks: int,
        metrics: Optional[object],
    ) -> None:
        self._dags: Dict[str, list[TaskDescriptor]] = {}
        self._dag_states: Dict[str, dict] = {}
        self.queue = SchedulerQueue()
        self.resources = resource_budget
        self.in_flight = InFlightRegistry()
        self.metrics = metrics

        self.tasks: Dict[str, TaskDescriptor] = {}
        self.runtime: Dict[str, TaskRuntimeState] = {}
        self.parents: Dict[str, set[str]] = {}
        self.children: Dict[str, set[str]] = {}
        self._dependents: dict[str, set[str]] = {}

        self._policy = policy
        self._max_concurrent_tasks = max_concurrent_tasks
        self._max_heavy_tasks = max_heavy_tasks

        self._scan_last_completion_monotonic: dict[str, float] = {}
        self._scan_started_monotonic: dict[str, float] = {}
        self._scan_failure_count: dict[str, int] = defaultdict(int)
        self._scan_terminal_count: dict[str, int] = defaultdict(int)
        self._scan_last_light_dispatch_monotonic: dict[str, float] = defaultdict(lambda: 0.0)

        self._ops = OperationalIntelligence(base_dir=settings.SCAN_RESULTS_DIR)

        logger.error("SCHEDULER INIT | pid=%s", os.getpid())

    def _state_snapshot(self, prefix: str = "") -> dict:
        snapshot = {
            "ready_queue": list(self.queue._heap),
            "runtime": {tid: rt.state.name for tid, rt in self.runtime.items()},
            "inflight": dict(self.in_flight._tasks),
            "resources": {
                "used_tokens": self.resources.used_tokens,
                "max_tokens": self.resources.max_tokens,
                "available_tokens": self.resources.available_tokens,
            },
        }
        logger.error("%s SCHEDULER SNAPSHOT:\n%s", prefix, json.dumps(snapshot, indent=2, default=str))
        return snapshot

    def register_scan_dag(self, scan_id: str, dag: list[TaskDescriptor]) -> None:
        self._dags[scan_id] = dag
        self._scan_started_monotonic[scan_id] = time.monotonic()
        self._scan_last_completion_monotonic[scan_id] = time.monotonic()

        logger.error("REGISTER DAG | scan_id=%s | tasks=%s", scan_id, [t.task_id for t in dag])

        for task in dag:
            self.tasks[task.task_id] = task
            self.parents[task.task_id] = set(task.dependencies)
            for dep in task.dependencies:
                self.children.setdefault(dep, set()).add(task.task_id)
                self._dependents.setdefault(dep, set()).add(task.task_id)
            self._dependents.setdefault(task.task_id, set())

            rt = TaskRuntimeState(task.task_id)
            self.runtime[task.task_id] = rt
            self._ops.mark_task_timestamp(scan_id=scan_id, task_id=task.task_id, field="admitted_at", value=rt.admitted_at)
            self._emit_task_event(
                task_id=task.task_id,
                event_type=SchedulerEventType.TASK_ADMITTED.value,
                reason="dag_registered",
            )

            if not task.dependencies:
                rt.state = TaskState.READY
                rt.ready_at = _utc_now_iso()
                self.queue.push(task.cost_units, task.task_id)
                self._ops.mark_task_timestamp(scan_id=scan_id, task_id=task.task_id, field="ready_at", value=rt.ready_at)
                self._emit_task_event(
                    task_id=task.task_id,
                    event_type=SchedulerEventType.TASK_READY.value,
                    reason="no_dependencies",
                )
            else:
                rt.state = TaskState.BLOCKED
                self._emit_task_event(
                    task_id=task.task_id,
                    event_type=SchedulerEventType.TASK_BLOCKED.value,
                    reason="waiting_for_dependencies",
                    context={"dependencies": sorted(task.dependencies)},
                )

        self._update_metrics_gauges()
        self._state_snapshot("AFTER DAG REGISTER")

    def schedule_once(self, dispatch_fn: Callable[[str, TaskDescriptor], None]) -> int:
        logger.error(
            "SCHEDULER TICK ENTER | ready=%d | inflight=%d | pid=%d",
            len(self.queue),
            len(self.in_flight),
            os.getpid(),
        )

        self._validate_invariants_and_alerts()

        scheduled = 0

        while True:
            if len(self.in_flight) >= self._max_concurrent_tasks:
                break

            task_id = self.queue.pop()
            if task_id is None:
                break

            rt = self.runtime.get(task_id)
            td = self.tasks.get(task_id)
            if not rt or not td:
                continue
            if rt.state != TaskState.READY:
                continue

            if not self.resources.can_acquire(td.cost_units):
                self.queue.push(td.cost_units, task_id)
                if self.metrics:
                    self.metrics.inc("tasks_blocked_total")
                self._emit_task_event(
                    task_id=task_id,
                    event_type=SchedulerEventType.TASK_BLOCKED.value,
                    reason="resource_limit",
                )
                break

            rt.state = TaskState.RUNNING
            now_iso = _utc_now_iso()
            rt.dispatched_at = now_iso
            rt.running_at = now_iso
            self._ops.mark_task_timestamp(scan_id=td.scan_id, task_id=task_id, field="dispatched_at", value=rt.dispatched_at)
            self._ops.mark_task_timestamp(scan_id=td.scan_id, task_id=task_id, field="running_at", value=rt.running_at)

            self.resources.acquire(td.cost_units)
            self.in_flight.add(task_id, td.cost_units)

            self._emit_task_event(task_id=task_id, event_type=SchedulerEventType.TOKENS_RESERVED.value, reason="task_start")
            self._emit_task_event(task_id=task_id, event_type=SchedulerEventType.TASK_DISPATCHED.value, reason="scheduler_dispatch")
            self._emit_task_event(task_id=task_id, event_type=SchedulerEventType.TASK_RUNNING.value, reason="dispatch_ack")

            try:
                dispatch_fn(task_id, td)
            except Exception as exc:
                logger.exception("Dispatch failed | task_id=%s | type=%s", task_id, td.task_type)
                self.on_task_complete(task_id=task_id, success=False, error=f"Dispatch error: {exc}")
                continue

            scheduled += 1
            if self.metrics:
                self.metrics.inc("tasks_scheduled_total")
            self._update_metrics_gauges()
            self._update_tokens_per_tier_metric()

            if _tier_from_cost(td.cost_units) == "LIGHT":
                self._scan_last_light_dispatch_monotonic[td.scan_id] = time.monotonic()

        self._validate_invariants_and_alerts()
        return scheduled

    def on_task_complete(
        self,
        task_id: str,
        success: bool,
        output_paths: Optional[list[str]] = None,
        error: Optional[str] = None,
    ) -> None:
        if task_id not in self.runtime:
            logger.error("UNKNOWN TASK COMPLETION | task_id=%s", task_id)
            return

        td = self.tasks[task_id]
        rt = self.runtime[task_id]

        if rt.state in {TaskState.COMPLETED, TaskState.FAILED}:
            logger.warning("DUPLICATE COMPLETION EVENT IGNORED | task_id=%s | state=%s", task_id, rt.state)
            return

        if task_id in self.in_flight:
            units = self.in_flight.remove(task_id)
            self.resources.release(units)
            self._emit_task_event(task_id=task_id, event_type=SchedulerEventType.TOKENS_RELEASED.value, reason="task_done")
        else:
            logger.warning("TASK NOT FOUND IN INFLIGHT | task_id=%s", task_id)

        now_iso = _utc_now_iso()
        rt.completed_at = now_iso
        self._ops.mark_task_timestamp(scan_id=td.scan_id, task_id=task_id, field="completed_at", value=now_iso)

        if success:
            self._handle_success(task_id, output_paths)
            if self.metrics:
                self.metrics.inc("tasks_completed_total")
            if rt.running_at:
                if self.metrics:
                    self.metrics.observe("task_latency_seconds", _seconds_since(rt.running_at))
            self._emit_task_event(task_id=task_id, event_type=SchedulerEventType.TASK_COMPLETED.value, reason="worker_success")
        else:
            self._handle_failure(task_id, error)
            self._emit_task_event(
                task_id=task_id,
                event_type=SchedulerEventType.TASK_FAILED.value,
                reason="worker_failure",
                context={"error": error or ""},
            )
            if self.metrics:
                self.metrics.inc("tasks_failed_total")

        self._scan_terminal_count[td.scan_id] += 1
        if not success:
            self._scan_failure_count[td.scan_id] += 1
        self._scan_last_completion_monotonic[td.scan_id] = time.monotonic()

        self._cleanup_scan_if_terminal(td.scan_id)
        self._update_metrics_gauges()
        self._update_tokens_per_tier_metric()
        self._validate_invariants_and_alerts()

    def _handle_success(self, task_id: str, output_paths: list[str] | None) -> None:
        rt = self.runtime[task_id]
        td = self.tasks[task_id]
        rt.state = TaskState.COMPLETED
        if output_paths:
            rt.output_paths.extend(output_paths)

        for dependent_id in self._dependents.get(task_id, []):
            dep_rt = self.runtime.get(dependent_id)
            dep_td = self.tasks.get(dependent_id)
            if not dep_rt or not dep_td:
                continue
            if dep_rt.state != TaskState.BLOCKED:
                continue

            if all(self.runtime[parent].state == TaskState.COMPLETED for parent in dep_td.dependencies):
                dep_rt.state = TaskState.READY
                dep_rt.ready_at = _utc_now_iso()
                self.queue.push(dep_td.cost_units, dependent_id)
                self._ops.mark_task_timestamp(
                    scan_id=dep_td.scan_id,
                    task_id=dependent_id,
                    field="ready_at",
                    value=dep_rt.ready_at,
                )
                self._emit_task_event(
                    task_id=dependent_id,
                    event_type=SchedulerEventType.TASK_READY.value,
                    reason=f"dependencies_satisfied_by:{task_id}",
                )

    def _handle_failure(self, task_id: str, error: Optional[str]) -> None:
        rt = self.runtime[task_id]
        td = self.tasks[task_id]

        rt.retry_count += 1
        rt.last_error = error

        if rt.retry_count <= td.retries_allowed:
            rt.state = TaskState.READY
            rt.ready_at = _utc_now_iso()
            self.queue.push(td.cost_units, task_id)
            if self.metrics:
                self.metrics.inc("tasks_retried_total")
            self._ops.mark_task_timestamp(scan_id=td.scan_id, task_id=task_id, field="ready_at", value=rt.ready_at)
            self._emit_task_event(
                task_id=task_id,
                event_type=SchedulerEventType.TASK_READY.value,
                reason="retry_scheduled",
                context={"retry_count": rt.retry_count},
            )
        else:
            rt.state = TaskState.FAILED
            if self.metrics:
                self.metrics.inc("tasks_terminal_failed_total")
            self._block_descendants(task_id)

    def _block_descendants(self, failed_task_id: str) -> None:
        for child in self.children.get(failed_task_id, []):
            rt = self.runtime.get(child)
            td = self.tasks.get(child)
            if not rt or not td:
                continue
            if rt.state in {TaskState.PENDING, TaskState.READY, TaskState.BLOCKED}:
                rt.state = TaskState.BLOCKED
                if self.metrics:
                    self.metrics.inc("tasks_blocked_total")
                self._emit_task_event(
                    task_id=child,
                    event_type=SchedulerEventType.TASK_BLOCKED.value,
                    reason=f"ancestor_failed:{failed_task_id}",
                )
                self._block_descendants(child)

    def _cleanup_scan_if_terminal(self, scan_id: str) -> None:
        scan_task_ids = [task_id for task_id, td in self.tasks.items() if td.scan_id == scan_id]
        if not scan_task_ids:
            return

        terminal_states = {TaskState.COMPLETED, TaskState.FAILED, TaskState.BLOCKED}
        if not all(self.runtime.get(task_id) and self.runtime[task_id].state in terminal_states for task_id in scan_task_ids):
            return

        removed = set(scan_task_ids)
        self.queue._heap = [entry for entry in self.queue._heap if entry[2] not in removed]
        heapq.heapify(self.queue._heap)

        for task_id in removed:
            self.runtime.pop(task_id, None)
            self.tasks.pop(task_id, None)
            self._dependents.pop(task_id, None)
            self.parents.pop(task_id, None)
            self.children.pop(task_id, None)

        for deps in self._dependents.values():
            deps.difference_update(removed)
        for deps in self.parents.values():
            deps.difference_update(removed)
        for deps in self.children.values():
            deps.difference_update(removed)

        self._dags.pop(scan_id, None)
        self._dag_states.pop(scan_id, None)
        self._scan_last_completion_monotonic.pop(scan_id, None)
        self._scan_started_monotonic.pop(scan_id, None)
        self._scan_failure_count.pop(scan_id, None)
        self._scan_terminal_count.pop(scan_id, None)
        self._scan_last_light_dispatch_monotonic.pop(scan_id, None)

    def get_metrics_snapshot(self) -> dict:
        self._update_metrics_gauges()
        self._update_tokens_per_tier_metric()
        return self.metrics.snapshot() if self.metrics else {}

    def get_runtime_overview(self) -> dict:
        per_scan: dict[str, dict] = {}
        for task_id, td in self.tasks.items():
            rt = self.runtime.get(task_id)
            if not rt:
                continue
            scan_bucket = per_scan.setdefault(
                td.scan_id,
                {
                    "task_counts": {"PENDING": 0, "READY": 0, "RUNNING": 0, "COMPLETED": 0, "FAILED": 0, "BLOCKED": 0},
                    "ready_queue_size": 0,
                    "in_flight_count": 0,
                },
            )
            scan_bucket["task_counts"][rt.state.value] = scan_bucket["task_counts"].get(rt.state.value, 0) + 1

        queue_ids = [entry[2] for entry in self.queue._heap]
        for task_id in queue_ids:
            td = self.tasks.get(task_id)
            if not td:
                continue
            if td.scan_id in per_scan:
                per_scan[td.scan_id]["ready_queue_size"] += 1

        for task_id in self.in_flight._tasks.keys():
            td = self.tasks.get(task_id)
            if not td:
                continue
            if td.scan_id in per_scan:
                per_scan[td.scan_id]["in_flight_count"] += 1

        return {
            "active_scan_count": len(per_scan),
            "global": {
                "ready_queue_size": len(self.queue),
                "in_flight_count": len(self.in_flight),
                "used_tokens": self.resources.used_tokens,
                "max_tokens": self.resources.max_tokens,
            },
            "per_scan": per_scan,
        }

    def _emit_task_event(
        self,
        *,
        task_id: str,
        event_type: str,
        reason: str,
        context: dict | None = None,
    ) -> None:
        td = self.tasks.get(task_id)
        if not td:
            return
        self._ops.emit_event(
            scan_id=td.scan_id,
            task_id=task_id,
            event_type=event_type,
            cost_tier=_tier_from_cost(td.cost_units),
            reason=reason,
            context=context,
        )

    def _update_metrics_gauges(self) -> None:
        if not self.metrics:
            return
        self.metrics.set_gauge("ready_queue_size", len(self.queue))
        self.metrics.set_gauge("in_flight_tasks", len(self.in_flight))

    def _update_tokens_per_tier_metric(self) -> None:
        if not self.metrics:
            return
        tiers = {"LIGHT": 0, "MEDIUM": 0, "HEAVY": 0, "POST_PROCESS": 0}
        for task_id, units in self.in_flight._tasks.items():
            tier = _tier_from_cost(units)
            tiers[tier] += units
        self.metrics.set_map("tokens_in_use_per_tier", tiers)

    def _validate_invariants_and_alerts(self) -> None:
        if not self.tasks:
            return

        queue_task_ids = {entry[2] for entry in self.queue._heap}
        violations: list[tuple[str, str, dict]] = []

        for task_id, rt in self.runtime.items():
            td = self.tasks.get(task_id)
            if not td:
                continue
            if rt.state == TaskState.READY and task_id not in queue_task_ids:
                violations.append((td.scan_id, "READY_TASK_MISSING_FROM_QUEUE", {"task_id": task_id}))
            if rt.state == TaskState.RUNNING and task_id not in self.in_flight:
                violations.append((td.scan_id, "RUNNING_TASK_MISSING_FROM_INFLIGHT", {"task_id": task_id}))

        if self.resources.used_tokens > self.resources.max_tokens:
            for scan_id in {t.scan_id for t in self.tasks.values()}:
                violations.append(
                    (
                        scan_id,
                        "TOKEN_BUDGET_EXCEEDED",
                        {
                            "used_tokens": self.resources.used_tokens,
                            "max_tokens": self.resources.max_tokens,
                        },
                    )
                )

        scans = defaultdict(list)
        for task_id, td in self.tasks.items():
            scans[td.scan_id].append(task_id)

        for scan_id, task_ids in scans.items():
            incomplete = [
                tid
                for tid in task_ids
                if self.runtime[tid].state not in {TaskState.COMPLETED, TaskState.FAILED, TaskState.BLOCKED}
            ]
            if incomplete:
                scan_queue = any(tid in queue_task_ids for tid in task_ids)
                scan_inflight = any(tid in self.in_flight for tid in task_ids)
                if not scan_queue and not scan_inflight:
                    violations.append(
                        (
                            scan_id,
                            "STALL_INVARIANT_VIOLATION",
                            {"incomplete_tasks": incomplete},
                        )
                    )

        for scan_id, violation, context in violations:
            self._ops.emit_alert(
                scan_id=scan_id,
                level="CRITICAL",
                alert_type=violation,
                context=context,
            )
            self._ops.dump_scheduler_snapshot(scan_id=scan_id, snapshot=self._state_snapshot("INVARIANT_VIOLATION"))

        now = time.monotonic()
        for scan_id, task_ids in scans.items():
            self._maybe_emit_soft_alerts(scan_id=scan_id, task_ids=task_ids, queue_task_ids=queue_task_ids, now=now)

    def _maybe_emit_soft_alerts(self, *, scan_id: str, task_ids: list[str], queue_task_ids: set[str], now: float) -> None:
        incomplete = [
            tid
            for tid in task_ids
            if self.runtime[tid].state not in {TaskState.COMPLETED, TaskState.FAILED, TaskState.BLOCKED}
        ]
        if not incomplete:
            return

        last_completion = self._scan_last_completion_monotonic.get(scan_id, self._scan_started_monotonic.get(scan_id, now))
        if now - last_completion > float(settings.SCHEDULER_STALL_THRESHOLD_SEC):
            self._ops.emit_alert(
                scan_id=scan_id,
                level="WARNING",
                alert_type="STALL_DETECTED",
                context={"seconds_since_last_completion": round(now - last_completion, 3)},
            )

        for task_id in task_ids:
            rt = self.runtime[task_id]
            if rt.state != TaskState.RUNNING or not rt.running_at:
                continue
            running_secs = _seconds_since(rt.running_at)
            if running_secs > float(settings.SCHEDULER_TASK_TIMEOUT_SEC):
                self._ops.emit_alert(
                    scan_id=scan_id,
                    level="WARNING",
                    alert_type="TASK_TIMEOUT",
                    context={"task_id": task_id, "running_seconds": round(running_secs, 3)},
                )

        terminal = self._scan_terminal_count.get(scan_id, 0)
        failures = self._scan_failure_count.get(scan_id, 0)
        if terminal >= 5:
            rate = failures / float(terminal)
            if rate > float(settings.SCHEDULER_HIGH_FAILURE_RATE_THRESHOLD):
                self._ops.emit_alert(
                    scan_id=scan_id,
                    level="WARNING",
                    alert_type="HIGH_FAILURE_RATE",
                    context={"failure_rate": round(rate, 4), "failures": failures, "terminal_tasks": terminal},
                )

        if not self.in_flight and self.resources.used_tokens > 0:
            self._ops.emit_alert(
                scan_id=scan_id,
                level="WARNING",
                alert_type="RESOURCE_LEAK",
                context={
                    "used_tokens": self.resources.used_tokens,
                    "in_flight_count": len(self.in_flight),
                },
            )

        scan_inflight_ids = [tid for tid in task_ids if tid in self.in_flight]
        scan_queue_ids = [tid for tid in task_ids if tid in queue_task_ids]
        has_light_waiting = any(_tier_from_cost(self.tasks[tid].cost_units) == "LIGHT" for tid in scan_queue_ids)
        heavy_running = all(_tier_from_cost(self.tasks[tid].cost_units) in {"HEAVY", "POST_PROCESS"} for tid in scan_inflight_ids) and bool(scan_inflight_ids)
        last_light = self._scan_last_light_dispatch_monotonic.get(scan_id, self._scan_started_monotonic.get(scan_id, now))
        if has_light_waiting and heavy_running and (now - last_light > float(settings.SCHEDULER_STARVATION_THRESHOLD_SEC)):
            self._ops.emit_alert(
                scan_id=scan_id,
                level="WARNING",
                alert_type="STARVATION_RISK",
                context={
                    "light_waiting": True,
                    "heavy_running_count": len(scan_inflight_ids),
                    "seconds_since_light_dispatch": round(now - last_light, 3),
                },
            )


def _tier_from_cost(cost_units: int) -> str:
    if cost_units <= 2:
        return "LIGHT"
    if cost_units <= 4:
        return "MEDIUM"
    if cost_units <= 7:
        return "HEAVY"
    return "POST_PROCESS"


def _utc_now_iso() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _seconds_since(utc_iso: str) -> float:
    import datetime as _dt

    started = _dt.datetime.fromisoformat(utc_iso)
    if started.tzinfo is None:
        started = started.replace(tzinfo=_dt.timezone.utc)
    return (_dt.datetime.now(_dt.timezone.utc) - started).total_seconds()
