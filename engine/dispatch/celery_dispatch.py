# engine/dispatch/celery_dispatch.py

"""
Celery dispatch adapter for Sentinel.

Responsibilities:
- Bridge scheduler -> Celery workers
- Dispatch exactly ONE task per call
- Never retry
- Never schedule
- Never inspect DAG

This file is intentionally thin.
"""

from typing import Callable

from engine.scheduler.scheduler import ScanScheduler
from engine.scheduler.dag import TaskDescriptor

from scanner import tasks as scanner_tasks


class CeleryDispatcher:
    """
    Stateless dispatcher.

    Scheduler calls this.
    Celery executes tasks.
    """

    def __init__(self, scheduler: ScanScheduler):
        self.scheduler = scheduler

    # -------------------------
    # PUBLIC ENTRYPOINT
    # -------------------------

    def run_once(self) -> int:
        """
        Run one scheduler dispatch cycle.

        Returns:
            Number of tasks dispatched
        """
        return self.scheduler.schedule_once(self._dispatch_task)

    # -------------------------
    # INTERNAL DISPATCH LOGIC
    # -------------------------

    def _dispatch_task(self, task_id: str, task: TaskDescriptor) -> None:
        """
        Dispatch a single task to Celery.

        This method must remain dumb and explicit.
        """

        task_type = task.task_type

        # ---- SCAN TASKS ----
        if task_type == "SAST":
            scanner_tasks.run_sast_task.delay(
                task_id=task_id,
                scan_id=task.scan_id,
                target=task.target,
            )

        elif task_type == "SCA":
            scanner_tasks.run_sca_task.delay(
                task_id=task_id,
                scan_id=task.scan_id,
                target=task.target,
            )

        elif task_type.startswith("DAST"):
            scanner_tasks.run_dast_task.delay(
                task_id=task_id,
                scan_id=task.scan_id,
                target=task.target,
                tool=task_type,
            )

        elif task_type == "IAC":
            scanner_tasks.run_iac_task.delay(
                task_id=task_id,
                scan_id=task.scan_id,
                target=task.target,
            )

        # ---- POST-PROCESS TASKS ----
        elif task_type == "CORRELATION":
            scanner_tasks.run_correlation_task.delay(
                task_id=task_id,
                scan_id=task.scan_id,
            )

        elif task_type == "AI_SUMMARY":
            scanner_tasks.run_ai_summary_task.delay(
                task_id=task_id,
                scan_id=task.scan_id,
            )

        elif task_type == "REPORT":
            scanner_tasks.run_report_task.delay(
                task_id=task_id,
                scan_id=task.scan_id,
            )

        # ---- PLUGINS / FALLBACK ----
        else:
            # Generic plugin dispatch
            scanner_tasks.run_plugin_task.delay(
                task_id=task_id,
                scan_id=task.scan_id,
                task_type=task_type,
                payload=task.payload,
            )
