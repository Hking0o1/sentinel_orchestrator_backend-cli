"""
Celery dispatch adapter for Sentinel (Phase 1.5).

Responsibilities:
- Bridge scheduler -> Celery workers
- Dispatch exactly ONE task per call
- Never retry
- Never schedule
- Never inspect DAG
"""

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

        # ---- TOOL TASKS (generic) ----
        if task_type in {
            "SAST",
            "SCA",
            "IAC",
            "DAST_ZAP",
            "DAST_NIKTO",
            "DAST_SQLMAP",
            "RESILIENCE",
        }:
            scanner_tasks.run_tool_task.delay(
                task_id=task.task_id,
                scan_id=task.scan_id,
                task_type=task.task_type,
            )

        # ---- POST-PROCESS TASKS ----
        elif task_type == "CORRELATION":
            scanner_tasks.run_correlation_task.delay(
                task_id=task.task_id,
                scan_id=task.scan_id,
            )

        elif task_type == "AI_SUMMARY":
            scanner_tasks.run_ai_summary_task.delay(
                task_id=task.task_id,
                scan_id=task.scan_id,
            )

        elif task_type == "REPORT":
            scanner_tasks.run_report_task.delay(
                task_id=task.task_id,
                scan_id=task.scan_id,
            )

        else:
            raise RuntimeError(f"Unsupported task type: {task_type}")
