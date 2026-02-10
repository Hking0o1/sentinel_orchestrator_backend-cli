"""
Celery dispatch adapter for Sentinel (Phase 1.5).

Responsibilities:
- Bridge scheduler -> Celery workers
- Dispatch exactly ONE task per call
- Never retry
- Never schedule
- Never inspect DAG
"""
import logging
from pathlib import Path
from engine.scheduler.scheduler import ScanScheduler
from engine.scheduler.dag import TaskDescriptor
from scanner import tasks as scanner_tasks
from engine.scheduler.events import drain_scheduler_events
from config.settings import settings
from engine.runtime.meta_loader import load_execution_context


logger = logging.getLogger(__name__)
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

    def run_once(self):
        applied = drain_scheduler_events(self.scheduler)

        if applied:
            logger.error("SCHEDULER EVENTS APPLIED | count=%d", applied)

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
            logger.info(
                "Dispatching task",
                extra={"task_id": task_id}
            )
            logger.info(
                "Dispatching task | task_id=%s | type=%s | scan_id=%s",
                task_id,
                task_type,
            )
            scanner_tasks.run_tool_task.apply_async(
                args=[task_id, task.scan_id, task_type],
            )

        # ---- POST-PROCESS TASKS ----
        elif task_type == "CORRELATION":
            base_dir = Path(settings.SCAN_RESULTS_DIR) / task.scan_id
            input_paths = []
            for dep_task_id in task.dependencies:
                dep_rt = self.scheduler.runtime.get(dep_task_id)
                if dep_rt and dep_rt.output_paths:
                    input_paths.extend(dep_rt.output_paths)

            output_path = str(base_dir / "correlation" / "correlated_findings.jsonl")
            scanner_tasks.run_correlation_task.delay(
                task_id=task.task_id,
                scan_id=task.scan_id,
                input_paths=input_paths,
                output_path=output_path,
            )

        elif task_type == "AI_SUMMARY":
            base_dir = Path(settings.SCAN_RESULTS_DIR) / task.scan_id
            findings_path = str(base_dir / "correlation" / "correlated_findings.jsonl")
            scanner_tasks.run_ai_summary_task.delay(
                task_id=task.task_id,
                scan_id=task.scan_id,
                findings_path=findings_path,
                output_path=str(base_dir / "ai" / "summary.txt"),
                progress_path=str(base_dir / "ai" / "summary.progress"),
                attack_path_path=str(base_dir / "ai" / "attack_path.txt"),
                provider_config={
                    "provider": settings.AI_PROVIDER,
                    "base_url": settings.OLLAMA_BASE_URL,
                    "model": settings.OLLAMA_MODEL,
                    "timeout_sec": settings.AI_TIMEOUT_SEC,
                },
            )

        elif task_type == "ATTACK_PATH":
            base_dir = Path(settings.SCAN_RESULTS_DIR) / task.scan_id
            ctx = load_execution_context(task.scan_id)
            scanner_tasks.run_attack_path_task.delay(
                task_id=task.task_id,
                scan_id=task.scan_id,
                findings_path=str(base_dir / "correlation" / "correlated_findings.jsonl"),
                output_path=str(base_dir / "ai" / "attack_path.txt"),
                target_url=ctx.target_url,
            )

        elif task_type == "REPORT":
            base_dir = Path(settings.SCAN_RESULTS_DIR) / task.scan_id
            ai_summary_path = str(base_dir / "ai" / "summary.txt")
            ai_summary = ai_summary_path if Path(ai_summary_path).exists() else None
            scanner_tasks.run_report_task.delay(
                task_id=task.task_id,
                scan_id=task.scan_id,
                findings_path=str(base_dir / "correlation" / "correlated_findings.jsonl"),
                ai_summary_path=ai_summary,
                json_output_path=str(base_dir / "report" / "report.json"),
                pdf_output_path=str(base_dir / "report" / "report.pdf"),
            )

        else:
            raise RuntimeError(f"Unsupported task type: {task_type}")
