from scanner.celery_app import celery_app
import os
import logging
from pathlib import Path
import asyncio
from scanner.ai.chunker import chunk_findings_jsonl
from scanner.ai.state import load_progress, save_progress
from scanner.ai.summarizer import summarize_chunk
from scanner.ai.provider import GeminiProvider
from scanner.ai.exceptions import AISummarizationError
from engine.dispatch.callbacks import notify_task_success, notify_task_failure
from scanner.tools.registry import get_tool
from scanner.correlation.disk_correlator import correlate_from_disk
from scanner.reporting.json_writer import write_json_report
from scanner.reporting.pdf_writer import write_pdf_report
from app.db.sync_session import get_sync_db
from app.models.scan import Scan
from config.settings import settings
from scanner.tools.adapter import ToolRunnerAdapter
from engine.runtime.meta_loader import load_execution_context


logger = logging.getLogger(__name__)
__all__ = ["celery_app"]


@celery_app.task(bind=True, autoretry_for=())
def run_tool_task(self, task_id: str, scan_id: str, task_type: str):
    db = None
    output_paths = []
    error = None

    try:
        db = next(get_sync_db())

        scan = db.query(Scan).filter(Scan.id == scan_id).one_or_none()
        if not scan:
            raise RuntimeError(f"Scan not found: {scan_id}")

        ctx = load_execution_context(scan_id)

        output_dir = Path(settings.SCAN_RESULTS_DIR) / scan_id / task_type.lower()
        output_dir.mkdir(parents=True, exist_ok=True)

        runner = get_tool(task_type)
        adapter = ToolRunnerAdapter(runner)

        result = adapter.run(
            target_url=ctx.target_url,
            src_path=ctx.src_path,
            output_dir=str(output_dir),
        )

        if result.get("raw_report"):
            output_paths.append(result["raw_report"])

        findings = result.get("findings", [])
        if isinstance(findings, int):
            findings_count = findings
        elif isinstance(findings, list):
            findings_count = len(findings)
        else:
            findings_count = 0

        logger.info(
            "Tool finished | tool=%s | findings=%d | artifacts=%s",
            task_type,
            findings_count,
            output_paths,
        )

    except Exception as exc:
        error = str(exc)
        logger.exception("Tool execution failed")

    finally:
        if error:
            notify_task_failure(task_id=task_id ,scan_id=scan_id , error=error)
        else:
            notify_task_success(
                task_id=task_id,
                scan_id=scan_id,
                output_paths=output_paths,
            )

        if db:
            db.close()


@celery_app.task
def on_task_success(result, task_id):
    from engine.scheduler.runtime import get_scheduler
    scheduler = get_scheduler()
    scheduler.on_task_complete(task_id=task_id, success=True)

@celery_app.task
def on_task_failure(request, exc, traceback, task_id):
    from engine.scheduler.runtime import get_scheduler
    scheduler = get_scheduler()
    scheduler.on_task_complete(
        task_id=task_id,
        success=False,
        error=str(exc),
    )

@celery_app.task(
    name="scanner.tasks.dispatch_scheduled_scans",
    bind=True,
    autoretry_for=(),
)
def dispatch_scheduled_scans(self, *args, **kwargs):
    """
    Celery Beat entrypoint.
    MUST accept self (bind=True) and extra args.
    """
    logger.info("DISPATCH_SCHEDULED_SCANS CALLED BY BEAT")

    from engine.scheduler.runtime import get_scheduler
    from engine.services.scan_submitter import ScanSubmitter
    from engine.services.schedule_loader import ScheduleLoader
    from app.db.session import get_db_session

    scheduler = get_scheduler()
    submitter = ScanSubmitter(scheduler)
    loader = ScheduleLoader(submitter)

    async def _run():
        async with get_db_session() as db:
            return await loader.dispatch_due_schedules(db)

    return asyncio.run(_run())
   
@celery_app.task(bind=True, autoretry_for=())
def run_correlation_task(
    *,
    task_id: str,
    scan_id: str,
    input_paths: list[str],
    output_path: str,
):
    """
    POST_PROCESS DAG task: Correlate findings from disk.

    - Stateless
    - Deterministic
    - Retry-safe
    """

    try:
        correlated_path = correlate_from_disk(
            input_paths=input_paths,
            output_path=output_path,
        )

        # Count findings WITHOUT loading into memory
        finding_count = 0
        with open(correlated_path, "r", encoding="utf-8") as f:
            for _ in f:
                finding_count += 1

        notify_task_success(
            task_id=task_id,
            output_summary={
                "task_type": "CORRELATION",
                "finding_count": finding_count,
                "artifact_count": 1,
            },
            findings_path=correlated_path,
        )

    except Exception as exc:
        notify_task_failure(
            task_id=task_id,
            error=str(exc),
        )


@celery_app.task(bind=True, autoretry_for=())
def run_ai_summary_task(
    self,
    task_id: str,
    scan_id: str,
    findings_path: str,
    output_path: str,
    progress_path: str,
    provider_config: dict,
    max_items_per_chunk: int = 20,
):
    """
    POST_PROCESS DAG task: AI summarization.

    HARD GUARANTEES:
    - Partial progress survives crashes
    - AI failure does NOT fail scan
    """

    try:
        provider = GeminiProvider(**provider_config)
        last_done = load_progress(progress_path)

        with open(output_path, "a", encoding="utf-8") as out:
            for idx, chunk in enumerate(
                chunk_findings_jsonl(
                    input_path=findings_path,
                    max_items=max_items_per_chunk,
                )
            ):
                if idx < last_done:
                    continue

                try:
                    summary = summarize_chunk(
                        provider=provider,
                        findings=chunk,
                    )
                    out.write(summary + "\n\n")
                    save_progress(progress_path, idx + 1)

                except AISummarizationError as ai_exc:
                    # Non-fatal: log + continue
                    out.write(
                        f"[AI ERROR] Chunk {idx}: {ai_exc}\n\n"
                    )
                    save_progress(progress_path, idx + 1)

        notify_task_success(
            task_id=task_id,
            output_summary={
                "task_type": "AI_SUMMARY",
                "finding_count": 0,
                "artifact_count": 1,
            },
            findings_path=output_path,
        )

    except Exception as exc:
        notify_task_failure(task_id=task_id, error=str(exc))


@celery_app.task(bind=True, autoretry_for=())
def run_report_task(
    self,
    task_id: str,
    scan_id: str,
    findings_path: str,
    ai_summary_path: str | None,
    json_output_path: str,
    pdf_output_path: str,
):
    """
    POST_PROCESS DAG task: Report generation.
    Disk-first, retry-safe, AI-isolated.
    """
    try:
        # Validate findings input
        if not os.path.exists(findings_path):
            raise FileNotFoundError(f"Findings file not found: {findings_path}")

        #  Optional AI summary (NON-FATAL)
        effective_ai_summary_path = None
        if ai_summary_path:
            try:
                write_json_report(
                    scan_id=scan_id,
                    findings_path=findings_path,
                    ai_summary_path=ai_summary_path,
                    output_path=ai_summary_path,
                )
                effective_ai_summary_path = ai_summary_path
            except Exception as ai_exc:
                logger.warning(
                    "AI summary generation failed (ignored): %s", ai_exc
                )

        # Core reports (MUST succeed)
        json_path = write_json_report(
            scan_id=scan_id,
            findings_path=findings_path,
            ai_summary_path=effective_ai_summary_path,
            output_path=json_output_path,
        )

        pdf_path = write_pdf_report(
            scan_id=scan_id,
            findings_path=findings_path,
            ai_summary_path=effective_ai_summary_path,
            output_path=pdf_output_path,
        )

        #  Verify artifacts exist
        if not os.path.exists(json_path):
            raise RuntimeError("JSON report was not created")

        if not os.path.exists(pdf_path):
            raise RuntimeError("PDF report was not created")

        # Success notification
        notify_task_success(
            task_id=task_id,
            output_summary={
                "task_type": "REPORT",
                "artifact_count": 2,
            },
            artifacts=[json_path, pdf_path],
        )

    except Exception as exc:
        notify_task_failure(
            task_id=task_id,
            error=str(exc),
        )
