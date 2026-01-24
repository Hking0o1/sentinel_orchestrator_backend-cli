from scanner.celery_app import celery_app
import os
import logging
from pathlib import Path
from scanner.ai.chunker import chunk_findings_jsonl
from scanner.ai.state import load_progress, save_progress
from scanner.ai.summarizer import summarize_chunk
from scanner.ai.provider import GeminiProvider
from scanner.ai.exceptions import AISummarizationError
from engine.dispatch.callbacks import notify_task_success, notify_task_failure
from scanner.tools.registry import get_tool
from scanner.result_adapter import adapt_tool_result
from scanner.correlation.disk_correlator import correlate_from_disk
from scanner.reporting.json_writer import write_json_report
from scanner.reporting.pdf_writer import write_pdf_report
from app.db.sync_session import get_sync_db
from app.db.session import get_db_session
from app.models.scan import Scan, ScanProfile
from config.settings import settings
from scanner.tools.adapter import ToolRunnerAdapter
from engine.runtime.scan_context import ExecutionScanContext
from engine.runtime.meta_loader import load_execution_context

logger = logging.getLogger(__name__)
__all__ = ["celery_app"]


@celery_app.task(bind=True, autoretry_for=())
def run_tool_task(
    self,
    task_id: str,
    scan_id: str,
    task_type: str,
):
    db = None
    try:
        db = next(get_sync_db())

        scan = db.query(Scan).filter(Scan.id == scan_id).one_or_none()
        if not scan:
            raise RuntimeError(f"Scan not found: {scan_id}")

        ctx = load_execution_context(scan_id)

        output_dir = (
            Path(settings.SCAN_RESULTS_DIR)
            / scan_id
            / task_type.lower()
        )
        output_dir.mkdir(parents=True, exist_ok=True)

        runner = get_tool(task_type)
        adapter = ToolRunnerAdapter(runner)

        result = adapter.run(
            target_url=ctx.target_url,
            src_path=ctx.src_path,
            output_dir=str(output_dir),
        )
        logger.info(
            "Tool finished | tool=%s | findings=%d | artifacts=%s",
            task_type,
            len(result.get("findings", [])),
            result.get("raw_report"),
        )

        notify_task_success(
            task_id=task_id,
            output_summary={
                "task_type": task_type,
                "artifact_count": 1,
            },
            artifacts=[result.get("raw_report")],
        )

    except Exception as exc:
        logger.exception("Tool execution failed")
        notify_task_failure(task_id=task_id, error=str(exc))
        raise

    finally:
        if db:
            db.close()


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
