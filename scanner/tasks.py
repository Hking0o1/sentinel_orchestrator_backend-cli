import os
import logging
from celery import shared_task
from typing import Dict, Any
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
from app.db.session import get_db_session
from app.models.scan import ScanJob

logger = logging.getLogger(__name__)


@shared_task(bind=True, autoretry_for=())
def run_tool_task(
    self,
    task_id: str,
    scan_id: str,
    task_type: str,
):
    """
    Execute a single tool task.

    Phase 1.5:
    - Scheduler passes identity only
    - Worker resolves execution data from DB
    """

    db = None
    try:
        # 1️⃣ Load scan + target from DB
        db = get_db_session()
        scan: ScanJob | None = (
            db.query(ScanJob)
            .filter(ScanJob.id == scan_id)
            .one_or_none()
        )

        if scan is None:
            raise RuntimeError(f"Scan not found: {scan_id}")

        target = scan.target
        if not target:
            raise RuntimeError("Scan target is empty")

        # 2️⃣ Resolve tool runner
        runner = get_tool(task_type)

        # 3️⃣ Execute tool
        result = runner(target=target)

        # 4️⃣ Notify scheduler
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
        if db is not None:
            db.close()

@shared_task(autoretry_for=())
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


@shared_task(bind=True, autoretry_for=())
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


@shared_task(bind=True, autoretry_for=())
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
        # 1️⃣ Validate findings input
        if not os.path.exists(findings_path):
            raise FileNotFoundError(f"Findings file not found: {findings_path}")

        # 2️⃣ Optional AI summary (NON-FATAL)
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

        # 3️⃣ Core reports (MUST succeed)
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

        # 4️⃣ Verify artifacts exist
        if not os.path.exists(json_path):
            raise RuntimeError("JSON report was not created")

        if not os.path.exists(pdf_path):
            raise RuntimeError("PDF report was not created")

        # 5️⃣ Success notification
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
