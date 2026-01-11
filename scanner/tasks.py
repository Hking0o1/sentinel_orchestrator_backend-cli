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
from engine.dispatch.callbacks import (
    notify_task_success,
    notify_task_failure,
)
from scanner.reporting.json_writer import write_json_report
from scanner.reporting.pdf_writer import write_pdf_report
from engine.dispatch.callbacks import notify_task_success, notify_task_failure


@shared_task(bind=True, autoretry_for=())
def run_tool_task(
    self,
    task_id: str,
    scan_id: str,
    task_type: str,
    target: str,
    payload: Dict[str, Any] | None = None,
):
    """
    Commit 5: SINGLE UNIT OF EXECUTION

    - Executes exactly one tool
    - No orchestration
    - No DB
    - No retries
    - No AI
    - No reports
    """

    try:
        runner = get_tool(task_type)

        raw_result = runner(
            task_id=task_id,
            scan_id=scan_id,
            target=target,
            **(payload or {}),
        )

        # Normalize tool output
        tool_result = adapt_tool_result(raw_result)

        # Notify scheduler (authoritative)
        notify_task_success(
            task_id=task_id,
            output=tool_result,
        )

    except Exception as exc:
        notify_task_failure(
            task_id=task_id,
            error=str(exc),
        )


@shared_task(bind=True, autoretry_for=())
def run_correlation_task(
    self,
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
    """

    try:
        json_path = write_json_report(
            scan_id=scan_id,
            findings_path=findings_path,
            ai_summary_path=ai_summary_path,
            output_path=json_output_path,
        )

        pdf_path = write_pdf_report(
            scan_id=scan_id,
            findings_path=findings_path,
            ai_summary_path=ai_summary_path,
            output_path=pdf_output_path,
        )

        notify_task_success(
            task_id=task_id,
            output_summary={
                "task_type": "REPORT",
                "finding_count": 0,
                "artifact_count": 2,
            },
            artifacts=[json_path, pdf_path],
        )

    except Exception as exc:
        notify_task_failure(task_id=task_id, error=str(exc))