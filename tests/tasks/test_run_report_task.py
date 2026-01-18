from pathlib import Path
from unittest.mock import patch, Mock
import json
import pytest

from scanner.tasks import run_report_task

def test_run_report_task_success(tmp_path):
    findings = tmp_path / "findings.jsonl"
    findings.write_text('{"id": 1}\n')

    json_out = tmp_path / "report.json"
    pdf_out = tmp_path / "report.pdf"

    with patch(
        "scanner.reporting.json_writer.write_json_report",
        return_value=str(json_out),
    ), patch(
        "scanner.reporting.pdf_writer.write_pdf_report",
        return_value=str(pdf_out),
    ), patch(
        "scanner.tasks.notify_task_success"
    ) as success_cb, patch(
        "scanner.tasks.notify_task_failure"
    ) as failure_cb:

        run_report_task.run(
            "rep-1",
            "scan-1",
            str(findings),
            None,
            str(json_out),
            str(pdf_out),
        )

        success_cb.assert_called_once()
        failure_cb.assert_not_called()

def test_run_report_task_ai_failure_isolated(tmp_path):
    findings = tmp_path / "findings.jsonl"
    findings.write_text('{"id": 1}\n')

    json_out = tmp_path / "report.json"
    pdf_out = tmp_path / "report.pdf"

    with patch(
        "scanner.tasks.generate_ai_summary",
        side_effect=RuntimeError("AI limit"),
        create=True,
    ), patch(
        "scanner.reporting.json_writer.write_json_report",
        return_value=str(json_out),
    ), patch(
        "scanner.reporting.pdf_writer.write_pdf_report",
        return_value=str(pdf_out),
    ), patch(
        "scanner.tasks.notify_task_success"
    ) as success_cb:

        run_report_task.run(
            "rep-2",
            "scan-2",
            str(findings),
            "ai.txt",
            str(json_out),
            str(pdf_out),
        )

        success_cb.assert_called_once()

def test_run_report_task_missing_findings(tmp_path):
    with patch(
        "scanner.tasks.notify_task_failure"
    ) as failure_cb:

        run_report_task.run(
            "rep-3",
            "scan-3",
            "/does/not/exist.jsonl",
            None,
            "out.json",
            "out.pdf",
        )

        failure_cb.assert_called_once()

def test_run_report_task_large_file(tmp_path):
    findings = tmp_path / "large.jsonl"
    with open(findings, "w") as f:
        for i in range(100_000):
            f.write(json.dumps({"id": i}) + "\n")

    with patch(
        "scanner.reporting.json_writer.write_json_report",
        return_value="out.json",
    ), patch(
        "scanner.reporting.pdf_writer.write_pdf_report",
        return_value="out.pdf",
    ), patch(
        "scanner.tasks.notify_task_success"
    ) as success_cb:

        run_report_task.run(
            "rep-4",
            "scan-4",
            str(findings),
            None,
            "out.json",
            "out.pdf",
        )

        success_cb.assert_called_once()
