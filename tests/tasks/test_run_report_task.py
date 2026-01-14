from pathlib import Path
from unittest.mock import patch, Mock
import json
import pytest

from scanner.tasks import run_report_task

def test_run_report_task_success(tmp_path):
    findings = tmp_path / "findings.jsonl"
    report_dir = tmp_path / "reports"
    report_dir.mkdir()

    findings.write_text(
        '{"id": 1, "severity": "HIGH"}\n'
        '{"id": 2, "severity": "LOW"}\n'
    )

    with patch("scanner.tasks.generate_json_report") as json_writer, \
         patch("scanner.tasks.generate_pdf_report") as pdf_writer, \
         patch("scanner.tasks.notify_task_success") as success_cb, \
         patch("scanner.tasks.notify_task_failure") as failure_cb:

        run_report_task(
            task_id="rep-1",
            scan_id="scan-1",
            findings_path=str(findings),
            report_dir=str(report_dir),
            enable_ai=False,
        )

        json_writer.assert_called_once()
        pdf_writer.assert_called_once()

        success_cb.assert_called_once()
        failure_cb.assert_not_called()
def test_run_report_task_ai_failure_isolated(tmp_path):
    findings = tmp_path / "findings.jsonl"
    report_dir = tmp_path / "reports"
    report_dir.mkdir()

    findings.write_text('{"id": 1}\n')

    with patch("scanner.tasks.generate_json_report"), \
         patch("scanner.tasks.generate_pdf_report"), \
         patch("scanner.tasks.run_ai_summary", side_effect=RuntimeError("AI token limit")), \
         patch("scanner.tasks.notify_task_success") as success_cb, \
         patch("scanner.tasks.notify_task_failure") as failure_cb:

        run_report_task(
            task_id="rep-2",
            scan_id="scan-2",
            findings_path=str(findings),
            report_dir=str(report_dir),
            enable_ai=True,
        )

        success_cb.assert_called_once()
        failure_cb.assert_not_called()

def test_run_report_task_missing_findings(tmp_path):
    report_dir = tmp_path / "reports"
    report_dir.mkdir()

    with patch("scanner.tasks.notify_task_success") as success_cb, \
         patch("scanner.tasks.notify_task_failure") as failure_cb:

        run_report_task(
            task_id="rep-3",
            scan_id="scan-3",
            findings_path="/does/not/exist.jsonl",
            report_dir=str(report_dir),
            enable_ai=False,
        )

        success_cb.assert_not_called()
        failure_cb.assert_called_once()
def test_run_report_task_streaming(tmp_path):
    findings = tmp_path / "large.jsonl"
    report_dir = tmp_path / "reports"
    report_dir.mkdir()

    with open(findings, "w") as f:
        for i in range(10_000):
            f.write(json.dumps({"id": i}) + "\n")

    with patch("scanner.tasks.generate_json_report") as json_writer, \
         patch("scanner.tasks.generate_pdf_report"), \
         patch("scanner.tasks.notify_task_success"):

        run_report_task(
            task_id="rep-4",
            scan_id="scan-4",
            findings_path=str(findings),
            report_dir=str(report_dir),
            enable_ai=False,
        )

        json_writer.assert_called_once()



