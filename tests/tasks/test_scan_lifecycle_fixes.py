from unittest.mock import patch

import pytest

from engine.dispatch.celery_dispatch import CeleryDispatcher
from engine.scheduler.dag import TaskDescriptor
from engine.scheduler.metrics import SchedulerMetrics
from engine.scheduler.policies import DefaultSchedulingPolicy
from engine.scheduler.resources import ResourceBudget
from engine.scheduler.scheduler import ScanScheduler
from engine.services.scan_submitter import ScanSubmissionError, ScanSubmitter
from scanner.tasks import run_report_task


class _DummyScheduler:
    def __init__(self):
        self.runtime = {}


def test_container_task_is_dispatched_to_run_tool_task():
    dispatcher = CeleryDispatcher(_DummyScheduler())
    td = TaskDescriptor(
        task_id="scan-1:CONTAINER",
        scan_id="scan-1",
        task_type="CONTAINER",
        cost_units=2,
        dependencies=frozenset(),
        retries_allowed=0,
    )

    with patch("engine.dispatch.celery_dispatch.scanner_tasks.run_tool_task.apply_async") as apply_async:
        dispatcher._dispatch_task("scan-1:CONTAINER", td)

    apply_async.assert_called_once_with(args=["scan-1:CONTAINER", "scan-1", "CONTAINER"])


def test_scheduler_releases_inflight_when_dispatch_raises():
    scheduler = ScanScheduler(
        resource_budget=ResourceBudget(max_tokens=10),
        policy=DefaultSchedulingPolicy(),
        max_concurrent_tasks=5,
        max_heavy_tasks=2,
        metrics=SchedulerMetrics(),
    )
    td = TaskDescriptor(
        task_id="scan-2:SAST",
        scan_id="scan-2",
        task_type="SAST",
        cost_units=3,
        dependencies=frozenset(),
        retries_allowed=0,
    )
    scheduler.register_scan_dag("scan-2", [td])

    def _boom(_task_id, _td):
        raise RuntimeError("dispatch exploded")

    scheduled = scheduler.schedule_once(_boom)

    assert scheduled == 0
    assert "scan-2:SAST" not in scheduler.in_flight
    assert scheduler.resources.used_tokens == 0
    assert "scan-2:SAST" not in scheduler.runtime


def test_submitter_rejects_missing_source_path(tmp_path, monkeypatch):
    monkeypatch.setattr("engine.services.scan_submitter.settings.SCAN_RESULTS_DIR", str(tmp_path))

    class _StubScheduler:
        def register_scan_dag(self, _scan_id, _dag):
            return None

    submitter = ScanSubmitter(_StubScheduler())

    with pytest.raises(ScanSubmissionError) as exc:
        submitter.submit_scan(
            {
                "scan_id": "scan-3",
                "profile": "DEVELOPER",
                "targets": {"source_code_path": str(tmp_path / "missing")},
            }
        )

    assert "does not exist" in str(exc.value)


def test_submitter_resolves_source_path_from_configured_roots(tmp_path, monkeypatch):
    project_dir = tmp_path / "Cybergeeta-encryption-tool"
    project_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("SCAN_SOURCE_ROOTS", str(tmp_path))
    monkeypatch.setattr("engine.services.scan_submitter.settings.SCAN_RESULTS_DIR", str(tmp_path / "results"))

    class _StubScheduler:
        def register_scan_dag(self, _scan_id, _dag):
            return None

    submitter = ScanSubmitter(_StubScheduler())
    normalized = submitter.validate_scan_request(
        {
            "scan_id": "scan-3b",
            "profile": "DEVELOPER",
            "targets": {"source_code_path": "/app/projects_to_scan/Cybergeeta-encryption-tool"},
        }
    )

    assert normalized["targets"]["source_code_path"] == str(project_dir.resolve())


def test_run_report_task_triggers_scan_finalization_hooks(tmp_path):
    findings = tmp_path / "findings.jsonl"
    findings.write_text('{"severity":"HIGH","title":"x"}\n', encoding="utf-8")
    json_out = tmp_path / "report.json"
    pdf_out = tmp_path / "report.pdf"
    json_out.write_text("{}", encoding="utf-8")
    pdf_out.write_text("%PDF-1.4", encoding="utf-8")

    with patch("scanner.tasks.write_json_report", return_value=str(json_out)), patch(
        "scanner.tasks.write_pdf_report", return_value=str(pdf_out)
    ), patch("scanner.tasks.notify_task_success") as success_cb, patch(
        "scanner.tasks._set_scan_status"
    ) as set_status_cb, patch("scanner.tasks._notify_integrations") as notify_integrations_cb:
        run_report_task.run(
            "scan-4:REPORT",
            "scan-4",
            str(findings),
            None,
            str(json_out),
            str(pdf_out),
        )

    success_cb.assert_called_once()
    set_status_cb.assert_called_once()
    notify_integrations_cb.assert_called_once()


def test_run_report_task_marks_failed_and_notifies_on_error():
    with patch("scanner.tasks.notify_task_failure") as failure_cb, patch(
        "scanner.tasks._set_scan_status"
    ) as set_status_cb, patch("scanner.tasks._notify_integrations") as notify_integrations_cb:
        run_report_task.run(
            "scan-5:REPORT",
            "scan-5",
            "missing-findings.jsonl",
            None,
            "out.json",
            "out.pdf",
        )

    failure_cb.assert_called_once()
    set_status_cb.assert_called_once()
    notify_integrations_cb.assert_called_once()
