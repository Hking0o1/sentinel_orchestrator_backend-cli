import json
from pathlib import Path
from unittest.mock import patch
import pytest
from scanner.tasks import run_correlation_task


def test_run_correlation_task_success(tmp_path):
    input1 = tmp_path / "tool1.jsonl"
    input2 = tmp_path / "tool2.jsonl"
    output = tmp_path / "correlated.jsonl"

    input1.write_text('{"id": 1}\n')
    input2.write_text('{"id": 2}\n')

    # Create a fake correlated output file
    output.write_text(
        '{"id": 1, "severity": "HIGH"}\n'
        '{"id": 2, "severity": "LOW"}\n'
    )

    with patch(
        "scanner.tasks.correlate_from_disk",
        return_value=str(output),
    ) as correlate, \
         patch("scanner.tasks.notify_task_success") as success_cb, \
         patch("scanner.tasks.notify_task_failure") as failure_cb:

        run_correlation_task(
            task_id="corr-1",
            scan_id="scan-1",
            input_paths=[str(input1), str(input2)],
            output_path=str(output),
        )

        correlate.assert_called_once()
        success_cb.assert_called_once()
        failure_cb.assert_not_called()


def test_run_correlation_task_failure(tmp_path):
    input_file = tmp_path / "tool.jsonl"
    output = tmp_path / "correlated.jsonl"

    input_file.write_text(json.dumps({"id": 1}) + "\n")

    with patch(
        "scanner.tasks.correlate_from_disk",
        side_effect=RuntimeError("correlation failed"),
    ), patch("scanner.tasks.notify_task_success") as success_cb, \
         patch("scanner.tasks.notify_task_failure") as failure_cb:

        run_correlation_task(
            task_id="corr-2",
            scan_id="scan-2",
            input_paths=[str(input_file)],
            output_path=str(output),
        )

        success_cb.assert_not_called()
        failure_cb.assert_called_once()
        assert not output.exists()

def test_run_correlation_task_invalid_input_path(tmp_path):
    output = tmp_path / "correlated.jsonl"

    with patch("scanner.tasks.notify_task_success") as success_cb, \
         patch("scanner.tasks.notify_task_failure") as failure_cb:

        run_correlation_task(
            task_id="corr-3",
            scan_id="scan-3",
            input_paths=["/does/not/exist.jsonl"],
            output_path=str(output),
        )

        success_cb.assert_not_called()
        failure_cb.assert_called_once()
