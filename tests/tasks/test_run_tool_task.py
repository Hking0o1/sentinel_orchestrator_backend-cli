import pytest
from unittest.mock import Mock, patch
from scanner.tasks import run_tool_task

def test_run_tool_task_success():
    fake_runner = Mock(return_value={"raw": "result"})
    fake_adapted = {"findings": [{"id": 1}]}

    with patch("scanner.tasks.get_tool", return_value=fake_runner), \
         patch("scanner.tasks.adapt_tool_result", return_value=fake_adapted), \
         patch("scanner.tasks.notify_task_success") as success_cb, \
         patch("scanner.tasks.notify_task_failure") as failure_cb:

        run_tool_task(
            task_id="task-1",
            scan_id="scan-1",
            task_type="SAST",
            target="example.com",
            payload={"foo": "bar"},
        )

        # Tool invoked correctly
        fake_runner.assert_called_once_with(
            task_id="task-1",
            scan_id="scan-1",
            target="example.com",
            foo="bar",
        )

        # Success callback
        success_cb.assert_called_once_with(
            task_id="task-1",
            output=fake_adapted,
        )

        # Failure must NOT be called
        failure_cb.assert_not_called()

def test_run_tool_task_tool_failure():
    fake_runner = Mock(side_effect=RuntimeError("boom"))

    with patch("scanner.tasks.get_tool", return_value=fake_runner), \
         patch("scanner.tasks.notify_task_success") as success_cb, \
         patch("scanner.tasks.notify_task_failure") as failure_cb:

        run_tool_task(
            task_id="task-2",
            scan_id="scan-2",
            task_type="SAST",
            target="example.com",
            payload=None,
        )

        success_cb.assert_not_called()
        failure_cb.assert_called_once()
        args, kwargs = failure_cb.call_args
        assert kwargs["task_id"] == "task-2"
        assert "boom" in kwargs["error"]

def test_run_tool_task_adaptation_failure():
    fake_runner = Mock(return_value={"bad": "data"})

    with patch("scanner.tasks.get_tool", return_value=fake_runner), \
         patch("scanner.tasks.adapt_tool_result", side_effect=ValueError("bad format")), \
         patch("scanner.tasks.notify_task_success") as success_cb, \
         patch("scanner.tasks.notify_task_failure") as failure_cb:

        run_tool_task(
            task_id="task-3",
            scan_id="scan-3",
            task_type="SAST",
            target="example.com",
        )

        success_cb.assert_not_called()
        failure_cb.assert_called_once()
