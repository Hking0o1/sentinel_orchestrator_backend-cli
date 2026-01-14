import pytest
from scanner.tools.registry import get_tool
from scanner.tools.adapter import ToolRunnerAdapter
from tests.contracts.bootstrap_tools import bootstrap_tool_registry


@pytest.mark.contract
def test_tool_failure_is_exception(tmp_path):
    """
    Tools must raise exceptions on invalid input,
    not return garbage or exit the process.
    """

    bootstrap_tool_registry()

    task_types = [
        "SAST",
        "SCA",
        "DAST_NIKTO",
        "DAST_SQLMAP",
        "DAST_ZAP",
        "IAC",
        "CONTAINER",
        "RESILIENCE",
    ]

    for task_type in task_types:
        runner = get_tool(task_type)
        adapter = ToolRunnerAdapter(runner)

        # Skip external dependency tools
        module = runner.__module__
        tool_module = __import__(module, fromlist=[""])
        if getattr(tool_module, "REQUIRES_EXTERNAL_DEPENDENCIES", False):
            pytest.skip(f"{task_type} requires external dependencies")

        # Invalid invocation must fail
        with pytest.raises(Exception):
            adapter.run(output_dir=tmp_path)
