import pytest
from scanner.tools.adapter import ToolRunnerAdapter
from scanner.tools.registry import get_tool
from tests.contracts.bootstrap_tools import bootstrap_tool_registry
import scanner.tools


@pytest.mark.contract
def test_all_tools_register_and_obey_contract(tmp_path):
    bootstrap_tool_registry()

    expected_tools = [
        "SAST",
        "SCA",
        "DAST_NIKTO",
        "DAST_SQLMAP",
        "DAST_ZAP",
        "IAC",
        "CONTAINER",
        "RESILIENCE",
    ]

    for task_type in expected_tools:
        runner = get_tool(task_type)

        module = runner.__module__
        tool_module = __import__(module, fromlist=[""])

        if getattr(tool_module, "REQUIRES_EXTERNAL_DEPENDENCIES", False):
            pytest.skip(f"{task_type} requires external dependencies")

        adapter = ToolRunnerAdapter(runner)
        assert callable(adapter.run)

        result = adapter.run(
            target="http://example.com",
            src_path=".",
            output_dir=tmp_path,
        )

        assert isinstance(result, dict)
        assert "findings" in result
        assert isinstance(result["findings"], list)
