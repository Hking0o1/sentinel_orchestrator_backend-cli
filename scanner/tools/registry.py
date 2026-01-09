# scanner/tools/registry.py

from typing import Callable, Dict

ToolRunner = Callable[..., list[str]]

_TOOL_REGISTRY: Dict[str, ToolRunner] = {}


def register_tool(task_type: str, runner: ToolRunner) -> None:
    """
    Register a tool execution function.

    task_type: e.g. "SAST", "DAST_ZAP", "IAC"
    runner: function that executes the tool
    """
    _TOOL_REGISTRY[task_type] = runner


def get_tool(task_type: str) -> ToolRunner:
    if task_type not in _TOOL_REGISTRY:
        raise KeyError(f"No tool registered for task type: {task_type}")
    return _TOOL_REGISTRY[task_type]


def has_tool(task_type: str) -> bool:
    return task_type in _TOOL_REGISTRY
