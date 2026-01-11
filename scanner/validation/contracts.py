# scanner/validation/contracts.py

from typing import Dict, Any
from scanner.types import ToolResult


def validate_tool_result(result: Dict[str, Any]) -> ToolResult:
    """
    Minimal runtime validation for tool outputs.

    Fails fast on corrupted or plugin-broken outputs.
    """

    if not isinstance(result, dict):
        raise ValueError("ToolResult must be dict")

    if "findings" not in result or not isinstance(result["findings"], list):
        raise ValueError("ToolResult missing valid 'findings' list")

    if "artifacts" in result and not isinstance(result["artifacts"], list):
        raise ValueError("'artifacts' must be list")

    return result  # type: ignore
