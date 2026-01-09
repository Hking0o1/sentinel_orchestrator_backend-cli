# scanner/result_adapter.py

from scanner.types import ToolResult

def adapt_tool_result(result: dict) -> ToolResult:
    """
    Normalize tool return value into ToolResult.
    """

    if not isinstance(result, dict):
        raise ValueError("Tool result must be a dict")

    return {
        "findings": result.get("findings", []),
        "raw_report": result.get("raw_report"),
        "artifacts": result.get("artifacts", []),
    }
