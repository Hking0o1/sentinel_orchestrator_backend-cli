# scanner/types.py (or scanner/results.py)

from typing import TypedDict, Any

class ToolResult(TypedDict):
    findings: list[dict]
    raw_report: tuple[str, Any] | None
    artifacts: list[str]          # file paths (optional)
