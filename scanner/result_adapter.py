# scanner/result_adapter.py

from typing import Dict, Any

from scanner.types import ToolResult, TaskResultSummary


def adapt_tool_result(raw_result: Dict[str, Any]) -> ToolResult:
    """
    Normalize raw tool output into ToolResult.

    Defensive but permissive:
    - prevents malformed tool output
    - does NOT mutate tool data
    """

    if not isinstance(raw_result, dict):
        raise ValueError("Tool result must be a dict")

    findings = raw_result.get("findings", [])
    artifacts = raw_result.get("artifacts", [])
    raw_report = raw_result.get("raw_report")

    if not isinstance(findings, list):
        raise ValueError("'findings' must be a list")

    if not isinstance(artifacts, list):
        raise ValueError("'artifacts' must be a list")

    return {
        "findings": findings,
        "raw_report": raw_report,
        "artifacts": artifacts,
    }


def summarize_for_scheduler(
    *,
    task_type: str,
    tool_result: ToolResult,
) -> TaskResultSummary:
    """
    Create a scheduler-safe summary.

    This is the ONLY object the scheduler should store.
    """

    return {
        "task_type": task_type,
        "finding_count": len(tool_result["findings"]),
        "artifact_count": len(tool_result["artifacts"]),
    }
