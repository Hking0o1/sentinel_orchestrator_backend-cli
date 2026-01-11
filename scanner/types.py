from typing import TypedDict,List, Dict, Any, Optional, Literal


Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"]

class ToolResult(TypedDict):
    findings: list[dict]
    raw_report: tuple[str, Any] | None
    artifacts: list[str]          # file paths (optional)



# -------------------------------------------------
# Finding (normalized vulnerability record)
# -------------------------------------------------

class Finding(TypedDict, total=False):
    """
    Normalized vulnerability finding.

    This structure is intentionally flexible.
    Validation happens in correlation & reporting,
    not at tool execution time.
    """

    id: str
    tool: str
    severity: Severity
    title: str
    description: str
    file: Optional[str]
    line: Optional[int]
    cve: Optional[str]
    metadata: Dict[str, Any]


# -------------------------------------------------
# Tool execution result (canonical, in-memory)
# -------------------------------------------------

class ToolResult(TypedDict):
    """
    Canonical output of a single tool execution.

    NOTE:
    - Tools do NOT need to emit this directly
    - result_adapter normalizes tool output into this
    """

    findings: List[Finding]
    raw_report: Optional[tuple[str, Any]]
    artifacts: List[str]


# -------------------------------------------------
# Scheduler-safe task summary (VERY IMPORTANT)
# -------------------------------------------------

class TaskResultSummary(TypedDict):
    """
    Lightweight summary stored by the scheduler.

    MUST remain small and JSON-serializable.
    """

    task_type: str
    finding_count: int
    artifact_count: int


# -------------------------------------------------
# Disk-first post-processing input
# -------------------------------------------------

class PostProcessInput(TypedDict):
    """
    Input passed to POST_PROCESS DAG nodes.

    All heavy data MUST be on disk.
    """

    scan_id: str
    source_task_ids: List[str]
    findings_path: str          # JSON / JSONL file
    artifacts: List[str]