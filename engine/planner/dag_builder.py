from typing import List, Dict, Set
from uuid import uuid4

from engine.scheduler.dag import TaskDescriptor
from engine.planner.cost_model import get_cost_tier, get_cost_units
from engine.planner.exceptions import (
    InvalidScanRequest,
    UnsupportedProfile,
    ToolResolutionError,
)

# -------------------------
# PUBLIC ENTRYPOINT
# -------------------------

def build_scan_dag(scan_request: dict) -> List[TaskDescriptor]:
    """
    Build execution DAG from scan request.

    Raises:
        InvalidScanRequest
        UnsupportedProfile
        ToolResolutionError
    """

    _validate_scan_request(scan_request)

    scan_id = scan_request["scan_id"]
    profile = scan_request.get("profile", "full")

    tools = resolve_tools(profile)

    scan_tasks = create_scan_tasks(scan_id, tools)

    correlation_task = create_correlation_task(scan_id, scan_tasks)

    final_dependency = correlation_task.task_id

    if scan_request.get("enable_ai", False):
        ai_task = create_ai_task(scan_id, correlation_task.task_id)
        final_dependency = ai_task.task_id
        tasks = scan_tasks + [correlation_task, ai_task]
    else:
        tasks = scan_tasks + [correlation_task]

    report_task = create_report_task(scan_id, final_dependency)
    tasks.append(report_task)

    return tasks

def _validate_scan_request(scan_request: dict) -> None:
    if not isinstance(scan_request, dict):
        raise InvalidScanRequest("scan_request must be a dict")

    if "scan_id" not in scan_request:
        raise InvalidScanRequest("scan_id missing")

    if "target" not in scan_request:
        raise InvalidScanRequest("target missing")

def resolve_tools(profile: str) -> List[str]:
    profiles = {
        "quick": ["SAST", "SCA"],
        "web": ["DAST_ZAP", "DAST_SQLMAP"],
        "full": ["SAST", "SCA", "DAST_ZAP", "DAST_SQLMAP"],
    }

    if profile not in profiles:
        raise UnsupportedProfile(f"Unknown profile: {profile}")

    tools = profiles[profile]

    if not tools:
        raise ToolResolutionError("No tools resolved")

    return tools

def create_scan_tasks(scan_id: str, tools: List[str]) -> List[TaskDescriptor]:
    tasks = []

    for tool in tools:
        task_id = _new_task_id(scan_id, tool)

        tasks.append(
            TaskDescriptor(
                task_id=task_id,
                scan_id=scan_id,
                task_type=tool,
                cost_tier=get_cost_tier(tool),
                cost_units=get_cost_units(tool),
                dependencies=frozenset(),
                retries_allowed=_retry_policy(tool),
            )
        )

    return tasks

def create_correlation_task(
    scan_id: str, scan_tasks: List[TaskDescriptor]
) -> TaskDescriptor:
    return TaskDescriptor(
        task_id=_new_task_id(scan_id, "CORRELATION"),
        scan_id=scan_id,
        task_type="CORRELATION",
        cost_tier="POST_PROCESS",
        cost_units=2,
        dependencies=frozenset(t.task_id for t in scan_tasks),
        retries_allowed=1,
    )

def create_ai_task(scan_id: str, parent_task_id: str) -> TaskDescriptor:
    return TaskDescriptor(
        task_id=_new_task_id(scan_id, "AI_SUMMARY"),
        scan_id=scan_id,
        task_type="AI_SUMMARY",
        cost_tier="POST_PROCESS",
        cost_units=3,
        dependencies=frozenset({parent_task_id}),
        retries_allowed=1,
    )

def create_report_task(scan_id: str, parent_task_id: str) -> TaskDescriptor:
    return TaskDescriptor(
        task_id=_new_task_id(scan_id, "REPORT"),
        scan_id=scan_id,
        task_type="REPORT",
        cost_tier="POST_PROCESS",
        cost_units=2,
        dependencies=frozenset({parent_task_id}),
        retries_allowed=0,
    )

def _retry_policy(tool: str) -> int:
    return 1 if tool.startswith("DAST") else 0


def _new_task_id(scan_id: str, name: str) -> str:
    return f"{scan_id}:{name}:{uuid4().hex[:8]}"
