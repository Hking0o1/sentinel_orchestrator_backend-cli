from typing import List, Dict, Set, FrozenSet
from uuid import uuid4
from engine.scheduler.dag import TaskDescriptor
from engine.planner.cost_model import get_cost_tier, get_cost_units
from engine.planner.exceptions import (
    InvalidScanRequest,
    UnsupportedProfile,
    ToolResolutionError,
)
from app.models.scan import ScanProfile
from engine.scheduler.types import TaskCostTier, TaskIdentity
from scanner.tools.registry import get_tool, has_tool


def build_scan_dag(scan_request: Dict) -> List[TaskDescriptor]:
    """
    Phase 1.5 DAG builder.

    Produces immutable TaskDescriptor objects only.
    No payloads, no execution details.
    """

    _validate_scan_request(scan_request)

    scan_id = scan_request["scan_id"]
    profile = scan_request["profile"]

    tool_tasks = _build_tool_tasks(scan_id, profile)

    tasks: List[TaskDescriptor] = []
    tasks.extend(tool_tasks)

    # -----------------------------
    # Correlation task
    # -----------------------------
    correlation_task = TaskDescriptor(
        task_id=f"{scan_id}:CORRELATION",
        scan_id=scan_id,
        task_type="CORRELATION",
        cost_units=2,
        dependencies=frozenset(t.task_id for t in tool_tasks),
        retries_allowed=1,
    )
    tasks.append(correlation_task)

    # -----------------------------
    # Optional AI task
    # -----------------------------
    last_task_id = correlation_task.task_id

    if scan_request.get("enable_ai", False):
        ai_task = TaskDescriptor(
            task_id=f"{scan_id}:AI_SUMMARY",
            scan_id=scan_id,
            task_type="AI_SUMMARY",
            cost_units=3,
            dependencies=frozenset({last_task_id}),
            retries_allowed=0,
        )
        tasks.append(ai_task)
        last_task_id = ai_task.task_id

    # -----------------------------
    # Report task
    # -----------------------------
    report_task = TaskDescriptor(
        task_id=f"{scan_id}:REPORT",
        scan_id=scan_id,
        task_type="REPORT",
        cost_units=2,
        dependencies=frozenset({last_task_id}),
        retries_allowed=0,
    )
    tasks.append(report_task)

    return tasks


def _build_tool_tasks(scan_id: str, profile: ScanProfile) -> List[TaskDescriptor]:
    """
    Build tool execution tasks based on scan profile.
    """

    profile_tool_map = {
        ScanProfile.WEB: [
            ("DAST_ZAP", 5),
            ("DAST_NIKTO", 3),
        ],
        ScanProfile.DEVELOPER: [
            ("SAST", 3),
            ("SCA", 1),
        ],
        ScanProfile.FULL: [
            ("SAST", 3),
            ("SCA", 1),
            ("DAST_ZAP", 5),
            ("DAST_NIKTO", 3),
        ],
    }

    if profile not in profile_tool_map:
        raise ValueError(f"Unsupported scan profile: {profile}")

    tasks: List[TaskDescriptor] = []

    for tool_type, cost_units in profile_tool_map[profile]:
        tasks.append(
            TaskDescriptor(
                task_id=f"{scan_id}:{tool_type}",
                scan_id=scan_id,
                task_type=tool_type,
                cost_units=cost_units,
                dependencies=frozenset(),
                retries_allowed=2,
            )
        )

    return tasks


def _validate_scan_request(scan_request: Dict) -> None:
    if not isinstance(scan_request, dict):
        raise ValueError("scan_request must be a dict")

    if "scan_id" not in scan_request:
        raise ValueError("scan_id missing")

    if "profile" not in scan_request:
        raise ValueError("profile missing")

    if "targets" not in scan_request or not scan_request["targets"]:
        raise ValueError("targets missing or empty")


def create_correlation_task(
    scan_id: str, scan_tasks: List[TaskDescriptor]
) -> TaskDescriptor:
    return TaskDescriptor(
        task_id=_new_task_id(scan_id, "CORRELATION"),
        scan_id=scan_id,
        task_type="CORRELATION",
        cost_units=2,
        dependencies=frozenset(t.task_id for t in scan_tasks),
        retries_allowed=1,
    )

def create_ai_task(scan_id: str, parent_task_id: str) -> TaskDescriptor:
    return TaskDescriptor(
        task_id=_new_task_id(scan_id, "AI_SUMMARY"),
        scan_id=scan_id,
        task_type="AI_SUMMARY",
        cost_units=3,
        dependencies=frozenset({parent_task_id}),
        retries_allowed=1,
    )

def create_report_task(scan_id: str, parent_task_id: str) -> TaskDescriptor:
    return TaskDescriptor(
        task_id=_new_task_id(scan_id, "REPORT"),
        scan_id=scan_id,
        task_type="REPORT",
        cost_units=2,
        dependencies=frozenset({parent_task_id}),
        retries_allowed=0,
    )

def _retry_policy(tool: str) -> int:
    return 1 if tool.startswith("DAST") else 0


def _new_task_id(scan_id: str, name: str) -> str:
    return f"{scan_id}:{name}:{uuid4().hex[:8]}"
