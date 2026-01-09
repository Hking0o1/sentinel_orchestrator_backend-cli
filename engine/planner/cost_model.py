# engine/planner/cost_model.py

"""
Cost & resource model for Sentinel.

Cost is declared by tools themselves via metadata.
Planner only resolves it.
"""

from typing import Dict
import importlib

# -------------------------
# COST TIERS (GLOBAL POLICY)
# -------------------------

COST_TIERS: Dict[str, int] = {
    "LIGHT": 10,
    "MEDIUM": 20,
    "HEAVY": 40,
    "POST_PROCESS": 60,
}

DEFAULT_TIER = "MEDIUM"
DEFAULT_UNITS = 3

# engine/planner/cost_model.py

"""
Cost & resource model for Sentinel.

Cost is declared by tools themselves via metadata.
Planner only resolves it.
"""

from typing import Dict
import importlib

# -------------------------
# COST TIERS (GLOBAL POLICY)
# -------------------------

COST_TIERS: Dict[str, int] = {
    "LIGHT": 10,
    "MEDIUM": 20,
    "HEAVY": 40,
    "POST_PROCESS": 60,
}

DEFAULT_TIER = "MEDIUM"
DEFAULT_UNITS = 3


def resolve_task_cost(task_type: str) -> tuple[str, int]:
    """
    Resolve (tier, units) for a task type.

    Order:
    1. Tool-declared metadata
    2. Plugin-declared metadata
    3. Safe defaults
    """

    metadata = _load_tool_cost_metadata(task_type)

    if not metadata:
        return DEFAULT_TIER, DEFAULT_UNITS

    tier = metadata.get("tier", DEFAULT_TIER)
    units = metadata.get("units", DEFAULT_UNITS)

    if tier not in COST_TIERS:
        tier = DEFAULT_TIER

    if not isinstance(units, int) or units <= 0:
        units = DEFAULT_UNITS

    return tier, units

def _load_tool_cost_metadata(task_type: str) -> Dict | None:
    """
    Attempt to load COST_METADATA from a tool module.

    Works for:
    - scanner.tools.*
    - scanner.ai.*
    - scanner.correlation.*
    - plugins
    """

    module_paths = [
        f"scanner.tools.{task_type.lower()}",
        f"scanner.ai.{task_type.lower()}",
        f"scanner.correlation.{task_type.lower()}",
        f"scanner.plugins.custom.{task_type.lower()}",
    ]

    for module_path in module_paths:
        try:
            module = importlib.import_module(module_path)
        except ModuleNotFoundError:
            continue

        return getattr(module, "COST_METADATA", None)

    return None


def get_cost_tier(task_type: str) -> str:
    tier, _ = resolve_task_cost(task_type)
    return tier


def get_cost_units(task_type: str) -> int:
    _, units = resolve_task_cost(task_type)
    return units
