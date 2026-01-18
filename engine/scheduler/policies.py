# engine/scheduler/policies.py

from __future__ import annotations
from engine.scheduler.types import TaskCostTier


class DefaultSchedulingPolicy:
    """
    Default deterministic scheduling policy.

    Encapsulates how task priority is computed.
    Stateless and side-effect free.
    """

    def compute_priority(
        self,
        *,
        base_priority: int,
        cost_tier: TaskCostTier,
        dependency_ready: bool,
        retry_count: int,
    ) -> int:
        """
        Compute a deterministic priority score.
        Higher score == higher scheduling priority.
        """

        priority = base_priority

        # Dependency readiness is mandatory
        if dependency_ready:
            priority += 50
        else:
            # Effectively unschedulable
            priority -= 1000

        # Cost-tier bias
        if cost_tier == TaskCostTier.LIGHT:
            priority += 30
        elif cost_tier == TaskCostTier.MEDIUM:
            priority += 10
        elif cost_tier == TaskCostTier.HEAVY:
            priority -= 20
        elif cost_tier == TaskCostTier.POST_PROCESS:
            priority += 5

        # Retry penalty (prevents retry storms)
        priority -= retry_count * 15

        return priority
