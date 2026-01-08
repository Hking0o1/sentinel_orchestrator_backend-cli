import time
from collections import defaultdict
from typing import Dict, List


class SchedulerMetrics:
    """
    Scheduler-owned metrics collector.

    Used for:
    - benchmarks
    - health monitoring
    - research evaluation
    """

    def __init__(self):
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, int] = {}
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.timestamps: Dict[str, float] = {}

    # ---- counters ----
    def inc(self, name: str, value: int = 1) -> None:
        self.counters[name] += value

    # ---- gauges ----
    def set_gauge(self, name: str, value: int) -> None:
        self.gauges[name] = value

    # ---- histograms ----
    def observe(self, name: str, value: float) -> None:
        self.histograms[name].append(value)

    # ---- timestamps ----
    def mark_time(self, key: str) -> None:
        self.timestamps[key] = time.monotonic()

    def elapsed_since(self, key: str) -> float:
        start = self.timestamps.get(key)
        if start is None:
            return 0.0
        return time.monotonic() - start
