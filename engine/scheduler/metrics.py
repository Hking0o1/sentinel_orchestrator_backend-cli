import time
from collections import defaultdict
from collections import deque
from threading import Lock
from typing import Dict, List, Any


class SchedulerMetrics:
    """
    Scheduler-owned metrics collector.

    Used for:
    - benchmarks
    - health monitoring
    - research evaluation
    """

    def __init__(self):
        self._lock = Lock()
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, int] = {}
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.timestamps: Dict[str, float] = {}
        self.maps: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._completion_events: deque[float] = deque(maxlen=10000)

    # ---- counters ----
    def inc(self, name: str, value: int = 1) -> None:
        with self._lock:
            self.counters[name] += value
            if name == "tasks_completed_total" and value > 0:
                now = time.monotonic()
                for _ in range(value):
                    self._completion_events.append(now)

    # ---- gauges ----
    def set_gauge(self, name: str, value: int) -> None:
        with self._lock:
            self.gauges[name] = value

    def set_map(self, name: str, value: Dict[str, int]) -> None:
        with self._lock:
            self.maps[name] = dict(value)

    # ---- histograms ----
    def observe(self, name: str, value: float) -> None:
        with self._lock:
            self.histograms[name].append(value)

    # ---- timestamps ----
    def mark_time(self, key: str) -> None:
        with self._lock:
            self.timestamps[key] = time.monotonic()

    def elapsed_since(self, key: str) -> float:
        with self._lock:
            start = self.timestamps.get(key)
        if start is None:
            return 0.0
        return time.monotonic() - start

    def snapshot(self) -> Dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            while self._completion_events and now - self._completion_events[0] > 60.0:
                self._completion_events.popleft()

            task_latency = self.histograms.get("task_latency_seconds", [])
            avg_latency = (sum(task_latency) / len(task_latency)) if task_latency else 0.0

            return {
                "ready_queue_size": self.gauges.get("ready_queue_size", 0),
                "in_flight_count": self.gauges.get("in_flight_tasks", 0),
                "tasks_completed_total": self.counters.get("tasks_completed_total", 0),
                "tasks_failed_total": self.counters.get("tasks_failed_total", 0),
                "average_task_latency": round(avg_latency, 6),
                "tokens_in_use_per_tier": self.maps.get(
                    "tokens_in_use_per_tier",
                    {"LIGHT": 0, "MEDIUM": 0, "HEAVY": 0, "POST_PROCESS": 0},
                ),
                "blocked_due_to_resource_total": self.counters.get("tasks_blocked_total", 0),
                "completion_rate_per_minute": len(self._completion_events),
            }
