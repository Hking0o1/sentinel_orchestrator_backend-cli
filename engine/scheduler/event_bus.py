from collections import deque
from threading import Lock
from typing import Dict, Any

_event_queue = deque()
_lock = Lock()


def publish_event(event: Dict[str, Any]) -> None:
    with _lock:
        _event_queue.append(event)


def drain_events() -> list[Dict[str, Any]]:
    with _lock:
        events = list(_event_queue)
        _event_queue.clear()
        return events
