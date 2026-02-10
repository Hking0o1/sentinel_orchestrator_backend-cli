import json
import logging
from collections import deque
from threading import Lock
from typing import Dict, Any

import redis

from config.settings import settings

logger = logging.getLogger(__name__)

_EVENT_QUEUE = deque()
_LOCK = Lock()
_EVENT_LIST_KEY = "sentinel:scheduler:events"
_redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)


def publish_event(event: Dict[str, Any]) -> None:
    """
    Cross-process event publish via Redis.
    Falls back to in-memory queue if Redis is unavailable.
    """
    try:
        _redis_client.rpush(_EVENT_LIST_KEY, json.dumps(event))
        return
    except Exception:
        logger.exception("Failed to publish scheduler event to Redis; using memory fallback")

    with _LOCK:
        _EVENT_QUEUE.append(event)


def drain_events() -> list[Dict[str, Any]]:
    """
    Cross-process event drain via Redis.
    Includes in-memory fallback drain.
    """
    events: list[Dict[str, Any]] = []

    try:
        while True:
            payload = _redis_client.lpop(_EVENT_LIST_KEY)
            if payload is None:
                break
            events.append(json.loads(payload))
    except Exception:
        logger.exception("Failed to drain scheduler events from Redis; using memory fallback")

    with _LOCK:
        if _EVENT_QUEUE:
            events.extend(_EVENT_QUEUE)
            _EVENT_QUEUE.clear()

    return events
