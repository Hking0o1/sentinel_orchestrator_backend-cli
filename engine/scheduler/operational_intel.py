from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


class OperationalIntelligence:
    """
    Passive observability layer for scheduler decisions and runtime health.
    """

    def __init__(self, *, base_dir: str):
        self._base_dir = Path(base_dir)
        self._lock = threading.Lock()
        self._timeline: dict[str, dict[str, dict[str, str | None]]] = defaultdict(dict)

    def emit_event(
        self,
        *,
        scan_id: str,
        task_id: str,
        event_type: str,
        cost_tier: str,
        reason: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        payload = {
            "timestamp": _utc_now_iso(),
            "scan_id": scan_id,
            "task_id": task_id,
            "event_type": event_type,
            "cost_tier": cost_tier,
            "reason": reason,
            "context": _to_json_safe(context or {}),
        }
        self._append_jsonl(scan_id=scan_id, filename="scheduler_events.jsonl", payload=payload)

    def emit_alert(
        self,
        *,
        scan_id: str,
        level: str,
        alert_type: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        payload = {
            "timestamp": _utc_now_iso(),
            "scan_id": scan_id,
            "level": level,
            "type": alert_type,
            "context": _to_json_safe(context or {}),
        }
        self._append_jsonl(scan_id=scan_id, filename="alerts.jsonl", payload=payload)

    def mark_task_timestamp(self, *, scan_id: str, task_id: str, field: str, value: str | None) -> None:
        if field not in {
            "admitted_at",
            "ready_at",
            "dispatched_at",
            "running_at",
            "completed_at",
        }:
            return
        with self._lock:
            task_tl = self._timeline[scan_id].setdefault(
                task_id,
                {
                    "admitted_at": None,
                    "ready_at": None,
                    "dispatched_at": None,
                    "running_at": None,
                    "completed_at": None,
                },
            )
            task_tl[field] = value
            self._persist_timeline(scan_id)

    def dump_scheduler_snapshot(self, *, scan_id: str, snapshot: dict[str, Any]) -> None:
        self._append_jsonl(
            scan_id=scan_id,
            filename="alerts.jsonl",
            payload={
                "timestamp": _utc_now_iso(),
                "scan_id": scan_id,
                "level": "CRITICAL",
                "type": "SCHEDULER_SNAPSHOT",
                "context": _to_json_safe(snapshot),
            },
        )

    def _append_jsonl(self, *, scan_id: str, filename: str, payload: dict[str, Any]) -> None:
        try:
            path = self._base_dir / scan_id / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                with path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(payload, ensure_ascii=False))
                    f.write("\n")
        except Exception:
            logger.exception("Failed to persist scheduler operational artifact | file=%s", filename)

    def _persist_timeline(self, scan_id: str) -> None:
        payload = {
            "scan_id": scan_id,
            "generated_at_utc": _utc_now_iso(),
            "tasks": self._timeline.get(scan_id, {}),
        }
        path = self._base_dir / scan_id / "timeline.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _to_json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_json_safe(v) for v in value]
    return str(value)
