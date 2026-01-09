# engine/services/scan_submitter.py

"""
Scan submission service.

This module is the ONLY entry point for submitting scans
from API or CLI into the Sentinel execution engine.

Responsibilities:
- Validate scan request (lightweight)
- Build execution DAG
- Register DAG with scheduler
- Trigger dispatch loop
"""

from typing import Dict, Any
from uuid import uuid4

from engine.planner.dag_builder import build_scan_dag
from engine.scheduler.scheduler import ScanScheduler
from engine.dispatch.celery_dispatch import CeleryDispatcher


class ScanSubmissionError(Exception):
    """Raised when scan submission fails."""


class ScanSubmitter:
    """
    Stateless service object.

    Safe to reuse across API and CLI.
    """

    def __init__(self, scheduler: ScanScheduler):
        if scheduler is None:
            raise ValueError("scheduler must not be None")

        self._scheduler = scheduler
        self._dispatcher = CeleryDispatcher(scheduler)

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def submit_scan(self, scan_request: Dict[str, Any]) -> str:
        """
        Submit a scan into Sentinel.

        Args:
            scan_request: user-provided scan configuration

        Returns:
            scan_id (str): stable identifier for the scan

        Raises:
            ScanSubmissionError
        """

        try:
            normalized_request = self._normalize_request(scan_request)

            dag = build_scan_dag(normalized_request)

            # Register DAG with scheduler
            self._scheduler.register_dag(
                scan_id=normalized_request["scan_id"],
                tasks=dag,
            )

            # Prime scheduler (mark READY tasks)
            self._scheduler.initialize_ready_tasks(
                scan_id=normalized_request["scan_id"]
            )

            # Trigger one dispatch cycle (non-blocking)
            self._dispatcher.run_once()

            return normalized_request["scan_id"]

        except Exception as exc:
            raise ScanSubmissionError(str(exc)) from exc

    # ------------------------------------------------------------------
    # INTERNAL HELPERS
    # ------------------------------------------------------------------

    def _normalize_request(self, scan_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize and minimally validate incoming scan request.

        We do NOT do deep validation here — API layer handles that.
        """

        if not isinstance(scan_request, dict):
            raise ValueError("scan_request must be a dictionary")

        normalized = dict(scan_request)

        # Ensure scan_id exists and is stable
        if "scan_id" not in normalized or not normalized["scan_id"]:
            normalized["scan_id"] = self._generate_scan_id()

        # Required fields (planner will validate deeper)
        if "target" not in normalized:
            raise ValueError("scan_request missing 'target'")

        # Optional defaults
        normalized.setdefault("profile", "full")
        normalized.setdefault("enable_ai", False)

        return normalized

    def _generate_scan_id(self) -> str:
        """
        Generate a stable, user-visible scan ID.
        """
        return f"scan-{uuid4().hex}"
