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
            scan_id (str)

        Raises:
            ScanSubmissionError
        """
        try:
            normalized_request = self._normalize_request(scan_request)

            # 🔑 DAG builder is the ONLY place where tasks are constructed
            dag = build_scan_dag(scan_request)

            scan_id = normalized_request["scan_id"]

            # Register DAG with scheduler
            self._scheduler.submit_tasks(dag)

            # Initialize READY tasks
            self._scheduler.initialize_ready_tasks()

            # Trigger a single dispatch cycle
            self._dispatcher.run_once()

            return scan_id

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

        # Phase 1.5 canonical requirement: targets
        if "targets" not in normalized or not normalized["targets"]:
            raise ValueError("scan_request missing 'targets'")

        if not isinstance(normalized["targets"], dict):
            raise ValueError("scan_request.targets must be a dict")

        # Optional defaults
        normalized.setdefault("profile", "full")

        return normalized

    def _generate_scan_id(self) -> str:
        """
        Generate a stable, user-visible scan ID.
        """
        return f"scan-{uuid4().hex}"
