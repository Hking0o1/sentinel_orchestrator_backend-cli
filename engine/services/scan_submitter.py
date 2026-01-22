from typing import Dict, Any
import uuid

from engine.planner.dag_builder import build_scan_dag
from engine.scheduler.scheduler import ScanScheduler


class ScanSubmissionError(Exception):
    """Raised when a scan cannot be submitted."""


class ScanSubmitter:
    """
    Phase 1.5 ScanSubmitter

    Responsibilities:
    - Validate incoming scan requests
    - Normalize scan requests into engine-internal format
    - Build execution DAG
    - Register DAG with scheduler

    NON-responsibilities:
    - No filesystem writes
    - No meta.json handling
    - No Celery dispatch
    """

    def __init__(self, scheduler: ScanScheduler):
        self._scheduler = scheduler
        
        
        
    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def submit_scan(self, scan_request: Dict[str, Any]) -> str:
        """
        Submit a scan into the engine.

        Returns:
            scan_id (str)
        """
        try:
            normalized = self._normalize_request(scan_request)

            scan_id = normalized["scan_id"]

            dag = build_scan_dag(normalized)
            print(
                    ">>> ScanSubmitter:",
                    "scan_id =", scan_id,
                    "| task_ids =", [t.task_id for t in dag],
                )
            
            # Register with scheduler
            self._scheduler.register_scan_dag(
                scan_id=scan_id,
                dag=dag,
            )
            print(">>> ScanSubmitter: DAG registered")
            
            return scan_id

        except Exception as exc:
            raise ScanSubmissionError(str(exc)) from exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _normalize_request(self, scan_request: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(scan_request, dict):
            raise ValueError("scan_request must be a dictionary")

        normalized = dict(scan_request)

        # --------------------------------------------------
        # scan_id (engine-owned)
        # --------------------------------------------------
        if not normalized.get("scan_id"):
            normalized["scan_id"] = str(uuid.uuid4())

        # --------------------------------------------------
        # profile
        # --------------------------------------------------
        
        profile = scan_request.get("profile")
        if not profile:
            raise ValueError("scan_request missing 'profile'")

        profile = profile.lower()
        normalized["profile"] = profile
        print(profile)
        # --------------------------------------------------
        # TARGET NORMALIZATION (CRITICAL FIX)
        # --------------------------------------------------
        targets = scan_request.get("targets", {})

        if profile == "WEB":
            target_url = (
                targets.get("target_url")
                or scan_request.get("target_url")
                or scan_request.get("target")
            )

            if not target_url:
                raise ValueError("web scan requires 'target_url'")

            normalized["target_url"] = target_url
        elif profile != "WEB":
            src_path = (
                normalized.get("source_code_path")
                or normalized.get("repo_path")
            )

            if not src_path:
                raise ValueError("non-web scan requires source path")

            normalized["source_code_path"] = src_path
            targets["repo"] = src_path

        normalized["targets"] = targets

        # --------------------------------------------------
        # defaults
        # --------------------------------------------------
        normalized.setdefault("enable_ai", False)

        return normalized

