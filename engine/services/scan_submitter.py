from pathlib import Path
import json
import uuid
from typing import Dict, Any

from engine.planner.dag_builder import build_scan_dag
from engine.scheduler.scheduler import ScanScheduler
from config.settings import settings


class ScanSubmissionError(Exception):
    pass


class ScanSubmitter:
    """
    Responsible for:
    - Normalizing scan requests
    - Writing immutable scan metadata
    - Registering DAG with the scheduler
    """

    def __init__(self, scheduler: ScanScheduler):
        self._scheduler = scheduler

        # 🔑 THIS WAS MISSING
        self._meta_dir = Path(settings.SCAN_RESULTS_DIR)
        self._meta_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------
    # Public API
    # -----------------------------
    def submit_scan(self, scan_request: Dict[str, Any]) -> str:
        try:
            scan_id = str(uuid.uuid4())

            normalized = self._normalize_scan_request(scan_request)
            dag = build_scan_dag(normalized)

            # Persist immutable metadata FIRST
            self._write_scan_meta(scan_id, normalized)

            # Register DAG with scheduler
            self._scheduler.register_scan_dag(
                scan_id=scan_id,
                dag=dag,
            )

            return scan_id

        except Exception as exc:
            raise ScanSubmissionError(str(exc)) from exc

    # -----------------------------
    # Internal helpers
    # -----------------------------
    def _normalize_scan_request(self, scan_request: Dict[str, Any]) -> Dict[str, Any]:
        profile = scan_request.get("profile")
        if not profile:
            raise ScanSubmissionError("profile missing")

        normalized: Dict[str, Any] = {
            "profile": profile.lower(),
            "enable_ai": scan_request.get("enable_ai", False),
        }

        if profile.lower() == "web":
            target_url = scan_request.get("target_url")
            if not target_url:
                raise ScanSubmissionError("target_url missing for web scan")

            # 🔑 Keep BOTH canonical + explicit fields
            normalized["target"] = target_url
            normalized["target_url"] = target_url

        else:
            src_path = scan_request.get("source_code_path")
            if not src_path:
                raise ScanSubmissionError("source_code_path missing")

            normalized["src_path"] = src_path

        return normalized

    def _write_scan_meta(self, scan_id: str, normalized_request: Dict[str, Any]) -> None:
        scan_dir = self._meta_dir / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)

        meta_path = scan_dir / "meta.json"

        with meta_path.open("w", encoding="utf-8") as f:
            json.dump(normalized_request, f, indent=2)
