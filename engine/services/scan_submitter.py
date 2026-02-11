from typing import Dict, Any, Optional
import json
from pathlib import Path
from urllib.parse import urlparse
from config.settings import settings
import logging
from engine.planner.dag_builder import build_scan_dag
from engine.scheduler.scheduler import ScanScheduler
from app.models.scan import ScanProfile

logger = logging.getLogger(__name__)
class ScanSubmissionError(Exception):
    """Raised when a scan cannot be submitted."""

    def __init__(
        self,
        message: str,
        *,
        public_message: Optional[str] = None,
        status_code: int = 400,
        code: str = "SCAN_SUBMISSION_FAILED",
    ):
        super().__init__(message)
        self.public_message = public_message or message
        self.status_code = status_code
        self.code = code


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
        self._meta_dir = Path(settings.SCAN_RESULTS_DIR)
        self._meta_dir.mkdir(parents=True, exist_ok=True)
        
        
    def _write_scan_meta(self, scan_id: str, normalized: dict) -> None:
        scan_dir = self._meta_dir / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)

        meta_path = scan_dir / "meta.json"
        if meta_path.exists():
            return

        profile = normalized["profile"]
        if isinstance(profile, ScanProfile):
            profile_value = profile.value
        else:
            profile_value = str(profile).lower()

        meta = {
            "scan_id": scan_id,
            "profile": profile_value,     
            "targets": normalized["targets"],
            "auth_cookie": normalized.get("auth_cookie"),
            "enable_ai": normalized.get("enable_ai", False),
        }

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)


    def validate_scan_request(self, scan_request: dict) -> dict:
        """
        Validate and normalize incoming request without side effects.
        """
        try:
            return self._normalize_request(scan_request)
        except ValueError as exc:
            raise ScanSubmissionError(
                str(exc),
                public_message=str(exc),
                status_code=400,
                code="INVALID_SCAN_REQUEST",
            ) from exc

    
    def submit_scan(self, scan_request: dict) -> None:
        try:
            scan_id = scan_request.get("scan_id")
            if not scan_id:
                raise ValueError("scan_request missing scan_id")

            scan_id = str(scan_id)
            normalized = self.validate_scan_request(scan_request)
            self._write_scan_meta(scan_id, normalized)
            normalized["scan_id"] = scan_id
            dag = build_scan_dag(normalized)
            self._scheduler.register_scan_dag(scan_id, dag)
            logger.info(
                "ScanSubmitter: scan_id=%s | tasks=%s",
                scan_id,
                [t.task_id for t in dag],
            )

        except ScanSubmissionError:
            raise
        except ValueError as exc:
            raise ScanSubmissionError(
                str(exc),
                public_message=str(exc),
                status_code=400,
                code="INVALID_SCAN_REQUEST",
            ) from exc
        except Exception as exc:
            logger.exception("Unexpected scan submission failure")
            raise ScanSubmissionError(
                "Unexpected scan submission failure",
                public_message="Unable to queue scan right now. Please try again.",
                status_code=500,
                code="SCAN_SUBMISSION_INTERNAL_ERROR",
            ) from exc

    @staticmethod
    def _validate_target_url(target_url: str) -> str:
        parsed = urlparse(str(target_url).strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("target_url must be a valid http/https URL")
        return str(target_url).strip()

    @staticmethod
    def _validate_source_path(src_path: str) -> str:
        resolved = Path(str(src_path)).expanduser().resolve()
        if not resolved.exists():
            raise ValueError(f"source_code_path does not exist: {resolved}")
        if not resolved.is_dir():
            raise ValueError(f"source_code_path must be a directory: {resolved}")
        return str(resolved)

    def _normalize_request(self, scan_request: dict) -> dict:
        normalized: dict = {}

        raw_profile = scan_request.get("profile")
        if not raw_profile:
            raise ValueError("scan profile missing")

        if hasattr(raw_profile, "value"):
            profile = raw_profile.value
        else:
            profile = str(raw_profile)

        profile = profile.upper()
        normalized["profile"] = profile

        targets: dict = {}

        incoming_targets = scan_request.get("targets", {})

        if profile == "WEB":
            target_url = (
                incoming_targets.get("target_url")
                or scan_request.get("target_url")
                or scan_request.get("target")
            )

            if not target_url:
                raise ValueError("web scan requires target_url")

            targets["target_url"] = self._validate_target_url(target_url)

        elif profile == "FULL":
            target_url = (
                incoming_targets.get("target_url")
                or scan_request.get("target_url")
            )
            src_path = (
                incoming_targets.get("source_code_path")
                or scan_request.get("source_code_path")
                or scan_request.get("src_path")
            )

            if not target_url:
                raise ValueError("full scan requires target_url")
            if not src_path:
                raise ValueError("full scan requires source path")

            targets["target_url"] = self._validate_target_url(target_url)
            targets["source_code_path"] = self._validate_source_path(src_path)

        else:
            src_path = (
                incoming_targets.get("source_code_path")
                or scan_request.get("source_code_path")
                or scan_request.get("src_path")
            )

            if not src_path:
                raise ValueError("non-web scan requires source path")

            targets["source_code_path"] = self._validate_source_path(src_path)

        normalized["targets"] = targets

        normalized["enable_ai"] = bool(scan_request.get("enable_ai", False))
        normalized["auth_cookie"] = scan_request.get("auth_cookie")

        return normalized
