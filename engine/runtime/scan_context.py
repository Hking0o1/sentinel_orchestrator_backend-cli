from dataclasses import dataclass
from typing import Optional
from app.models.scan import ScanProfile


@dataclass(frozen=True)
class ExecutionScanContext:
    scan_id: str
    profile: ScanProfile

    target_url: Optional[str] = None
    src_path: Optional[str] = None
    auth_cookie: Optional[str] = None
