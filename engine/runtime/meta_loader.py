import json
from pathlib import Path
from engine.runtime.scan_context import ExecutionScanContext
from app.models.scan import ScanProfile

SCAN_ROOT = Path("/app/scan_results")


def load_execution_context(scan_id: str) -> ExecutionScanContext:
    meta_path = SCAN_ROOT / scan_id / "meta.json"
    if not meta_path.exists():
        raise RuntimeError(f"meta.json missing for scan {scan_id}")

    with open(meta_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return ExecutionScanContext(
        scan_id=data["scan_id"],
        profile=ScanProfile(data["profile"]),
        target_url=data.get("target_url"),
        src_path=data.get("src_path"),
        auth_cookie=data.get("auth_cookie"),
    )
