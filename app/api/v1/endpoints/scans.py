from uuid import uuid4
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.models.scan import Scan, ScanCreate
from app.core.security import get_current_user

from engine.services.scan_submitter import ScanSubmitter, ScanSubmissionError
from engine.scheduler.runtime import get_scheduler
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/start", status_code=status.HTTP_202_ACCEPTED)
async def start_scan(
    scan_in: ScanCreate,
    db: AsyncSession = Depends(get_db_session),
    current_user=Depends(get_current_user),
):
    targets: Dict[str, str] = {}

    if scan_in.target_url:
        targets["target_url"] = str(scan_in.target_url)

    if scan_in.source_code_path:
        targets["source_code_path"] = scan_in.source_code_path

    if not targets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid scan target provided",
        )

    scan_id = uuid4()

    display_target = (
        targets.get("target_url")
        or targets.get("source_code_path")
    )

    scan = Scan(
        id=scan_id,
        target=display_target,
        profile=scan_in.profile,
        status="PENDING",
        user_id=current_user.id,
    )

    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    scheduler = get_scheduler()
    submitter = ScanSubmitter(scheduler)

    try:
        submitter.submit_scan(
            {
                "scan_id": str(scan.id),
                "profile": scan_in.profile,     
                "target": scan.target,         
                "auth_cookie": scan_in.auth_cookie,
            }
        )
    except Exception as exc:
        logger.exception("Scan submission failed")
        scan.status = "FAILED"
        await db.commit()
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )
    return {
        "scan_id": str(scan.id),
        "target": scan.target,
        "profile": scan.profile,
        "status": scan.status,
    }

