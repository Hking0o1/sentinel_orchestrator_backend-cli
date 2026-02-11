from uuid import uuid4
from typing import Dict, List
import os

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.models.scan import ScanCreate, ScanJob, ScanJobSummary, ScanFinding, ScanStatus
from app.core.security import get_current_user
from app.models.user import User
from app.db import crud

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

    scan_id = str(uuid4())

    scheduler = get_scheduler()
    submitter = ScanSubmitter(scheduler)

    scan_request = {
        "scan_id": scan_id,
        "profile": scan_in.profile,
        "targets": targets,
        "auth_cookie": scan_in.auth_cookie,
        "enable_ai": scan_in.enable_ai,
    }

    try:
        submitter.validate_scan_request(scan_request)
    except ScanSubmissionError as exc:
        logger.warning(
            "Scan validation rejected | user_id=%s | reason=%s",
            current_user.id,
            exc.public_message,
        )
        raise HTTPException(
            status_code=exc.status_code,
            detail={
                "message": exc.public_message,
                "code": exc.code,
            },
        )

    try:
        db_scan = await crud.create_scan_job(
            db=db,
            job_id=scan_id,
            scan_in=scan_in,
            owner_id=current_user.id,
        )
    except Exception:
        logger.exception("Failed to create scan job row")
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Unable to create scan record right now. Please try again.",
                "code": "SCAN_RECORD_CREATE_FAILED",
            },
        )

    try:
        submitter.submit_scan(scan_request)
    except ScanSubmissionError as exc:
        logger.warning(
            "Scan submission rejected | user_id=%s | code=%s | reason=%s",
            current_user.id,
            exc.code,
            exc.public_message,
        )
        db_scan.status = ScanStatus.FAILED
        await db.commit()
        raise HTTPException(
            status_code=exc.status_code,
            detail={
                "message": exc.public_message,
                "code": exc.code,
            },
        )
    except Exception:
        logger.exception("Scan submission failed")
        db_scan.status = ScanStatus.FAILED
        await db.commit()
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Unable to queue scan right now. Please try again.",
                "code": "SCAN_SUBMISSION_INTERNAL_ERROR",
            },
        )
    return {
        "scan_id": db_scan.id,
        "job_id": db_scan.id,
        "target": db_scan.target_url or db_scan.source_code_path,
        "profile": db_scan.profile,
        "status": db_scan.status,
    }


@router.get("/", response_model=List[ScanJobSummary])
async def get_scan_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
    skip: int = 0,
    limit: int = 100,
):
    scans = await crud.get_scan_history(
        db,
        owner_id=current_user.id,
        skip=skip,
        limit=limit,
    )
    return [
        ScanJobSummary(
            id=scan.id,
            status=scan.status,
            profile=scan.profile,
            target=scan.target_url or scan.source_code_path or "N/A",
            highest_severity=scan.highest_severity,
            created_at=scan.created_at,
        )
        for scan in scans
    ]


@router.get("/{scan_id}", response_model=ScanJob)
async def get_scan_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    db_scan = await crud.get_scan_job(db, job_id=scan_id)
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if db_scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    return db_scan


@router.get("/{scan_id}/download")
async def download_scan_pdf(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    db_scan = await crud.get_scan_job(db, job_id=scan_id)
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if db_scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    file_path = db_scan.report_url
    if not file_path:
        raise HTTPException(status_code=404, detail="PDF report path not available for this scan.")

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="PDF report file not found on server.")

    return FileResponse(
        path=file_path,
        filename=f"Sentinel_Report_{scan_id}.pdf",
        media_type="application/pdf",
    )


@router.get("/findings/all", response_model=List[ScanFinding])
async def get_all_vulnerabilities(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
    limit: int = 500,
):
    scans = await crud.get_scan_history(db, owner_id=current_user.id, limit=50)

    all_findings = []
    for scan in scans:
        if scan.status == "COMPLETED" and scan.findings:
            for finding_dict in scan.findings:
                target_name = scan.target_url or scan.source_code_path or "Unknown"
                finding = finding_dict.copy()
                original_loc = finding.get("location") or ""
                finding["location"] = f"[{target_name}] {original_loc}"
                all_findings.append(finding)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: sev_order.get(x.get("severity", "INFO"), 5))
    return all_findings[:limit]

