from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from datetime import datetime, timedelta, timezone
import pydantic

# Import the models (from the models file, not defining them here!)
from app.models.scan import (
    ScanCreate, 
    ScanJobStarted, 
    ScanJobSummary, 
    ScanJob,
    ScanFinding
)
from app.models.user import User
from app.core.security import get_current_user
from app.db.session import get_db_session
from app.db import crud

# Celery Imports
from scanner.tasks import run_security_scan
from scanner.tasks import celery_app
from celery.result import AsyncResult

router = APIRouter()

@router.post("/start", response_model=ScanJobStarted, status_code=status.HTTP_202_ACCEPTED)
async def start_a_scan(
    scan_in: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Starts a new security scan.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to start scans."
        )

    print(f"[API] Admin user '{current_user.email}' requested a '{scan_in.profile}' scan.")
    
    # 1. Dispatch to Celery
    try:
        print(f"[API] Dispatching job to Celery worker...")
        task = run_security_scan.delay(
            scan_in.model_dump_json(),
            current_user.email
        )
        job_id = task.id
        print(f"[API] Job accepted by Celery. Job ID: {job_id}")

    except Exception as e:
        print(f"[API ERROR] Failed to dispatch job to Celery/Redis: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to queue scan job. Is the 'worker' service running?"
        )
    
    # 2. Create DB Entry
    try:
        await crud.create_scan_job(
            db=db,
            job_id=job_id,
            scan_in=scan_in,
            owner_id=current_user.id
        )
    except Exception as e:
        print(f"[API ERROR] Failed to save job {job_id} to database: {e}")
        # In production, you might want to revoke the celery task here
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Job queued but database save failed."
        )
    
    return ScanJobStarted(
        job_id=job_id,
        profile=scan_in.profile,
        target_url=scan_in.target_url,
    )

@router.get("/", response_model=List[ScanJobSummary])
async def get_scan_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
    skip: int = 0,
    limit: int = 100
):
    """
    Gets the list of all past and running scans.
    """
    scans = await crud.get_scan_history(
        db, 
        owner_id=current_user.id, 
        skip=skip, 
        limit=limit
    )
    
    # Convert DB models to Pydantic models
    return [
        ScanJobSummary(
            id=scan.id,
            status=scan.status,
            profile=scan.profile,
            target=scan.target_url or scan.source_code_path or "N/A",
            highest_severity=scan.highest_severity,
            created_at=scan.created_at
        ) for scan in scans
    ]

@router.get("/{scan_id}", response_model=ScanJob)
async def get_scan_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Gets the full, detailed report for a single scan.
    """
    # 1. Try DB first
    db_scan = await crud.get_scan_job(db, job_id=scan_id)

    if db_scan:
        # Security Check
        if db_scan.owner_id != current_user.id and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to view this scan."
            )
        return db_scan

    # 2. If not in DB (rare, maybe very recent), try Celery
    task_result = AsyncResult(scan_id, app=celery_app)
    if task_result and task_result.state != 'PENDING':
        # We found it in Celery but not DB (maybe DB save failed or pending)
        # For now, just 404 because we rely on DB for ownership check
        pass

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Scan job {scan_id} not found."
    )