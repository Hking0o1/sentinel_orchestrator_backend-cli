from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from datetime import datetime, timedelta, timezone

from app.models.scan import (
    ScanCreate, 
    ScanJobStarted, 
    ScanJobSummary, 
    ScanJob
)
from app.models.user import User
from app.core.security import get_current_user
from app.db.session import get_db_session
from app.db import crud

# --- Celery Task Import ---
from scanner.tasks import run_security_scan
# ----------------------------

router = APIRouter()

@router.post("/start", response_model=ScanJobStarted, status_code=status.HTTP_202_ACCEPTED)
async def start_a_scan(
    scan_in: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Starts a new security scan.
    This endpoint is protected, requires an ADMIN role,
    dispatches a Celery job, AND creates a record in the database.
    """
    
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to start scans."
        )

    print(f"[API] Admin user '{current_user.email}' requested a '{scan_in.profile}' scan.")
    
    # 1. Dispatch the job to the Celery worker
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
    
    # 2. Create the initial ScanJob record in our database
    try:
        await crud.create_scan_job(
            db=db,
            job_id=job_id,
            scan_in=scan_in,
            owner_id=current_user.id
        )
        print(f"[API] Job {job_id} saved to database with PENDING status.")
    except Exception as e:
        # This is a problem: the job is queued but we couldn't save it.
        # A real-world app would need a compensating transaction.
        print(f"[API ERROR] Failed to save job {job_id} to database: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Job was queued but failed to save to DB. Check logs."
        )
    
    # 3. Return the confirmation to the user
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
    Gets the list of all past and running scans for the current user.
    This endpoint is now 100% database-driven.
    """
    
    print(f"[API] User '{current_user.email}' requested scan history.")
    
    # --- REAL DATABASE LOOKUP ---
    scans = await crud.get_scan_history(
        db, 
        owner_id=current_user.id, 
        skip=skip, 
        limit=limit
    )
    
    # Convert SQLAlchemy models to Pydantic models for the response
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
    This endpoint is now 100% database-driven.
    """
    
    print(f"[API] User '{current_user.email}' requested report for scan: {scan_id}")
    
    # --- REAL DATABASE LOOKUP ---
    # Fetch the job from the database
    db_scan = await crud.get_scan_job(db, job_id=scan_id)

    if db_scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job {scan_id} not found."
        )
        
    # Security Check: Ensure the user owns this scan
    # (or is an admin)
    if db_scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to view this scan."
        )

    # Return the full ScanJob object from the database.
    # FastAPI will automatically convert it using the response_model.
    return db_scan