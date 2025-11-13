from fastapi import APIRouter, Depends, HTTPException, status
import pydantic
from app.models.scan import (
    ScanCreate, 
    ScanJobStarted, 
    ScanJobSummary, 
    ScanStatus, 
    ScanSeverity, 
    ScanProfile,
    ScanJob,
    ScanFinding
)
from app.models.user import User
from app.core.security import get_current_user
from typing import List
from datetime import datetime, timedelta, timezone

# --- THIS IS THE FUNCTIONAL PART ---
# We import the Celery app itself and the task result class
from scanner.tasks import celery_app, run_security_scan
from celery.result import AsyncResult
# -----------------------------------

router = APIRouter()

@router.post("/start", response_model=ScanJobStarted, status_code=status.HTTP_202_ACCEPTED)
async def start_a_scan(
    scan_in: ScanCreate,
    current_user: User = Depends(get_current_user) 
):
    """
    Starts a new security scan.
    This endpoint is protected and requires an ADMIN role.
    """
    
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to start scans."
        )

    print(f"[API] Admin user '{current_user.email}' requested a '{scan_in.profile}' scan.")
    print(f"[API] Dispatching job to Celery worker...")
    
    try:
        # Pass arguments positionally to Celery
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
    
    return ScanJobStarted(
        job_id=job_id,
        profile=scan_in.profile,
        target_url=scan_in.target_url,
    )

@router.get("/", response_model=List[ScanJobSummary])
async def get_scan_history(
    current_user: User = Depends(get_current_user)
):
    """
    Gets the list of all past and running scans.
    This is a protected endpoint.
    
    --- MOCK DATA ---
    This endpoint is still MOCKED. A real implementation would
    require a persistent database to list all jobs. The Celery
    result backend is not designed for listing all results.
    """
    print(f"[API] User '{current_user.email}' requested scan history (MOCKED).")
    
    mock_scans = [
        ScanJobSummary(
            id="mock-id-1",
            status=ScanStatus.COMPLETED,
            profile=ScanProfile.WEB,
            target="https://v0-secure-encryption-tool.vercel.app/",
            highest_severity=ScanSeverity.HIGH,
            created_at=datetime.now(timezone.utc) - timedelta(hours=2)
        ),
        ScanJobSummary(
            id="mock-id-2",
            status=ScanStatus.RUNNING,
            profile=ScanProfile.FULL,
            target="http://internal-app.dev",
            highest_severity=ScanSeverity.INFO,
            created_at=datetime.now(timezone.utc) - timedelta(minutes=5)
        ),
    ]
    return mock_scans

# --- THIS ENDPOINT IS NOW 100% REAL ---
@router.get("/{scan_id}", response_model=ScanJob)
async def get_scan_report(
    scan_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Gets the full, detailed report for a single scan.
    This endpoint fetches REAL data from the Celery result backend.
    """
    
    print(f"[API] User '{current_user.email}' requested REAL report for scan: {scan_id}")
    
    # 1. Get the task result from Celery (Redis)
    task_result = AsyncResult(scan_id, app=celery_app)

    # 2. Handle "Not Found" (or a non-mock ID that's not ready)
    if not task_result or (task_result.state == ScanStatus.PENDING and not task_result.info):
         # Also check for our mock ID for development
         if scan_id == "mock-id-1":
             print("[API] Returning MOCK data for mock-id-1")
             return ScanJob(
                 id=scan_id, status=ScanStatus.COMPLETED, profile=ScanProfile.WEB,
                 target_url=pydantic.AnyUrl("https://v0-secure-encryption-tool.vercel.app/"),
                 created_at=datetime.now(timezone.utc) - timedelta(hours=2),
                 completed_at=datetime.now(timezone.utc) - timedelta(hours=1),
                 highest_severity=ScanSeverity.HIGH,
                 findings=[ ScanFinding(severity=ScanSeverity.HIGH, title="[MOCK] ZAP Finding", tool="DAST (ZAP)", details="...")]
             )
         
         raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job {scan_id} not found or has not started."
        )

    # 3. Handle REAL task states
    
    # If the task is still running
    if task_result.state == ScanStatus.RUNNING:
        print(f"[API] Scan {scan_id} is still in progress. Status: {task_result.state}")
        # Return a partial ScanJob object to update the UI
        return ScanJob(
            id=scan_id,
            status=ScanStatus.RUNNING,
            # We can't know these details until it's done, so we use placeholders
            profile=ScanProfile.WEB, 
            created_at=datetime.now(timezone.utc), 
            highest_severity=ScanSeverity.INFO,
            findings=[]
        )

    # If the task failed
    elif task_result.state == ScanStatus.FAILED:
        print(f"[API] Scan {scan_id} has FAILED.")
        # Return a partial ScanJob with the error message
        return ScanJob(
            id=scan_id,
            status=ScanStatus.FAILED,
            profile=ScanProfile.WEB, # Placeholder
            created_at=datetime.now(timezone.utc), # Placeholder
            highest_severity=ScanSeverity.INFO,
            findings=[
                ScanFinding(
                    severity=ScanSeverity.HIGH,
                    title="Scan Job Failed",
                    tool="Celery Worker",
                    # 'task_result.info' contains the exception message
                    details=f"The scan worker failed to execute: {str(task_result.info)}", 
                    remediation="Check the worker logs for the full traceback."
                )
            ]
        )

    # If the task completed successfully
    elif task_result.state == "SUCCESS":
        print(f"[API] Scan {scan_id} is COMPLETE. Returning real data.")
        # The 'task_result.info' (or .get()) is the JSON string
        # we returned from the 'run_security_scan' task.
        scan_job_json = task_result.get()
        
        # Parse the JSON string back into our Pydantic model and return it
        try:
            return ScanJob.model_validate_json(scan_job_json)
        except Exception as e:
            print(f"[API ERROR] Failed to parse successful job result: {e}")
            raise HTTPException(status_code=500, detail="Failed to parse job result.")

    # Fallback for any other state
    print(f"[API] Scan {scan_id} in unknown state: {task_result.state}")
    return ScanJob(
        id=scan_id,
        status=ScanStatus.PENDING,
        profile=ScanProfile.WEB, # Placeholder
        created_at=datetime.now(timezone.utc), # Placeholder
        highest_severity=ScanSeverity.INFO,
        findings=[]
    )