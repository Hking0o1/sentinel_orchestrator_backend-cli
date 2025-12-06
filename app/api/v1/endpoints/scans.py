from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
import pydantic
import os
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
from typing import List
from datetime import datetime, timedelta, timezone

from scanner.tasks import celery_app, run_security_scan
from celery.result import AsyncResult

router = APIRouter()

# ... (start_a_scan, get_scan_history, get_scan_report endpoints remain the same) ...

@router.post("/start", response_model=ScanJobStarted, status_code=status.HTTP_202_ACCEPTED)
async def start_a_scan(
    scan_in: ScanCreate,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db_session)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    print(f"[API] Admin user '{current_user.email}' requested a '{scan_in.profile}' scan.")
    
    try:
        task = run_security_scan.delay(scan_in.model_dump_json(), current_user.email)
        job_id = task.id
    except Exception as e:
        print(f"[API ERROR] Failed to dispatch: {e}")
        raise HTTPException(status_code=503, detail="Failed to queue scan job.")
    
    try:
        await crud.create_scan_job(db=db, job_id=job_id, scan_in=scan_in, owner_id=current_user.id)
    except Exception as e:
        print(f"[API ERROR] DB Save failed: {e}")
        raise HTTPException(status_code=500, detail="Job queued but DB failed.")
    
    return ScanJobStarted(job_id=job_id, profile=scan_in.profile, target_url=scan_in.target_url)

@router.get("/", response_model=List[ScanJobSummary])
async def get_scan_history(
    current_user: User = Depends(get_current_user),
    db = Depends(get_db_session),
    skip: int = 0, 
    limit: int = 100
):
    scans = await crud.get_scan_history(db, owner_id=current_user.id, skip=skip, limit=limit)
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
    db = Depends(get_db_session)
):
    db_scan = await crud.get_scan_job(db, job_id=scan_id)
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    if db_scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    return db_scan

# --- FIX: Improved Download Endpoint with Debugging ---
@router.get("/{scan_id}/download")
async def download_scan_pdf(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db_session)
):
    """
    Downloads the PDF report for a specific scan.
    """
    # 1. Get the scan from DB
    db_scan = await crud.get_scan_job(db, job_id=scan_id)
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # 2. Check permissions
    if db_scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # 3. Check if the file path exists
    file_path = db_scan.report_url
    
    print(f"[API DEBUG] Requested download for Scan {scan_id}")
    print(f"[API DEBUG] DB report_url: {file_path}")

    # Fallback logic: if report_url is None or wrong, try to construct it
    if not file_path:
        # Default location based on our orchestrator logic
        potential_path = f"/app/scan_results/{scan_id}/Gemini_Security_Report.pdf"
        print(f"[API DEBUG] report_url was null. Trying default: {potential_path}")
        file_path = potential_path

    if not os.path.exists(file_path):
        print(f"[API ERROR] File NOT found at: {file_path}")
        # Check if directory exists at all
        dir_path = os.path.dirname(file_path)
        if os.path.exists(dir_path):
            print(f"[API DEBUG] Directory exists. Listing contents of {dir_path}:")
            print(os.listdir(dir_path))
        else:
            print(f"[API DEBUG] Directory does NOT exist: {dir_path}")

        raise HTTPException(status_code=404, detail="PDF report file not found on server.")
        
    # 4. Return the file
    print(f"[API DEBUG] File found! Serving: {file_path}")
    return FileResponse(
        path=file_path, 
        filename=f"Sentinel_Report_{scan_id}.pdf", 
        media_type='application/pdf'
    )

@router.get("/findings/all", response_model=List[ScanFinding])
async def get_all_vulnerabilities(
    current_user: User = Depends(get_current_user),
    db = Depends(get_db_session),
    limit: int = 500
):
    """
    Aggregates findings from the user's recent scans.
    This provides a global view of vulnerabilities.
    """
    # 1. Fetch recent completed scans
    # We re-use get_scan_history but request more items
    scans = await crud.get_scan_history(db, owner_id=current_user.id, limit=50)
    
    all_findings = []
    
    for scan in scans:
        if scan.status == 'COMPLETED' and scan.findings:
            # We iterate through the JSONB list
            for finding_dict in scan.findings:
                # We optionally inject the target name into the location for context
                # (This helps the user know WHICH app has the vulnerability)
                target_name = scan.target_url or scan.source_code_path or "Unknown"
                
                # Create a copy to avoid mutating the DB object in memory
                f = finding_dict.copy()
                
                # Prepend target to location if it exists
                original_loc = f.get('location') or ""
                f['location'] = f"[{target_name}] {original_loc}"
                
                all_findings.append(f)
    
    # Sort by severity (Critical first)
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: sev_order.get(x.get('severity', 'INFO'), 5))
    
    return all_findings[:limit]