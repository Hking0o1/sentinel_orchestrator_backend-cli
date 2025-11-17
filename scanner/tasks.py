import pydantic
from celery import Celery
from config.settings import settings
from app.models.scan import ScanCreate, ScanJob, ScanStatus, ScanSeverity, ScanFinding, ScanJobUpdate
from app.db.session import AsyncSessionLocal
from app.db import crud
from datetime import datetime, timezone
import asyncio
from croniter import croniter # <-- NEW: Import croniter

# --- Celery Application Setup ---

# 1. Initialize the Celery app
celery_app = Celery(
    "scanner",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["scanner.tasks"] # Tell Celery to find tasks in this module
)

# 2. Configure Celery
celery_app.conf.update(
    task_track_started=True,
    broker_connection_retry_on_startup=True,
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    
    # --- NEW: CELERY BEAT SCHEDULE ---
    # This defines our periodic task.
    beat_schedule={
        'dispatch-scheduled-scans-every-30-mins': {
            'task': 'scanner.tasks.dispatch_scheduled_scans',
            'schedule': timedelta(minutes=30), # Runs every 30 minutes
        },
    },
    # -----------------------------------
)

# --- Helper function to run async code from a sync Celery task ---
def run_async(async_func):
    """
    A helper function to correctly run an async function
    from within a synchronous Celery task.
    """
    # Fix for newer Python/asyncio versions
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(async_func)

# --- Celery Task Definitions ---

@celery_app.task(bind=True)
def run_security_scan(self, scan_create_json: str, user_email: str, schedule_id: str = None) -> str:
    """
    The main Celery task that runs our entire security scan orchestrator
    AND saves the results back to the database.
    
    Args:
        self: The task itself (bound=True), used to update status.
        scan_create_json: A JSON string of the ScanCreate Pydantic model.
        user_email: The email of the user who started the scan.
        schedule_id: (Optional) The ID of the schedule that triggered this.
    """
    
    # --- 1. Import Dependencies (inside the task) ---
    try:
        from scanner.orchestrator import run_orchestration 
    except ImportError as e:
        print(f"Error importing scanner modules: {e}")
        self.update_state(state='FAILURE', meta={'error': 'Worker import error'})
        raise
        
    print(f"[WORKER] Job {self.request.id} received for user {user_email}")
    self.update_state(state=str(ScanStatus.RUNNING))

    try:
        scan_config = ScanCreate.model_validate_json(scan_create_json)
    except Exception as e:
        print(f"[WORKER] Failed to parse scan config: {e}")
        self.update_state(state=str(ScanStatus.FAILED), meta={'error': 'Invalid scan config'})
        # Create a placeholder ScanJob to return
        scan_result = ScanJob(
            id=self.request.id, status=ScanStatus.FAILED, profile="unknown",
            created_at=datetime.now(timezone.utc), highest_severity=ScanSeverity.INFO
        )
        return scan_result.model_dump_json()

    
    final_status = ScanStatus.COMPLETED
    
    try:
        # --- 2. Run the Orchestration ---
        orchestration_result: dict = run_orchestration(
            job_id=self.request.id,
            profile=scan_config.profile,
            target_url=str(scan_config.target_url) if scan_config.target_url else None,
            source_code_path=scan_config.source_code_path,
            auth_cookie=scan_config.auth_cookie
        )
        
        print(f"[WORKER] Scan job {self.request.id} completed successfully.")
        
        # --- 3. Create the Pydantic model for the results ---
        findings_list = orchestration_result.get('findings', [])
        
        highest_sev = ScanSeverity.INFO
        if findings_list:
            sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
            valid_findings = [f for f in findings_list if f.get('severity') in sev_order]
            if valid_findings:
                highest_sev_str = max(valid_findings, key=lambda f: sev_order.get(f.get('severity'))).get('severity')
                highest_sev = ScanSeverity(highest_sev_str)
        
        scan_results_model = ScanJobUpdate(
            status=ScanStatus.COMPLETED,
            findings=findings_list,
            highest_severity=highest_sev,
            attack_path_analysis=orchestration_result.get('raw_reports', {}).get('AI_Attack_Path_Analysis'),
            report_url=orchestration_result.get('report_url')
        )
        
        final_status = ScanStatus.COMPLETED

    except Exception as e:
        # --- 4. Handle Orchestrator Failure ---
        print(f"[WORKER] Scan job {self.request.id} failed: {e}")
        self.update_state(state=str(ScanStatus.FAILED), meta={'error': str(e)})
        
        scan_results_model = ScanJobUpdate(
            status=ScanStatus.FAILED,
            findings=[
                ScanFinding(
                    severity=ScanSeverity.HIGH,
                    title="Orchestrator Failed",
                    tool="Celery Worker",
                    details=f"The scan orchestrator crashed: {e}",
                    remediation="Check the worker logs for the full traceback."
                )
            ],
            highest_severity=ScanSeverity.HIGH
        )
        final_status = ScanStatus.FAILED

    
    # --- 5. Save Results to Database (The New Step) ---
    async def save_results_to_db():
        """
        An async function to save our results to PostgreSQL.
        """
        print(f"[WORKER] Connecting to DB to save results for job {self.request.id}...")
        async with AsyncSessionLocal() as db:
            try:
                await crud.update_scan_job_results(
                    db=db,
                    job_id=self.request.id,
                    scan_results=scan_results_model
                )
                print(f"[WORKER] Successfully saved results for job {self.request.id} to DB.")
            except Exception as e:
                print(f"[WORKER] CRITICAL ERROR: Failed to save results to DB: {e}")
                
    run_async(save_results_to_db())

    return f"Scan {final_status}. Findings: {len(scan_results_model.findings)}"


# --- NEW: CELERY BEAT TASK ---
@celery_app.task
def dispatch_scheduled_scans():
    """
    This is a periodic task run by Celery Beat.
    It checks the database for active schedules and dispatches them.
    """
    print(f"[BEAT] Running dispatch_scheduled_scans at {datetime.now(timezone.utc)}")
    
    async def _check_and_dispatch():
        async with AsyncSessionLocal() as db:
            try:
                # 1. Get all active schedules from the DB
                schedules = await crud.get_active_schedules(db)
                print(f"[BEAT] Found {len(schedules)} active schedules to check.")
                
                for schedule in schedules:
                    # 2. Check if the schedule is due to run *now*
                    if croniter.is_now(schedule.crontab):
                        print(f"[BEAT] Schedule '{schedule.name}' ({schedule.id}) is due. Dispatching...")
                        
                        # 3. Create the ScanCreate config from the schedule
                        scan_in = ScanCreate(
                            profile=schedule.profile,
                            target_url=schedule.target_url,
                            source_code_path=schedule.source_code_path,
                            auth_cookie=schedule.auth_cookie
                        )
                        
                        # 4. Get the owner's email
                        owner = await crud.get_user(db, user_id=schedule.owner_id)
                        if not owner:
                            print(f"[BEAT] ERROR: Schedule {schedule.id} has no owner. Skipping.")
                            continue
                            
                        # 5. Create the ScanJob in the DB first
                        # (This is the same logic as the API endpoint)
                        try:
                            # 5a. Dispatch the job to Celery
                            task = run_security_scan.delay(
                                scan_in.model_dump_json(),
                                owner.email,
                                str(schedule.id) # Pass the schedule ID
                            )
                            job_id = task.id
                            
                            # 5b. Save the job to our DB, linking it to the schedule
                            await crud.create_scan_job(
                                db=db,
                                job_id=job_id,
                                scan_in=scan_in,
                                owner_id=owner.id,
                                schedule_id=schedule.id # Link the job to its parent
                            )
                            print(f"[BEAT] Dispatched job {job_id} for schedule {schedule.id}.")
                            
                        except Exception as e:
                            print(f"[BEAT] ERROR: Failed to dispatch or save job for schedule {schedule.id}: {e}")
                    
            except Exception as e:
                print(f"[BEAT] CRITICAL ERROR: Failed to query schedules from DB: {e}")

    # Use our helper to run the main async logic
    run_async(_check_and_dispatch())