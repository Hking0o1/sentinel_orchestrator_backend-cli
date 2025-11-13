import pydantic
from celery import Celery
from config.settings import settings
from app.models.scan import ScanCreate, ScanJob, ScanStatus, ScanSeverity
from datetime import datetime, timezone

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
)

# --- Celery Task Definition ---

@celery_app.task(bind=True)
def run_security_scan(self, scan_create_json: str, user_email: str) -> str:
    """
    The main Celery task that runs our entire security scan orchestrator.
    
    Args:
        self: The task itself (bound=True), used to update status.
        scan_create_json: A JSON string of the ScanCreate Pydantic model.
        user_email: The email of the user who started the scan.
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
        print(f"[WORKK_E_R] Failed to parse scan config: {e}")
        self.update_state(state=str(ScanStatus.FAILED), meta={'error': 'Invalid scan config'})
        # We must create a placeholder ScanJob to return
        scan_result = ScanJob(
            id=self.request.id, status=ScanStatus.FAILED, profile="unknown",
            created_at=datetime.now(timezone.utc), highest_severity=ScanSeverity.INFO
        )
        return scan_result.model_dump_json()

    try:
        # --- 3. Run the Orchestration ---
        #
        # --- THE FIX IS HERE ---
        # We now pass 'self.request.id' as the first argument,
        # which matches the definition in orchestrator.py
        #
        orchestration_result: dict = run_orchestration(
            job_id=self.request.id,
            profile=scan_config.profile,
            target_url=str(scan_config.target_url) if scan_config.target_url else None,
            source_code_path=scan_config.source_code_path,
            auth_cookie=None # We'll add this later
        )
        
        # --- 4. Report Success ---
        print(f"[WORKER] Scan job {self.request.id} completed successfully.")
        
        findings_list = orchestration_result.get('findings', [])
        highest_sev = ScanSeverity.INFO
        if findings_list:
            sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
            # Ensure severity is valid before getting max
            valid_findings = [f for f in findings_list if f.get('severity') in sev_order]
            if valid_findings:
                highest_sev_str = max(valid_findings, key=lambda f: sev_order.get(f.get('severity'))).get('severity')
                highest_sev = ScanSeverity(highest_sev_str)
            
        scan_result = ScanJob(
            id=self.request.id,
            status=ScanStatus.COMPLETED,
            profile=scan_config.profile,
            target_url=scan_config.target_url,
            source_code_path=scan_config.source_code_path,
            created_at=orchestration_result.get('start_time', datetime.now(timezone.utc).isoformat()),
            completed_at=datetime.now(timezone.utc),
            highest_severity=highest_sev,
            findings=findings_list
        )
        
        return scan_result.model_dump_json()

    except Exception as e:
        # --- 5. Handle Failure ---
        print(f"[WORKER] Scan job {self.request.id} failed: {e}")
        self.update_state(state=str(ScanStatus.FAILED), meta={'error': str(e)})
        
        scan_result = ScanJob(
            id=self.request.id,
            status=ScanStatus.FAILED,
            profile=scan_config.profile,
            target_url=scan_config.target_url,
            source_code_path=scan_config.source_code_path,
            created_at=datetime.now(timezone.utc),
            highest_severity=ScanSeverity.INFO,
            findings=[]
        )
        return scan_result.model_dump_json()