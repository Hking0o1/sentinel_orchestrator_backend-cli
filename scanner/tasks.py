import pydantic
from celery import Celery
from config.settings import settings
from app.models.scan import ScanCreate, ScanJob, ScanStatus, ScanSeverity, ScanFinding, ScanJobUpdate
# Note: We do NOT import the global engine/session here to avoid loop conflicts
from app.db import crud
from app.services.jira import jira_service
from app.services.notifier import notifier
from datetime import datetime, timedelta, timezone
import asyncio
from croniter import croniter
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

# --- Celery Application Setup ---
celery_app = Celery(
    "scanner",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["scanner.tasks"]
)

celery_app.conf.update(
    task_track_started=True,
    broker_connection_retry_on_startup=True,
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    beat_schedule={
        'dispatch-scheduled-scans-every-30-mins': {
            'task': 'scanner.tasks.dispatch_scheduled_scans',
            'schedule': timedelta(minutes=30), 
        },
    },
)

# --- Helper: Run Async Code ---
def run_async(async_func):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(async_func)

# --- Helper: Create a Fresh DB Session ---
async def get_local_db_session():
    # Create a new engine for this specific task execution
    local_engine = create_async_engine(
        settings.DATABASE_URL,
        pool_pre_ping=True,
    )
    LocalSession = async_sessionmaker(bind=local_engine, expire_on_commit=False)
    session = LocalSession()
    try:
        return session, local_engine
    except Exception:
        await session.close()
        await local_engine.dispose()
        raise

# --- Task 1: The Scanner Executor ---

@celery_app.task(bind=True)
def run_security_scan(self, scan_create_json: str, user_email: str, schedule_id: str = None) -> str:
    # 1. Import Orchestrator
    try:
        from scanner.orchestrator import run_orchestration 
    except ImportError as e:
        self.update_state(state='FAILURE', meta={'error': 'Worker import error'})
        raise
        
    print(f"[WORKER] Job {self.request.id} received for {user_email}")
    self.update_state(state=str(ScanStatus.RUNNING))

    # 2. Parse Configuration
    try:
        scan_config = ScanCreate.model_validate_json(scan_create_json)
    except Exception as e:
        self.update_state(state=str(ScanStatus.FAILED), meta={'error': 'Invalid scan config'})
        return f"Failed to parse config: {e}"

    final_status = ScanStatus.COMPLETED
    
    try:
        # 3. Run Orchestration
        orchestration_result = run_orchestration(
            job_id=self.request.id,
            profile=scan_config.profile,
            target_url=str(scan_config.target_url) if scan_config.target_url else None,
            source_code_path=scan_config.source_code_path,
            auth_cookie=scan_config.auth_cookie
        )
        
        # 4. Process & Validate Findings
        findings_raw = orchestration_result.get('findings', [])
        validated_findings = []
        for f in findings_raw:
            try:
                if 'tool' not in f and 'tool_source' in f: f['tool'] = f['tool_source']
                if 'severity' not in f: f['severity'] = 'INFO'
                validated_findings.append(ScanFinding(**f))
            except Exception as ve:
                print(f"[WORKER] Warning: Skipped invalid finding: {ve}")

        # Calc Severity
        highest_sev = ScanSeverity.INFO
        sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        if validated_findings:
            highest_sev_str = max(validated_findings, key=lambda f: sev_order.get(f.severity.value, 0)).severity
            highest_sev = highest_sev_str

        scan_results_model = ScanJobUpdate(
            status=ScanStatus.COMPLETED,
            findings=validated_findings, 
            highest_severity=highest_sev,
            attack_path_analysis=orchestration_result.get('raw_reports', {}).get('AI_Attack_Path_Analysis'),
            report_url=orchestration_result.get('report_url'),
            ai_report_text=orchestration_result.get('ai_report_text')
        )

    except Exception as e:
        print(f"[WORKER] Scan failed: {e}")
        self.update_state(state=str(ScanStatus.FAILED), meta={'error': str(e)})
        scan_results_model = ScanJobUpdate(
            status=ScanStatus.FAILED,
            findings=[ScanFinding(
                severity=ScanSeverity.HIGH, title="Scan Failed", tool="System",
                details=str(e), remediation="Check logs"
            )],
            highest_severity=ScanSeverity.HIGH
        )
        final_status = ScanStatus.FAILED

    # 5. Save to Database (Thread-Safe)
    async def save_results_to_db():
        session, local_engine = await get_local_db_session()
        try:
            async with session:
                await crud.update_scan_job_results(
                    db=session, 
                    job_id=self.request.id, 
                    scan_results=scan_results_model
                )
                print(f"[WORKER] Saved results for job {self.request.id}")
        except Exception as e:
            print(f"[WORKER] DB Save Failed: {e}")
        finally:
            await local_engine.dispose()
    
    # 6. Run Integrations (Jira & Notifications)
    def run_integrations_sync():
        # A. JIRA
        critical_findings = [
            {
                "title": f.title,
                "description": f.details,
                "priority": f.severity.value,
                "remediation": f.remediation or "Investigate immediately."
            }
            for f in scan_results_model.findings 
            if f.severity == ScanSeverity.CRITICAL or f.severity == ScanSeverity.HIGH
        ]
        
        if critical_findings:
            print(f"[WORKER] Creating {len(critical_findings)} Jira tickets...")
            jira_service.create_tickets(critical_findings)

        # B. NOTIFICATIONS
        total_count = len(validated_findings)
        critical_count = len([f for f in validated_findings if f.severity == ScanSeverity.CRITICAL or f.severity == ScanSeverity.HIGH])
        
        project_name = str(scan_config.target_url) if scan_config.target_url else scan_config.source_code_path
        
        report_link = f"http://localhost:4000/app/scans/{self.request.id}"

        print(f"[WORKER] Sending notification. Findings: {total_count}, Critical: {critical_count}")

        notifier.send_scan_complete(
            project_name=str(project_name),
            status=final_status,
            finding_count=total_count,
            critical_count=critical_count,
            report_url=report_link
        )

    # Execute
    run_async(save_results_to_db())
    run_integrations_sync()

    return f"Scan {final_status}. Findings: {len(scan_results_model.findings)}"


# --- Task 2: The Scheduler Dispatcher ---

@celery_app.task
def dispatch_scheduled_scans():
    print(f"[BEAT] Checking schedules at {datetime.now(timezone.utc)}")
    
    async def _check_and_dispatch():
        session, local_engine = await get_local_db_session()
        try:
            async with session:
                schedules = await crud.get_active_schedules(session)
                
                for schedule in schedules:
                    if croniter.is_now(schedule.crontab):
                        print(f"[BEAT] Dispatching schedule '{schedule.name}' ({schedule.id})")
                        
                        scan_in = ScanCreate(
                            profile=schedule.profile,
                            target_url=schedule.target_url,
                            source_code_path=schedule.source_code_path,
                            auth_cookie=schedule.auth_cookie
                        )
                        
                        owner = await crud.get_user(session, user_id=schedule.owner_id)
                        if not owner: continue
                            
                        try:
                            task = run_security_scan.delay(
                                scan_in.model_dump_json(),
                                owner.email,
                                str(schedule.id)
                            )
                            
                            await crud.create_scan_job(
                                db=session,
                                job_id=task.id,
                                scan_in=scan_in,
                                owner_id=owner.id,
                                schedule_id=schedule.id
                            )
                        except Exception as e:
                            print(f"[BEAT] Dispatch failed for {schedule.id}: {e}")
        except Exception as e:
             print(f"[BEAT] Error: {e}")
        finally:
            await local_engine.dispose()

    run_async(_check_and_dispatch())