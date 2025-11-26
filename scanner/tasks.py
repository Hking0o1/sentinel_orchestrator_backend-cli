import pydantic
import os
from celery import Celery
from config.settings import settings
from app.models.scan import ScanCreate, ScanJob, ScanStatus, ScanSeverity, ScanFinding, ScanJobUpdate
from app.db.session import AsyncSessionLocal, engine
from app.db import crud
from datetime import datetime, timedelta, timezone
import asyncio
from croniter import croniter
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.core.storage import storage

celery_app = Celery("scanner", broker=settings.REDIS_URL, backend=settings.REDIS_URL, include=["scanner.tasks"])
celery_app.conf.update(task_track_started=True, broker_connection_retry_on_startup=True, task_serializer='json', result_serializer='json', accept_content=['json'], beat_schedule={'dispatch-scheduled-scans-every-30-mins': {'task': 'scanner.tasks.dispatch_scheduled_scans', 'schedule': timedelta(minutes=30)}})

def run_async(async_func):
    try: return asyncio.run(async_func)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(async_func)

async def get_local_db_session():
    local_engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
    LocalSession = async_sessionmaker(bind=local_engine, expire_on_commit=False)
    session = LocalSession()
    try: return session, local_engine
    except Exception: await session.close(); await local_engine.dispose(); raise

@celery_app.task(bind=True)
def run_security_scan(self, scan_create_json: str, user_email: str, schedule_id: str = None) -> str:
    try: from scanner.orchestrator import run_orchestration 
    except ImportError as e: self.update_state(state='FAILURE', meta={'error': 'Worker import error'}); raise
    print(f"[WORKER] Job {self.request.id} received.")
    self.update_state(state=str(ScanStatus.RUNNING))

    try: scan_config = ScanCreate.model_validate_json(scan_create_json)
    except Exception as e: self.update_state(state=str(ScanStatus.FAILED), meta={'error': 'Invalid scan config'}); return f"Failed to parse config: {e}"

    final_status = ScanStatus.COMPLETED
    try:
        orchestration_result = run_orchestration(
            job_id=self.request.id, profile=scan_config.profile, target_url=str(scan_config.target_url) if scan_config.target_url else None,
            source_code_path=scan_config.source_code_path, auth_cookie=scan_config.auth_cookie
        )
        report_local_path = orchestration_result.get('report_url')
        report_s3_url = None
        
        if report_local_path and os.path.exists(report_local_path):
            print(f"[WORKER] Uploading report to MinIO...")
         
            report_s3_url = storage.upload_file(
                report_local_path, 
                object_name=f"{self.request.id}/report.pdf"
            )
        findings_raw = orchestration_result.get('findings', [])
        validated_findings = []
        for f in findings_raw:
            try:
                if 'tool' not in f and 'tool_source' in f: f['tool'] = f['tool_source']
                if 'severity' not in f: f['severity'] = 'INFO'
                validated_findings.append(ScanFinding(**f))
            except Exception: pass

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
            report_url=report_s3_url ,
            ai_report_text=orchestration_result.get('ai_report_text')
        )
        
    except Exception as e:
        print(f"[WORKER] Scan failed: {e}")
        self.update_state(state=str(ScanStatus.FAILED), meta={'error': str(e)})
        scan_results_model = ScanJobUpdate(status=ScanStatus.FAILED, findings=[], highest_severity=ScanSeverity.HIGH)
        final_status = ScanStatus.FAILED

    async def save_results_to_db():
        session, local_engine = await get_local_db_session()
        try:
            async with session:
                await crud.update_scan_job_results(db=session, job_id=self.request.id, scan_results=scan_results_model)
                print(f"[WORKER] Saved results for job {self.request.id}")
        except Exception as e: print(f"[WORKER] DB Save Failed: {e}")
        finally: await local_engine.dispose()
                
    run_async(save_results_to_db())
    return f"Scan {final_status}"

@celery_app.task
def dispatch_scheduled_scans():
    print(f"[BEAT] Checking schedules at {datetime.now(timezone.utc)}")
    
    async def _check_and_dispatch():
        # Create a fresh, local session for the scheduler task
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