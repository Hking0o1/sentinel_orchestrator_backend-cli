from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from uuid import UUID
from datetime import datetime, timezone
from typing import Optional, List

from app.db.models import User, ScanJob, ScanSchedule
from app.models.user import UserCreate
from app.models.scan import ScanCreate, ScanJobUpdate, ScanStatus
from app.models.schedule import ScanScheduleCreate, ScanScheduleUpdate

# ... (User functions remain the same) ...
async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()

async def get_user(db: AsyncSession, user_id: UUID) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()

async def create_user(db: AsyncSession, user_in: UserCreate) -> User:
    from app.core.security import get_password_hash
    hashed_password = get_password_hash(user_in.password)
    db_user = User(email=user_in.email, full_name=user_in.full_name, hashed_password=hashed_password, is_active=user_in.is_active, is_admin=user_in.is_admin)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

# --- ScanJob CRUD Functions ---
async def create_scan_job(db: AsyncSession, job_id: str, scan_in: ScanCreate, owner_id: UUID, schedule_id: Optional[UUID] = None) -> ScanJob:
    db_scan_job = ScanJob(
        id=job_id, owner_id=owner_id, status=ScanStatus.PENDING, profile=scan_in.profile,
        target_url=str(scan_in.target_url) if scan_in.target_url else None,
        source_code_path=scan_in.source_code_path, auth_cookie=scan_in.auth_cookie, schedule_id=schedule_id
    )
    db.add(db_scan_job)
    await db.commit()
    await db.refresh(db_scan_job)
    return db_scan_job

async def get_scan_job(db: AsyncSession, job_id: str) -> ScanJob | None:
    result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
    return result.scalar_one_or_none()

async def get_scan_history(db: AsyncSession, owner_id: UUID, skip: int = 0, limit: int = 100) -> list[ScanJob]:
    result = await db.execute(select(ScanJob).where(ScanJob.owner_id == owner_id).order_by(ScanJob.created_at.desc()).offset(skip).limit(limit))
    return result.scalars().all()

async def update_scan_job_results(db: AsyncSession, job_id: str, scan_results: ScanJobUpdate) -> ScanJob | None:
    """
    Updates a ScanJob in the database when the Celery worker finishes.
    """
    db_scan = await get_scan_job(db, job_id)
    if db_scan:
        db_scan.status = scan_results.status
        db_scan.findings = [f.model_dump() for f in scan_results.findings]
        db_scan.highest_severity = scan_results.highest_severity
        db_scan.attack_path_analysis = scan_results.attack_path_analysis
        db_scan.report_url = scan_results.report_url
        
        # --- NEW: Save the AI report text ---
        db_scan.ai_report_text = scan_results.ai_report_text
        # ------------------------------------

        db_scan.completed_at = datetime.now(timezone.utc)
        
        await db.commit()
        await db.refresh(db_scan)
        
    return db_scan

# ... (Schedule functions remain the same) ...
async def get_active_schedules(db: AsyncSession) -> list[ScanSchedule]:
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.is_active == True))
    return result.scalars().all()

async def get_schedules_by_owner(db: AsyncSession, owner_id: UUID) -> list[ScanSchedule]:
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.owner_id == owner_id).order_by(ScanSchedule.name))
    return result.scalars().all()

async def get_scan_schedule_by_id(db: AsyncSession, schedule_id: UUID) -> ScanSchedule | None:
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    return result.scalar_one_or_none()

async def create_scan_schedule(db: AsyncSession, owner_id: UUID, schedule_in: ScanScheduleCreate) -> ScanSchedule:
    db_schedule = ScanSchedule(
        name=schedule_in.name, description=schedule_in.description, crontab=schedule_in.crontab,
        owner_id=owner_id, is_active=schedule_in.is_active, profile=schedule_in.profile,
        target_url=str(schedule_in.target_url) if schedule_in.target_url else None,
        source_code_path=schedule_in.source_code_path, auth_cookie=schedule_in.auth_cookie
    )
    db.add(db_schedule)
    await db.commit()
    await db.refresh(db_schedule)
    return db_schedule

async def update_scan_schedule(db: AsyncSession, schedule_id: UUID, schedule_in: ScanScheduleUpdate) -> ScanSchedule | None:
    db_schedule = await get_scan_schedule_by_id(db, schedule_id)
    if not db_schedule: return None
    update_data = schedule_in.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        if key == 'target_url' and value is not None: value = str(value)
        setattr(db_schedule, key, value)
    await db.commit()
    await db.refresh(db_schedule)
    return db_schedule

async def delete_scan_schedule(db: AsyncSession, schedule_id: UUID) -> bool:
    db_schedule = await get_scan_schedule_by_id(db, schedule_id)
    if not db_schedule: return False
    await db.delete(db_schedule)
    await db.commit()
    return True