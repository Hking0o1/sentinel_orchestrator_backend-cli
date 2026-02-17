from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, and_
from uuid import UUID
from datetime import datetime, timezone
from typing import Optional
from app.db.models import User, ScanJob, ScanSchedule, DomainOwnership, ScanActivity
from app.models.user import UserCreate
from app.models.scan import ScanCreate, ScanJobUpdate, ScanStatus
from app.models.schedule import ScanScheduleCreate, ScanScheduleUpdate
from app.models.user import UserUpdate
from app.models.security import DomainStatus, ActivityOutcome
from engine.planner.identity import normalize_target_value
import secrets

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


async def get_due_schedules(db: AsyncSession):
    result = await db.execute(
        select(ScanSchedule).where(ScanSchedule.is_active.is_(True))
    )
    return result.scalars().all()


async def update_user(db: AsyncSession, user_id: UUID, user_in: UserUpdate) -> User:
    """
    Updates a user's profile information.
    """
    db_user = await get_user(db, user_id)
    if not db_user:
        return None
    
    update_data = user_in.model_dump(exclude_unset=True)
    
    if 'password' in update_data and update_data['password']:
        from app.core.security import get_password_hash
        hashed_password = get_password_hash(update_data['password'])
        db_user.hashed_password = hashed_password
        del update_data['password'] # Remove raw password from dict

    for field, value in update_data.items():
        setattr(db_user, field, value)

    await db.commit()
    await db.refresh(db_user)
    return db_user


def normalize_domain(domain_or_url: str) -> str:
    return normalize_target_value("domain", domain_or_url)


def build_domain_verification_value(token: str) -> str:
    return f"sentinel-verification={token}"


async def get_domain_record(
    db: AsyncSession,
    user_id: UUID,
    domain: str,
) -> DomainOwnership | None:
    normalized = normalize_domain(domain)
    result = await db.execute(
        select(DomainOwnership).where(
            and_(
                DomainOwnership.user_id == user_id,
                DomainOwnership.domain == normalized,
            )
        )
    )
    return result.scalar_one_or_none()


async def get_user_domains(db: AsyncSession, user_id: UUID) -> list[DomainOwnership]:
    result = await db.execute(
        select(DomainOwnership)
        .where(DomainOwnership.user_id == user_id)
        .order_by(DomainOwnership.created_at.desc())
    )
    return result.scalars().all()


async def create_or_refresh_domain_record(
    db: AsyncSession,
    user_id: UUID,
    domain: str,
) -> DomainOwnership:
    normalized = normalize_domain(domain)
    existing = await get_domain_record(db, user_id=user_id, domain=normalized)
    token = secrets.token_hex(32)
    if existing:
        existing.verification_token = token
        existing.status = DomainStatus.PENDING
        existing.verified_at = None
    else:
        existing = DomainOwnership(
            user_id=user_id,
            domain=normalized,
            verification_token=token,
            status=DomainStatus.PENDING,
        )
        db.add(existing)

    await db.commit()
    await db.refresh(existing)
    return existing


async def mark_domain_verified(db: AsyncSession, record: DomainOwnership) -> DomainOwnership:
    record.status = DomainStatus.VERIFIED
    record.verified_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(record)
    return record


async def increment_domain_verification_failure(db: AsyncSession, record: DomainOwnership) -> None:
    record.failed_verification_attempts = (record.failed_verification_attempts or 0) + 1
    await db.commit()


async def count_domains_added_since(db: AsyncSession, user_id: UUID, since: datetime) -> int:
    result = await db.execute(
        select(func.count(DomainOwnership.id)).where(
            and_(
                DomainOwnership.user_id == user_id,
                DomainOwnership.created_at >= since,
            )
        )
    )
    return int(result.scalar_one() or 0)


async def count_user_scans_since(db: AsyncSession, user_id: UUID, since: datetime) -> int:
    result = await db.execute(
        select(func.count(ScanJob.id)).where(
            and_(
                ScanJob.owner_id == user_id,
                ScanJob.created_at >= since,
            )
        )
    )
    return int(result.scalar_one() or 0)


async def count_user_active_scans(db: AsyncSession, user_id: UUID) -> int:
    result = await db.execute(
        select(func.count(ScanJob.id)).where(
            and_(
                ScanJob.owner_id == user_id,
                ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
            )
        )
    )
    return int(result.scalar_one() or 0)


async def count_global_active_scans(db: AsyncSession) -> int:
    result = await db.execute(
        select(func.count(ScanJob.id)).where(
            ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING])
        )
    )
    return int(result.scalar_one() or 0)


async def count_domain_deep_scans_since(
    db: AsyncSession,
    user_id: UUID,
    domain: str,
    since: datetime,
) -> int:
    domain = normalize_domain(domain)
    result = await db.execute(
        select(func.count(ScanActivity.id)).where(
            and_(
                ScanActivity.user_id == user_id,
                ScanActivity.domain == domain,
                ScanActivity.scan_type == "full",
                ScanActivity.outcome == ActivityOutcome.ALLOWED,
                ScanActivity.timestamp >= since,
            )
        )
    )
    return int(result.scalar_one() or 0)


async def get_latest_activity_for_user(db: AsyncSession, user_id: UUID) -> ScanActivity | None:
    result = await db.execute(
        select(ScanActivity)
        .where(ScanActivity.user_id == user_id)
        .order_by(ScanActivity.timestamp.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def get_latest_domain_activity_for_user(
    db: AsyncSession,
    user_id: UUID,
    domain: str,
) -> ScanActivity | None:
    domain = normalize_domain(domain)
    result = await db.execute(
        select(ScanActivity)
        .where(
            and_(
                ScanActivity.user_id == user_id,
                ScanActivity.domain == domain,
            )
        )
        .order_by(ScanActivity.timestamp.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def create_scan_activity(
    db: AsyncSession,
    user_id: UUID,
    domain: str | None,
    scan_type: str | None,
    ip_address: str | None,
    risk_score: int,
    outcome: ActivityOutcome,
    reason: str | None = None,
    metadata_json: dict | None = None,
) -> ScanActivity:
    activity = ScanActivity(
        user_id=user_id,
        domain=normalize_domain(domain) if domain else None,
        scan_type=scan_type,
        ip_address=ip_address,
        risk_score=risk_score,
        outcome=outcome,
        reason=reason,
        metadata_json=metadata_json or {},
    )
    db.add(activity)
    await db.commit()
    await db.refresh(activity)
    return activity
