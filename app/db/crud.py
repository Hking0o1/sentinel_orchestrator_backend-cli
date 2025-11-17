from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import delete, update
from uuid import UUID
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from app.db.models import User, ScanJob, ScanSchedule
from app.models.user import UserCreate
# Import all the Pydantic models we need
from app.models.scan import ScanCreate, ScanJobUpdate, ScanStatus
from app.models.schedule import ScanScheduleCreate, ScanScheduleUpdate

# --- User CRUD Functions ---

async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    """
    Fetches a single user from the database by their email address.
    """
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()

async def get_user(db: AsyncSession, user_id: UUID) -> User | None:
    """
    Fetches a single user from the database by their UUID.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()

async def create_user(db: AsyncSession, user_in: UserCreate) -> User:
    """
    Creates a new user in the database.
    - Hashes the password before storing.
    - Commits the transaction.
    - Refreshes the instance to get DB-generated data (like ID, created_at).
    """
    
    # --- We import the function here, inside the
    # method that needs it. This breaks the circular import.
    from app.core.security import get_password_hash
    # ----------------------------------------------------

    # Securely hash the password
    hashed_password = get_password_hash(user_in.password)
    
    # Create the new User database model
    db_user = User(
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=hashed_password,
        is_active=user_in.is_active,
        is_admin=user_in.is_admin
    )
    
    db.add(db_user)
    await db.commit() # Save the new user to the database
    await db.refresh(db_user) # Get the generated ID, created_at, etc.
    return db_user

# --- ScanJob CRUD Functions ---

async def create_scan_job(
    db: AsyncSession, 
    job_id: str, 
    scan_in: ScanCreate, 
    owner_id: UUID,
    schedule_id: Optional[UUID] = None
) -> ScanJob:
    """
    Creates a new scan job entry in the database.
    This is called by the API right after the Celery task is created.
    """
    
    db_scan_job = ScanJob(
        id=job_id,
        owner_id=owner_id,
        status=ScanStatus.PENDING,
        profile=scan_in.profile,
        target_url=str(scan_in.target_url) if scan_in.target_url else None,
        source_code_path=scan_in.source_code_path,
        auth_cookie=scan_in.auth_cookie,
        schedule_id=schedule_id
    )

    db.add(db_scan_job)
    await db.commit()
    await db.refresh(db_scan_job)
    return db_scan_job

async def get_scan_job(db: AsyncSession, job_id: str) -> ScanJob | None:
    """
    Fetches a single scan job from the database by its ID (Celery Task ID).
    """
    result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
    return result.scalar_one_or_none()

async def get_scan_history(db: AsyncSession, owner_id: UUID, skip: int = 0, limit: int = 100) -> list[ScanJob]:
    """
    Fetches a paginated list of all scan jobs for a specific user.
    """
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.owner_id == owner_id)
        .order_by(ScanJob.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()

async def update_scan_job_results(db: AsyncSession, job_id: str, scan_results: ScanJobUpdate) -> ScanJob | None:
    """
    Updates a ScanJob in the database when the Celery worker finishes.
    This function is called by the worker, not the API.
    """
    
    db_scan = await get_scan_job(db, job_id)
    if db_scan:
        # Update all the fields from the ScanJobUpdate model
        db_scan.status = scan_results.status
        # Note: 'findings' is a list of Pydantic models, we must convert
        # them to a dict list for JSONB storage.
        db_scan.findings = [f.model_dump() for f in scan_results.findings]
        db_scan.highest_severity = scan_results.highest_severity
        db_scan.attack_path_analysis = scan_results.attack_path_analysis
        db_scan.report_url = scan_results.report_url
        db_scan.completed_at = datetime.now(timezone.utc)
        
        await db.commit()
        await db.refresh(db_scan)
        
    return db_scan


# --- ScanSchedule CRUD Functions ---

async def get_active_schedules(db: AsyncSession) -> list[ScanSchedule]:
    """
    Fetches all scan schedules that are currently active.
    This is the main function Celery Beat will use.
    """
    result = await db.execute(
        select(ScanSchedule).where(ScanSchedule.is_active == True)
    )
    return result.scalars().all()

async def get_schedules_by_owner(db: AsyncSession, owner_id: UUID) -> list[ScanSchedule]:
    """
    Fetches all scan schedules created by a specific user.
    This is the secure function for the API.
    """
    result = await db.execute(
        select(ScanSchedule)
        .where(ScanSchedule.owner_id == owner_id)
        .order_by(ScanSchedule.name)
    )
    return result.scalars().all()

async def get_scan_schedule_by_id(db: AsyncSession, schedule_id: UUID) -> ScanSchedule | None:
    """
    Fetches a single scan schedule by its ID.
    """
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    return result.scalar_one_or_none()

async def create_scan_schedule(
    db: AsyncSession, 
    owner_id: UUID,
    schedule_in: ScanScheduleCreate # Use the Pydantic model for creation
) -> ScanSchedule:
    """
    Creates a new scan schedule in the database.
    (This will be called by a new API endpoint).
    """
    db_schedule = ScanSchedule(
        name=schedule_in.name,
        description=schedule_in.description,
        crontab=schedule_in.crontab,
        owner_id=owner_id,
        is_active=schedule_in.is_active,
        profile=schedule_in.profile,
        target_url=str(schedule_in.target_url) if schedule_in.target_url else None,
        source_code_path=schedule_in.source_code_path,
        auth_cookie=schedule_in.auth_cookie
    )
    db.add(db_schedule)
    await db.commit()
    await db.refresh(db_schedule)
    return db_schedule

async def update_scan_schedule(
    db: AsyncSession,
    schedule_id: UUID,
    schedule_in: ScanScheduleUpdate
) -> ScanSchedule | None:
    """
    Updates an existing scan schedule.
    """
    db_schedule = await get_scan_schedule_by_id(db, schedule_id)
    if not db_schedule:
        return None
    
    # Get the update data from the Pydantic model
    # .model_dump(exclude_unset=True) is key: it only includes
    # fields that were actually provided by the user.
    update_data = schedule_in.model_dump(exclude_unset=True)
    
    # Update the model fields
    for key, value in update_data.items():
        # Special handling for AnyUrl
        if key == 'target_url' and value is not None:
            value = str(value)
        setattr(db_schedule, key, value)
        
    await db.commit()
    await db.refresh(db_schedule)
    return db_schedule

async def delete_scan_schedule(
    db: AsyncSession,
    schedule_id: UUID
) -> bool:
    """
    Deletes a scan schedule by its ID.
    Returns True if successful, False if not found.
    """
    db_schedule = await get_scan_schedule_by_id(db, schedule_id)
    if not db_schedule:
        return False
        
    await db.delete(db_schedule)
    await db.commit()
    return True