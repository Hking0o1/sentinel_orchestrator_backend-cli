from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID
from engine.scheduler.runtime import get_scheduler
from engine.services.scan_submitter import ScanSubmitter
from engine.security import AbuseDecision, AbuseGuard, RateLimiter
import logging
from app.models.user import User
from app.models.scan import ScanProfile
from app.models.security import ActivityOutcome, DomainStatus, TrustTier
from app.models.schedule import ScanSchedule, ScanScheduleCreate, ScanScheduleUpdate
from app.core.security import get_current_user
from app.db.session import get_db_session
from app.db import crud
from app.services.security_controls import (
    is_abuse_guard_enabled,
    is_domain_verification_enabled,
    is_rate_limiting_enabled,
)

router = APIRouter()
logger = logging.getLogger(__name__)
abuse_guard = AbuseGuard()
rate_limiter = RateLimiter()
_SHARED_PLATFORM_SUFFIXES = (".vercel.app", ".netlify.app")


def _profile_value(profile: str | ScanProfile) -> str:
    if hasattr(profile, "value"):
        return str(profile.value).lower()
    raw = str(profile).strip()
    if "." in raw:
        raw = raw.split(".")[-1]
    return raw.lower()


def _resolve_trust_tier(raw_tier) -> TrustTier:
    if isinstance(raw_tier, TrustTier):
        return raw_tier
    try:
        return TrustTier(str(raw_tier))
    except Exception:
        return TrustTier.NEW

@router.post(
    "/",
    response_model=ScanSchedule,
    status_code=status.HTTP_201_CREATED
)
async def create_new_scan_schedule(
    schedule_in: ScanScheduleCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Create a new scan schedule in the database.
    This endpoint is protected and requires an ADMIN role.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to create schedules."
        )
    
    # The 'owner_id' is the ID of the user creating the schedule
    new_schedule = await crud.create_scan_schedule(
        db=db,
        owner_id=current_user.id,
        schedule_in=schedule_in
    )
    return new_schedule

@router.get(
    "/",
    response_model=List[ScanSchedule]
)
async def get_all_schedules_for_user(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get all scan schedules created by the currently authenticated user.
    """
    schedules = await crud.get_schedules_by_owner(db, owner_id=current_user.id)
    return schedules

@router.get(
    "/{schedule_id}",
    response_model=ScanSchedule
)
async def get_schedule_by_id(
    schedule_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get a specific scan schedule by its ID.
    Ensures the user owns the schedule.
    """
    schedule = await crud.get_scan_schedule_by_id(db, schedule_id=schedule_id)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found."
        )
    if schedule.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to view this schedule."
        )
    return schedule

@router.put(
    "/{schedule_id}",
    response_model=ScanSchedule
)
async def update_existing_scan_schedule(
    schedule_id: UUID,
    schedule_in: ScanScheduleUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Update a scan schedule's properties.
    Ensures the user owns the schedule.
    """
    # First, ensure it exists and the current user can access it.
    await get_schedule_by_id(
        schedule_id=schedule_id,
        current_user=current_user,
        db=db,
    )
    
    # Now, update it
    updated_schedule = await crud.update_scan_schedule(
        db=db,
        schedule_id=schedule_id,
        schedule_in=schedule_in
    )
    return updated_schedule

@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT
)
async def delete_existing_scan_schedule(
    schedule_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Delete a scan schedule.
    Ensures the user owns the schedule.
    """
    # First, ensure it exists and the current user can access it.
    await get_schedule_by_id(
        schedule_id=schedule_id,
        current_user=current_user,
        db=db,
    )
    
    # Now, delete it
    await crud.delete_scan_schedule(db, schedule_id=schedule_id)
    return

@router.post("/internal/dispatch-due")
async def dispatch_due_schedules(
    db: AsyncSession = Depends(get_db_session),
):
    """
    INTERNAL endpoint.
    Triggered by Celery Beat.
    """

    scheduler = get_scheduler()
    submitter = ScanSubmitter(scheduler)

    schedules = await crud.get_due_schedules(db)

    count = 0
    for sched in schedules:
        profile_value = _profile_value(sched.profile)
        owner = await crud.get_user(db, user_id=sched.owner_id)
        if not owner:
            continue
        trust_tier = _resolve_trust_tier(getattr(owner, "trust_tier", TrustTier.NEW))
        if trust_tier == TrustTier.SUSPENDED:
            await crud.create_scan_activity(
                db=db,
                user_id=sched.owner_id,
                domain=crud.normalize_domain(sched.target_url) if sched.target_url else None,
                scan_type=profile_value,
                ip_address="scheduler",
                risk_score=100,
                outcome=ActivityOutcome.BLOCKED,
                reason="USER_SUSPENDED",
            )
            continue

        if profile_value == ScanProfile.FULL.value and trust_tier != TrustTier.TRUSTED:
            await crud.create_scan_activity(
                db=db,
                user_id=sched.owner_id,
                domain=crud.normalize_domain(sched.target_url) if sched.target_url else None,
                scan_type=profile_value,
                ip_address="scheduler",
                risk_score=0,
                outcome=ActivityOutcome.BLOCKED,
                reason="TRUST_TIER_RESTRICTED_SCAN_DEPTH",
            )
            continue

        target_domain = crud.normalize_domain(sched.target_url) if sched.target_url else None
        if target_domain and target_domain.endswith(_SHARED_PLATFORM_SUFFIXES) and profile_value == ScanProfile.FULL.value:
            await crud.create_scan_activity(
                db=db,
                user_id=sched.owner_id,
                domain=target_domain,
                scan_type=profile_value,
                ip_address="scheduler",
                risk_score=0,
                outcome=ActivityOutcome.BLOCKED,
                reason="SHARED_PLATFORM_DOMAIN_RESTRICTED",
            )
            continue
        if target_domain and is_domain_verification_enabled():
            domain_record = await crud.get_domain_record(
                db=db,
                user_id=sched.owner_id,
                domain=target_domain,
            )
            if not domain_record or domain_record.status != DomainStatus.VERIFIED:
                await crud.create_scan_activity(
                    db=db,
                    user_id=sched.owner_id,
                    domain=target_domain,
                    scan_type=profile_value,
                    ip_address="scheduler",
                    risk_score=0,
                    outcome=ActivityOutcome.BLOCKED,
                    reason="DOMAIN_NOT_VERIFIED",
                )
                continue

        if is_abuse_guard_enabled():
            abuse_decision = await abuse_guard.evaluate(
                db=db,
                user_id=sched.owner_id,
                domain=target_domain,
                ip_address="scheduler",
                target_url=sched.target_url,
            )
            if abuse_decision.action != "ALLOW":
                await crud.create_scan_activity(
                    db=db,
                    user_id=sched.owner_id,
                    domain=target_domain,
                    scan_type=profile_value,
                    ip_address="scheduler",
                    risk_score=abuse_decision.risk_score,
                    outcome=ActivityOutcome.BLOCKED if abuse_decision.action == "BLOCK" else ActivityOutcome.THROTTLED,
                    reason=f"ABUSE_RISK_{abuse_decision.action}",
                    metadata_json={"reasons": abuse_decision.reasons},
                )
                continue
        else:
            abuse_decision = AbuseDecision(risk_score=0, action="ALLOW", reasons=[])

        if is_rate_limiting_enabled():
            rate_decision = await rate_limiter.evaluate(
                db=db,
                user_id=sched.owner_id,
                trust_tier=trust_tier,
                domain=target_domain,
                profile=ScanProfile(profile_value) if profile_value in {p.value for p in ScanProfile} else ScanProfile.DEVELOPER,
            )
            if not rate_decision.allowed:
                await crud.create_scan_activity(
                    db=db,
                    user_id=sched.owner_id,
                    domain=target_domain,
                    scan_type=profile_value,
                    ip_address="scheduler",
                    risk_score=abuse_decision.risk_score,
                    outcome=ActivityOutcome.THROTTLED,
                    reason=rate_decision.reason,
                )
                continue

        targets = {}
        if sched.target_url:
            targets["target_url"] = sched.target_url
        if sched.source_code_path:
            targets["source_code_path"] = sched.source_code_path

        submitter.submit_scan(
            {
                "scan_id": str(sched.id),
                "profile": profile_value,
                "targets": targets,
                "auth_cookie": sched.auth_cookie,
            }
        )
        await crud.create_scan_activity(
            db=db,
            user_id=sched.owner_id,
            domain=target_domain,
            scan_type=profile_value,
            ip_address="scheduler",
            risk_score=abuse_decision.risk_score,
            outcome=ActivityOutcome.ALLOWED,
            reason="SCHEDULED_SCAN_ACCEPTED",
        )
        count += 1

    logger.info("Dispatched %d scheduled scans", count)

    return {"dispatched": count}
