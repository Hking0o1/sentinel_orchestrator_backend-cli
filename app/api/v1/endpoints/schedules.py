from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID

from app.models.user import User
from app.models.schedule import ScanSchedule, ScanScheduleCreate, ScanScheduleUpdate
from app.core.security import get_current_user
from app.db.session import get_db_session
from app.db import crud

router = APIRouter()

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
    # First, get the schedule to ensure it exists and we can check ownership
    schedule = await get_schedule_by_id(db, schedule_id=schedule_id, current_user=current_user)
    
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
    # First, get the schedule to ensure it exists and we can check ownership
    schedule = await get_schedule_by_id(db, schedule_id=schedule_id, current_user=current_user)
    
    # Now, delete it
    await crud.delete_scan_schedule(db, schedule_id=schedule_id)
    return