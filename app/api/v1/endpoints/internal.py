from fastapi import APIRouter, Depends, HTTPException

from app.core.security import get_current_user
from app.models.user import User
from engine.scheduler.runtime import get_scheduler


router = APIRouter()


@router.get("/scheduler/metrics")
async def get_scheduler_metrics(
    current_user: User = Depends(get_current_user),
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    scheduler = get_scheduler()
    return scheduler.get_metrics_snapshot()


@router.get("/scheduler/overview")
async def get_scheduler_overview(
    current_user: User = Depends(get_current_user),
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    scheduler = get_scheduler()
    return scheduler.get_runtime_overview()
