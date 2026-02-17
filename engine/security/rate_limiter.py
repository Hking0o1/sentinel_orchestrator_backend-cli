from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.db import crud
from app.models.scan import ScanProfile
from app.models.security import TrustTier
from config.settings import settings


@dataclass
class RateLimitDecision:
    allowed: bool
    reason: str | None = None


class RateLimiter:
    async def evaluate(
        self,
        db: AsyncSession,
        user_id,
        trust_tier: TrustTier,
        domain: str | None,
        profile: ScanProfile,
    ) -> RateLimitDecision:
        if trust_tier == TrustTier.SUSPENDED:
            return RateLimitDecision(allowed=False, reason="USER_SUSPENDED")

        max_user_concurrent = {
            TrustTier.NEW: settings.SECURITY_MAX_CONCURRENT_NEW,
            TrustTier.VERIFIED: settings.SECURITY_MAX_CONCURRENT_VERIFIED,
            TrustTier.TRUSTED: settings.SECURITY_MAX_CONCURRENT_TRUSTED,
        }.get(trust_tier, settings.SECURITY_MAX_CONCURRENT_NEW)

        user_active = await crud.count_user_active_scans(db, user_id=user_id)
        if user_active >= max_user_concurrent:
            return RateLimitDecision(allowed=False, reason="USER_CONCURRENT_LIMIT")

        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        user_per_hour = await crud.count_user_scans_since(db, user_id=user_id, since=one_hour_ago)
        if user_per_hour >= settings.SECURITY_MAX_SCANS_PER_HOUR:
            return RateLimitDecision(allowed=False, reason="USER_HOURLY_LIMIT")

        global_active = await crud.count_global_active_scans(db)
        if global_active >= settings.SECURITY_GLOBAL_ACTIVE_SCAN_CAP:
            return RateLimitDecision(allowed=False, reason="GLOBAL_ACTIVE_SCAN_CAP")

        if domain:
            latest_domain_activity = await crud.get_latest_domain_activity_for_user(
                db, user_id=user_id, domain=domain
            )
            if latest_domain_activity and latest_domain_activity.timestamp:
                elapsed = datetime.now(timezone.utc) - latest_domain_activity.timestamp
                if elapsed.total_seconds() < settings.SECURITY_DOMAIN_COOLDOWN_SECONDS:
                    return RateLimitDecision(allowed=False, reason="DOMAIN_COOLDOWN_WINDOW")

            if profile == ScanProfile.FULL:
                day_ago = datetime.now(timezone.utc) - timedelta(days=1)
                deep_count = await crud.count_domain_deep_scans_since(
                    db, user_id=user_id, domain=domain, since=day_ago
                )
                if deep_count >= settings.SECURITY_MAX_DEEP_SCANS_PER_DOMAIN_PER_DAY:
                    return RateLimitDecision(allowed=False, reason="DOMAIN_DEEP_SCAN_DAILY_LIMIT")

        return RateLimitDecision(allowed=True)
