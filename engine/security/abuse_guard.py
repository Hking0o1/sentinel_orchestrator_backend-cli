from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.db import crud


_SENSITIVE_DOMAIN_PATTERNS = [
    re.compile(r"(^|\.)gov(\.[a-z]+)?$", re.IGNORECASE),
    re.compile(r"(^|\.)mil(\.[a-z]+)?$", re.IGNORECASE),
    re.compile(r"(^|\.)bank", re.IGNORECASE),
    re.compile(r"(^|\.)paypal", re.IGNORECASE),
]

_UNSAFE_PATH_MARKERS = {"/admin", "/internal", "/debug", "/private", "/.git", "/actuator"}


@dataclass
class AbuseDecision:
    risk_score: int
    action: str
    reasons: list[str]


class AbuseGuard:
    async def evaluate(
        self,
        db: AsyncSession,
        user_id,
        domain: str | None,
        ip_address: str | None,
        target_url: str | None,
        context: dict[str, Any] | None = None,
    ) -> AbuseDecision:
        context = context or {}
        now = datetime.now(timezone.utc)
        score = 0
        reasons: list[str] = []

        recent_domain_adds = await crud.count_domains_added_since(
            db, user_id=user_id, since=now - timedelta(minutes=15)
        )
        if recent_domain_adds >= 4:
            score += 30
            reasons.append("MULTIPLE_DOMAINS_ADDED_RAPIDLY")

        last_activity = await crud.get_latest_activity_for_user(db, user_id=user_id)
        if last_activity and ip_address and last_activity.ip_address and ip_address != last_activity.ip_address:
            score += 20
            reasons.append("IP_ADDRESS_CHANGED")

        if domain:
            domain_record = await crud.get_domain_record(db, user_id=user_id, domain=domain)
            if domain_record and int(domain_record.failed_verification_attempts or 0) >= 2:
                score += 40
                reasons.append("REPEATED_FAILED_VERIFICATION")

            if any(pattern.search(domain) for pattern in _SENSITIVE_DOMAIN_PATTERNS):
                score += 50
                reasons.append("SENSITIVE_DOMAIN_PATTERN")

        if target_url:
            lowered = target_url.lower()
            if any(marker in lowered for marker in _UNSAFE_PATH_MARKERS):
                score += 70
                reasons.append("POTENTIAL_UNDOCUMENTED_ENDPOINT_PROBING")

        if context.get("manual_risk_points"):
            score += int(context["manual_risk_points"])
            reasons.append("MANUAL_RISK_ADJUSTMENT")

        if score < 50:
            return AbuseDecision(risk_score=score, action="ALLOW", reasons=reasons)
        if score <= 80:
            return AbuseDecision(risk_score=score, action="THROTTLE", reasons=reasons)
        return AbuseDecision(risk_score=score, action="BLOCK", reasons=reasons)
