import asyncio
from types import SimpleNamespace

from app.models.scan import ScanProfile
from app.models.security import TrustTier
from engine.security.abuse_guard import AbuseGuard
from engine.security.rate_limiter import RateLimiter


def test_abuse_guard_blocks_high_risk(monkeypatch):
    guard = AbuseGuard()

    async def _count_domains(*_args, **_kwargs):
        return 5

    async def _last_activity(*_args, **_kwargs):
        return SimpleNamespace(ip_address="10.0.0.1")

    async def _domain_record(*_args, **_kwargs):
        return SimpleNamespace(failed_verification_attempts=3)

    monkeypatch.setattr("engine.security.abuse_guard.crud.count_domains_added_since", _count_domains)
    monkeypatch.setattr("engine.security.abuse_guard.crud.get_latest_activity_for_user", _last_activity)
    monkeypatch.setattr("engine.security.abuse_guard.crud.get_domain_record", _domain_record)

    decision = asyncio.run(
        guard.evaluate(
            db=None,
            user_id="u1",
            domain="example.gov",
            ip_address="10.0.0.2",
            target_url="https://example.gov/internal",
        )
    )
    assert decision.action == "BLOCK"
    assert decision.risk_score > 80


def test_abuse_guard_throttles_medium_risk(monkeypatch):
    guard = AbuseGuard()

    async def _count_domains(*_args, **_kwargs):
        return 1

    async def _last_activity(*_args, **_kwargs):
        return None

    async def _domain_record(*_args, **_kwargs):
        return SimpleNamespace(failed_verification_attempts=0)

    monkeypatch.setattr("engine.security.abuse_guard.crud.count_domains_added_since", _count_domains)
    monkeypatch.setattr("engine.security.abuse_guard.crud.get_latest_activity_for_user", _last_activity)
    monkeypatch.setattr("engine.security.abuse_guard.crud.get_domain_record", _domain_record)

    decision = asyncio.run(
        guard.evaluate(
            db=None,
            user_id="u1",
            domain="bank.example.com",
            ip_address="10.0.0.2",
            target_url=None,
        )
    )
    assert decision.action == "THROTTLE"
    assert 50 <= decision.risk_score <= 80


def test_rate_limiter_rejects_suspended_user():
    limiter = RateLimiter()
    decision = asyncio.run(
        limiter.evaluate(
            db=None,
            user_id="u1",
            trust_tier=TrustTier.SUSPENDED,
            domain="example.com",
            profile=ScanProfile.WEB,
        )
    )
    assert decision.allowed is False
    assert decision.reason == "USER_SUSPENDED"
