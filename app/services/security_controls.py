from __future__ import annotations

from config.settings import settings


def is_domain_verification_enabled() -> bool:
    return bool(settings.SECURITY_ENABLE_DOMAIN_VERIFICATION)


def is_abuse_guard_enabled() -> bool:
    return bool(settings.SECURITY_ENABLE_ABUSE_GUARD)


def is_rate_limiting_enabled() -> bool:
    return bool(settings.SECURITY_ENABLE_RATE_LIMITING)
