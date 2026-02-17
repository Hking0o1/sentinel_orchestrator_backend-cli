from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.endpoints import domains, scans
from app.core.security import get_current_user
from app.db.session import get_db_session
from app.models.security import DomainStatus, TrustTier
from app.models.user import User


def _build_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(domains.router, prefix="/api/v1/domains")
    app.include_router(scans.router, prefix="/api/v1/scans")
    return app


async def _dummy_db_session():
    yield SimpleNamespace()


def _user(*, trust_tier: TrustTier = TrustTier.NEW) -> User:
    return User(
        id=uuid4(),
        email="tester@example.com",
        full_name="Tester",
        is_active=True,
        is_admin=False,
        trust_tier=trust_tier,
    )


def test_domains_register_returns_frontend_clarity_flags(monkeypatch):
    app = _build_test_app()
    app.dependency_overrides[get_db_session] = _dummy_db_session
    app.dependency_overrides[get_current_user] = lambda: _user()

    async def _create_or_refresh_domain_record(*_args, **_kwargs):
        return SimpleNamespace(
            id=uuid4(),
            domain="example.com",
            verification_token="abc123",
            status=DomainStatus.PENDING,
            verified_at=None,
            created_at=datetime.now(timezone.utc),
        )

    monkeypatch.setattr(domains.crud, "create_or_refresh_domain_record", _create_or_refresh_domain_record)

    with TestClient(app) as client:
        response = client.post("/api/v1/domains/", json={"domain": "example.com"})

    assert response.status_code == 201
    payload = response.json()
    assert payload["verification_type"] == "DNS_TXT"
    assert payload["record_name"] == "@"
    assert payload["domain"] == "example.com"
    assert payload["verification_required"] is True
    assert payload["can_scan"] is False
    assert payload["is_verified"] is False
    assert payload["record_value"].startswith("sentinel-verification=")


def test_domains_frontend_setup_endpoint_returns_steps(monkeypatch):
    app = _build_test_app()
    app.dependency_overrides[get_db_session] = _dummy_db_session
    app.dependency_overrides[get_current_user] = lambda: _user()

    async def _create_or_refresh_domain_record(*_args, **_kwargs):
        return SimpleNamespace(
            id=uuid4(),
            domain="example.com",
            verification_token="abc123",
            status=DomainStatus.PENDING,
            verified_at=None,
            created_at=datetime.now(timezone.utc),
        )

    monkeypatch.setattr(domains.crud, "create_or_refresh_domain_record", _create_or_refresh_domain_record)

    with TestClient(app) as client:
        response = client.post("/api/v1/domains/example.com/dns-txt/setup")

    assert response.status_code == 200
    payload = response.json()
    assert payload["domain"] == "example.com"
    assert payload["is_verified"] is False
    assert payload["can_scan"] is False
    assert len(payload["setup_steps"]) >= 3
    assert payload["verification"]["record_value"].startswith("sentinel-verification=")


def test_scans_start_rejects_unverified_domain(monkeypatch):
    app = _build_test_app()
    app.dependency_overrides[get_db_session] = _dummy_db_session
    app.dependency_overrides[get_current_user] = lambda: _user(trust_tier=TrustTier.TRUSTED)

    async def _create_scan_activity(*_args, **_kwargs):
        return None

    async def _get_domain_record(*_args, **_kwargs):
        return None

    monkeypatch.setattr(scans.crud, "create_scan_activity", _create_scan_activity)
    monkeypatch.setattr(scans.crud, "get_domain_record", _get_domain_record)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans/start",
            json={"profile": "web", "target_url": "https://example.com"},
        )

    assert response.status_code == 403
    assert "not verified" in response.json()["detail"].lower()


def test_scans_start_rejects_full_scan_for_non_trusted(monkeypatch):
    app = _build_test_app()
    app.dependency_overrides[get_db_session] = _dummy_db_session
    app.dependency_overrides[get_current_user] = lambda: _user(trust_tier=TrustTier.NEW)

    async def _create_scan_activity(*_args, **_kwargs):
        return None

    monkeypatch.setattr(scans.crud, "create_scan_activity", _create_scan_activity)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans/start",
            json={
                "profile": "full",
                "target_url": "https://example.com",
                "source_code_path": ".",
            },
        )

    assert response.status_code == 403
    assert "trust tier" in response.json()["detail"].lower()
