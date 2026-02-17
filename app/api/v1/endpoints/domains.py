from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.db import crud
from app.db.session import get_db_session
from app.models.security import (
    DomainCreateRequest,
    DomainDnsTxtSetupResponse,
    DomainRead,
    DomainVerificationInstruction,
    DomainVerifyRequest,
)
from app.models.user import User
from app.models.security import DomainStatus
from app.services.domain_verification import verify_dns_txt_token
from app.services.security_controls import is_domain_verification_enabled
from config.settings import settings

router = APIRouter()


def _build_dns_setup_response(record) -> DomainDnsTxtSetupResponse:
    record_value = crud.build_domain_verification_value(record.verification_token)
    is_verified = record.status == DomainStatus.VERIFIED
    instruction = DomainVerificationInstruction(
        domain=record.domain,
        record_value=record_value,
        is_verified=is_verified,
        verification_required=is_domain_verification_enabled(),
        can_scan=(is_verified or not is_domain_verification_enabled()),
    )
    return DomainDnsTxtSetupResponse(
        domain=record.domain,
        status=record.status,
        is_verified=is_verified,
        can_scan=(is_verified or not is_domain_verification_enabled()),
        verification=instruction,
        setup_steps=[
            "Add a TXT record at your DNS provider for this domain.",
            "Use '@' as the host/name and paste the exact value returned.",
            "Wait for DNS propagation, then call /api/v1/domains/verify.",
        ],
    )


@router.post("/", response_model=DomainVerificationInstruction, status_code=status.HTTP_201_CREATED)
async def register_domain(
    payload: DomainCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    record = await crud.create_or_refresh_domain_record(
        db=db,
        user_id=current_user.id,
        domain=payload.domain,
    )
    setup = _build_dns_setup_response(record)
    return setup.verification


@router.post("/verify", response_model=DomainRead)
async def verify_domain(
    payload: DomainVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    record = await crud.get_domain_record(db, user_id=current_user.id, domain=payload.domain)
    if not record:
        raise HTTPException(status_code=404, detail="Domain is not registered.")

    expected = crud.build_domain_verification_value(record.verification_token)
    is_verified = await verify_dns_txt_token(
        domain=record.domain,
        expected_record_value=expected,
        timeout_seconds=settings.SECURITY_DNS_TIMEOUT_SECONDS,
    )
    if not is_verified:
        await crud.increment_domain_verification_failure(db, record)
        raise HTTPException(
            status_code=400,
            detail="Verification TXT record not found. Add the record and retry.",
        )

    updated = await crud.mark_domain_verified(db, record)
    return DomainRead.model_validate(updated)


@router.get("/", response_model=list[DomainRead])
async def list_domains(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    rows = await crud.get_user_domains(db, user_id=current_user.id)
    return [DomainRead.model_validate(row) for row in rows]


@router.post("/{domain}/dns-txt/setup", response_model=DomainDnsTxtSetupResponse)
async def setup_dns_txt_for_frontend(
    domain: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Frontend helper endpoint.
    Generates or refreshes TXT verification payload and returns setup metadata/flags.
    """
    record = await crud.create_or_refresh_domain_record(
        db=db,
        user_id=current_user.id,
        domain=domain,
    )
    return _build_dns_setup_response(record)


@router.get("/{domain}/dns-txt/setup", response_model=DomainDnsTxtSetupResponse)
async def get_dns_txt_setup_for_frontend(
    domain: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Read-only frontend helper endpoint for current DNS TXT verification details.
    """
    record = await crud.get_domain_record(db, user_id=current_user.id, domain=domain)
    if not record:
        raise HTTPException(status_code=404, detail="Domain is not registered.")
    return _build_dns_setup_response(record)
