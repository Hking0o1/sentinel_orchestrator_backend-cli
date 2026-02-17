from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID

import pydantic
from pydantic import ConfigDict
from pydantic.alias_generators import to_camel


class DomainStatus(str, Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"


class TrustTier(str, Enum):
    NEW = "NEW"
    VERIFIED = "VERIFIED"
    TRUSTED = "TRUSTED"
    SUSPENDED = "SUSPENDED"


class ActivityOutcome(str, Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    THROTTLED = "THROTTLED"


class DomainCreateRequest(pydantic.BaseModel):
    domain: str


class DomainVerifyRequest(pydantic.BaseModel):
    domain: str


class DomainVerificationInstruction(pydantic.BaseModel):
    verification_type: str = "DNS_TXT"
    record_name: str = "@"
    record_value: str
    domain: str
    is_verified: bool
    verification_required: bool = True
    can_scan: bool


class DomainDnsTxtSetupResponse(pydantic.BaseModel):
    domain: str
    status: DomainStatus
    is_verified: bool
    can_scan: bool
    verification: DomainVerificationInstruction
    setup_steps: list[str]


class DomainRead(pydantic.BaseModel):
    id: UUID
    domain: str
    status: DomainStatus
    verified_at: Optional[datetime] = None
    created_at: datetime
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )
