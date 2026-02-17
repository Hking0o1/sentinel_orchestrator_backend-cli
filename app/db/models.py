import uuid
from sqlalchemy import (
    Column, String, Boolean, DateTime, ForeignKey, Text, Integer, Enum as SQLEnum, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base import Base 
from app.models.scan import ScanStatus, ScanProfile, ScanSeverity
from app.models.security import DomainStatus, TrustTier, ActivityOutcome

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean(), default=True)
    is_admin = Column(Boolean(), default=False)
    trust_tier = Column(
        SQLEnum(TrustTier, name="trust_tier_enum"),
        nullable=False,
        default=TrustTier.NEW,
        server_default=TrustTier.NEW.value,
    )
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    scans = relationship("ScanJob", back_populates="owner", cascade="all, delete-orphan")
    schedules = relationship("ScanSchedule", back_populates="owner", cascade="all, delete-orphan")
    domains = relationship("DomainOwnership", back_populates="owner", cascade="all, delete-orphan")
    scan_activity = relationship("ScanActivity", back_populates="owner", cascade="all, delete-orphan")

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(String(36), primary_key=True, index=True)
    status = Column(String(50), nullable=False, default=ScanStatus.PENDING)
    profile = Column(String(50), nullable=False)
    target_url = Column(String, nullable=True)
    source_code_path = Column(String, nullable=True)
    auth_cookie = Column(Text, nullable=True)
    highest_severity = Column(String(50), nullable=False, default=ScanSeverity.INFO)
    findings = Column(JSONB, nullable=True, default=[])
    
    # Legacy PDF URL (optional now)
    report_url = Column(String, nullable=True)
    
    # --- NEW: Store the raw AI report content ---
    ai_report_text = Column(Text, nullable=True)
    # -------------------------------------------

    attack_path_analysis = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    owner = relationship("User", back_populates="scans")
    
    schedule_id = Column(UUID(as_uuid=True), ForeignKey("scan_schedules.id"), nullable=True)
    schedule = relationship("ScanSchedule", back_populates="jobs")

class ScanSchedule(Base):
    __tablename__ = "scan_schedules"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean(), default=True)
    crontab = Column(String(100), nullable=False) 
    profile = Column(String(50), nullable=False)
    target_url = Column(String, nullable=True)
    source_code_path = Column(String, nullable=True)
    auth_cookie = Column(Text, nullable=True)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    owner = relationship("User", back_populates="schedules")
    jobs = relationship("ScanJob", back_populates="schedule")


class DomainOwnership(Base):
    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("user_id", "domain", name="uq_domains_user_domain"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    domain = Column(String, nullable=False, index=True)
    verification_token = Column(String(128), nullable=False)
    status = Column(
        SQLEnum(DomainStatus, name="domain_status_enum"),
        nullable=False,
        default=DomainStatus.PENDING,
        server_default=DomainStatus.PENDING.value,
    )
    failed_verification_attempts = Column(Integer, nullable=False, default=0, server_default="0")
    verified_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    owner = relationship("User", back_populates="domains")


class ScanActivity(Base):
    __tablename__ = "scan_activity"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    domain = Column(String, nullable=True, index=True)
    scan_type = Column(String(50), nullable=True)
    ip_address = Column(String(64), nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False, default=0, server_default="0")
    outcome = Column(
        SQLEnum(ActivityOutcome, name="activity_outcome_enum"),
        nullable=False,
    )
    reason = Column(String(200), nullable=True)
    metadata_json = Column(JSONB, nullable=True, default={})

    owner = relationship("User", back_populates="scan_activity")
