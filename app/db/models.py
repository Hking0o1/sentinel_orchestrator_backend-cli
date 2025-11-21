import uuid
from sqlalchemy import (
    Column, String, Boolean, DateTime, ForeignKey, Text
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base import Base 
from app.models.scan import ScanStatus, ScanProfile, ScanSeverity

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean(), default=True)
    is_admin = Column(Boolean(), default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    scans = relationship("ScanJob", back_populates="owner", cascade="all, delete-orphan")
    schedules = relationship("ScanSchedule", back_populates="owner", cascade="all, delete-orphan")

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