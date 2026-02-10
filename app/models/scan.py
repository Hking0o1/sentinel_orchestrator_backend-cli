import pydantic
from enum import Enum
from datetime import datetime
from typing import Optional, List
from pydantic import ConfigDict, AnyUrl, Field
from pydantic.alias_generators import to_camel
from sqlalchemy import Column, String, DateTime, Integer, ForeignKey, Enum as SQLEnum
from app.db.base import Base
from sqlalchemy.dialects.postgresql import UUID
import uuid
# --- Enums (No changes) ---
class ScanProfile(str, Enum):
    DEVELOPER = "developer"
    WEB = "web"
    FULL = "full"
class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
class ScanSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

# --- Models ---
class ScanCreate(pydantic.BaseModel):
    profile: ScanProfile
    enable_ai: bool = True
    target_url: Optional[AnyUrl] = None
    source_code_path: Optional[str] = None
    auth_cookie: Optional[str] = None
    @pydantic.model_validator(mode='after')
    def validate_dependencies(self) -> 'ScanCreate':
        if self.profile in [ScanProfile.WEB, ScanProfile.FULL] and not self.target_url:
            raise ValueError("A valid 'target_url' is required for 'web' and 'full' profiles.")
        if self.profile in [ScanProfile.DEVELOPER, ScanProfile.FULL] and not self.source_code_path:
            raise ValueError("A 'source_code_path' is required for 'developer' and 'full' profiles.")
        return self

class ScanJobStarted(pydantic.BaseModel):
    job_id: str
    status: ScanStatus = ScanStatus.PENDING
    message: str = "Scan job successfully queued."
    profile: ScanProfile
    target_url: Optional[AnyUrl] = None

class ScanFinding(pydantic.BaseModel):
    severity: ScanSeverity
    title: str
    tool: str
    details: str
    remediation: Optional[str] = None
    location: Optional[str] = None
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, from_attributes=True)

class ScanJob(pydantic.BaseModel):
    id: str
    status: ScanStatus
    profile: ScanProfile
    target_url: Optional[AnyUrl] = None
    source_code_path: Optional[str] = None
    auth_cookie: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    highest_severity: ScanSeverity = ScanSeverity.INFO
    findings: List[ScanFinding] = []
    
    # --- NEW: AI Report Content ---
    ai_report_text: Optional[str] = None
    # ------------------------------

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, from_attributes=True)

class ScanJobSummary(pydantic.BaseModel):
    id: str
    status: ScanStatus
    profile: ScanProfile
    target: str
    highest_severity: ScanSeverity
    created_at: datetime
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, from_attributes=True)

class ScanJobUpdate(pydantic.BaseModel):
    status: ScanStatus
    findings: List[ScanFinding]
    highest_severity: ScanSeverity
    attack_path_analysis: Optional[str] = None
    report_url: Optional[str] = None
    
    # --- NEW: Update with AI text ---
    ai_report_text: Optional[str] = None
    
    
class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target = Column(String, nullable=False)
    profile = Column(SQLEnum(ScanProfile), nullable=False)
    status = Column(SQLEnum(ScanStatus), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
