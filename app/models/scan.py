import pydantic
from enum import Enum
from datetime import datetime
from typing import Optional, List
from pydantic import ConfigDict, AnyUrl
from pydantic.alias_generators import to_camel

# --- Enums for categorical, controlled values ---

class ScanProfile(str, Enum):
    """
    Defines the allowed scan profiles.
    """
    DEVELOPER = "developer"
    WEB = "web"
    FULL = "full"

class ScanStatus(str, Enum):
    """
    Defines the lifecycle of a scan job.
    """
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class ScanSeverity(str, Enum):
    """
    Defines the severity levels for vulnerabilities.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

# --- API Request Models (Data from Client) ---

class ScanCreate(pydantic.BaseModel):
    """
    Model used when a user requests to start a new scan.
    This validates the incoming request from the API.
    """
    profile: ScanProfile
    target_url: Optional[AnyUrl] = None
    source_code_path: Optional[str] = None
    auth_cookie: Optional[str] = None

    @pydantic.model_validator(mode='after')
    def validate_dependencies(self) -> 'ScanCreate':
        """
        Ensures that the correct arguments are provided for the chosen profile.
        """
        if self.profile in [ScanProfile.WEB, ScanProfile.FULL] and not self.target_url:
            raise ValueError("A valid 'target_url' is required for 'web' and 'full' profiles.")
        
        if self.profile in [ScanProfile.DEVELOPER, ScanProfile.FULL] and not self.source_code_path:
            raise ValueError("A 'source_code_path' is required for 'developer' and 'full' profiles.")
        
        return self

# --- API Response Models (Data to Client) ---

class ScanJobStarted(pydantic.BaseModel):
    """
    Model for the response sent back immediately after a scan is queued.
    """
    job_id: str
    status: ScanStatus = ScanStatus.PENDING
    message: str = "Scan job successfully queued."
    profile: ScanProfile
    target_url: Optional[AnyUrl] = None

class ScanFinding(pydantic.BaseModel):
    """
    Model representing a single vulnerability finding.
    """
    severity: ScanSeverity
    title: str
    tool: str
    details: str
    remediation: Optional[str] = None
    location: Optional[str] = None
    
    # --- FIX: Add from_attributes ---
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True
    )
    # -------------------------------


class ScanJob(pydantic.BaseModel):
    """
    Model representing a complete scan job, including its results.
    This is a Pydantic model, not a DB model.
    """
    id: str
    status: ScanStatus
    profile: ScanProfile
    target_url: Optional[AnyUrl] = None
    source_code_path: Optional[str] = None
    auth_cookie: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    highest_severity: ScanSeverity = ScanSeverity.INFO
    findings: List[ScanFinding] = []
    
    # --- FIX: Add from_attributes ---
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True
    )
    # -------------------------------

class ScanJobSummary(pydantic.BaseModel):
    """
    A lightweight model for listing multiple scans (e.g., in a dashboard table).
    """
    id: str
    status: ScanStatus
    profile: ScanProfile
    target: str # A simple string combining URL or path
    highest_severity: ScanSeverity
    created_at: datetime

    # --- FIX: Add from_attributes ---
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True
    )
    # -------------------------------

class ScanJobUpdate(pydantic.BaseModel):
    """
    Model used by the worker to send results back to the database.
    """
    status: ScanStatus
    findings: List[ScanFinding]
    highest_severity: ScanSeverity
    attack_path_analysis: Optional[str] = None
    report_url: Optional[str] = None
