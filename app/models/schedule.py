import pydantic
from pydantic import ConfigDict, AnyUrl
from pydantic.alias_generators import to_camel
from uuid import UUID
from typing import Optional
from app.models.scan import ScanProfile

# We need a validator for crontab strings
from croniter import croniter

class ScanScheduleBase(pydantic.BaseModel):
    """
    Base Pydantic model for a Scan Schedule.
    Contains all common fields.
    """
    name: str
    description: Optional[str] = None
    crontab: str # e.g., "0 2 * * 0" (2 AM every Sunday)
    is_active: bool = True
    
    # Scan configuration
    profile: ScanProfile
    target_url: Optional[AnyUrl] = None
    source_code_path: Optional[str] = None
    auth_cookie: Optional[str] = None

    @pydantic.validator('crontab')
    def validate_crontab(cls, v):
        """
        Validates that the provided string is a valid crontab.
        """
        if not croniter.is_valid(v):
            raise ValueError('Invalid crontab string format.')
        return v
    
    @pydantic.model_validator(mode='after')
    def validate_dependencies(self) -> 'ScanScheduleBase':
        """
        Ensures that the correct arguments are provided for the chosen profile.
        """
        if self.profile in [ScanProfile.WEB, ScanProfile.FULL] and not self.target_url:
            raise ValueError("A valid 'target_url' is required for 'web' and 'full' profiles.")
        
        if self.profile in [ScanProfile.DEVELOPER, ScanProfile.FULL] and not self.source_code_path:
            raise ValueError("A 'source_code_path' is required for 'developer' and 'full' profiles.")
        
        return self

class ScanScheduleCreate(ScanScheduleBase):
    """
    Pydantic model for creating a new scan schedule.
    All fields are required from the API.
    """
    pass

class ScanScheduleUpdate(ScanScheduleBase):
    """
    Pydantic model for updating an existing schedule.
    All fields are made optional for PATCH requests.
    """
    name: Optional[str] = None
    crontab: Optional[str] = None
    is_active: Optional[bool] = None
    profile: Optional[ScanProfile] = None
    
    # We must redefine the model_validator for updates
    @pydantic.model_validator(mode='after')
    def validate_update_dependencies(self) -> 'ScanScheduleUpdate':
        # This logic would be more complex in a real app,
        # checking against the existing values in the DB.
        # For now, we'll keep it simple.
        return self

class ScanSchedule(ScanScheduleBase):
    """
    Pydantic model for reading a scan schedule from the API.
    This includes DB-generated fields like 'id' and 'owner_id'.
    """
    id: UUID
    owner_id: UUID

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True # Allows creating this from the SQLAlchemy model
    )