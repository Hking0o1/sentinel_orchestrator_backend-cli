import uuid
from sqlalchemy import (
    Column, String, Boolean, DateTime, ForeignKey
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base import Base # Import our Base class from base.py

class User(Base):
    """
    SQLAlchemy model for the 'users' table.
    This defines the actual table in our PostgreSQL database.
    """
    __tablename__ = "users"

    # We use a UUID for the primary key, not an integer.
    # This is more secure as it's not guessable.
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)
    
    # We store the *hashed* password, never the plain text.
    hashed_password = Column(String, nullable=False)
    
    is_active = Column(Boolean(), default=True)
    is_admin = Column(Boolean(), default=False)
    
    created_at = Column(
        DateTime(timezone=True), 
        server_default=func.now(), # Let the database handle the timestamp
        nullable=False
    )
    
    # --- Relationships ---
    # This creates the "one-to-many" link. One user can have many scans.
    # 'back_populates' links this to the 'owner' field in the ScanJob model.
    scans = relationship(
        "ScanJob", 
        back_populates="owner", 
        cascade="all, delete-orphan" # If a user is deleted, delete their scans
    )

class ScanJob(Base):
    """
    SQLAlchemy model for the 'scan_jobs' table.
    This stores the status and results of every scan.
    """
    __tablename__ = "scan_jobs"

    # We use the Celery Task ID (a string) as our primary key.
    # This makes lookups from the API (which knows the job_id) instant.
    id = Column(String(36), primary_key=True, index=True)
    
    status = Column(String, nullable=False, default="PENDING")
    profile = Column(String, nullable=False)
    
    target_url = Column(String, nullable=True)
    source_code_path = Column(String, nullable=True)
    
    highest_severity = Column(String, nullable=False, default="INFO")
    
    # We use JSONB (a native PostgreSQL JSON type) to store the
    # list of all vulnerability findings. This is highly efficient.
    findings = Column(JSONB, nullable=True, default=[])
    
    # Store the path to the final PDF report in our scan_results volume
    report_url = Column(String, nullable=True)
    
    created_at = Column(
        DateTime(timezone=True), 
        server_default=func.now(), 
        nullable=False
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # --- Relationships ---
    # This is the "many-to-one" link.
    # It creates a foreign key to the 'users.id' column.
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    # Links this to the 'scans' field in the User model.
    owner = relationship("User", back_populates="scans")