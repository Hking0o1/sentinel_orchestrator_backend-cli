from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    """
    The base class for all of our SQLAlchemy (database) models.
    
    When we create our database models (like User, ScanJob) in models.py,
    they will inherit from this class.
    
    e.g., class User(Base):
             __tablename__ = "users"
             ...
    """
    pass