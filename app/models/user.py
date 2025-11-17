import pydantic
from typing import Optional
from pydantic import ConfigDict, EmailStr
from pydantic.alias_generators import to_camel
import uuid # We need this for the default_factory

class UserBase(pydantic.BaseModel):
    """
    Base user model with fields common to all user representations.
    """
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool = True
    is_admin: bool = False

class UserCreate(UserBase):
    """
    Model used when creating a new user. Includes the password.
    This model is used for API input.
    """
    password: str

class UserUpdate(pydantic.BaseModel):
    """
    Model used when updating an existing user. All fields are optional.
    """
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None
    password: Optional[str] = None

class User(UserBase):
    """
    Model used when reading user data (e.g., returning from API).
    It should NOT include the password.
    """
    id: uuid.UUID # Use the UUID type
    
    # --- FIX: Use the Pydantic v2 ConfigDict ---
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True  # <-- THIS IS THE FIX
    )
    # ---------------------------------------------

class UserInDB(User):
    """
    Model representing a user as stored in our "database".
    This includes the hashed password for authentication checks.
    """
    hashed_password: str

class Token(pydantic.BaseModel):
    """
    Model for the JWT access token returned upon successful login.
    """
    access_token: str
    token_type: str

class LoginResponse(pydantic.BaseModel):
    """
    The full response for a successful login, including
    the token and the user's details.
    """
    access_token: str
    token_type: str = "bearer"
    user: User # This field expects a Pydantic 'User' model
    
    # --- FIX: This model also needs to be created from attributes ---
    model_config = ConfigDict(
        from_attributes=True
    )
    # -------------------------------------------------------------

class TokenData(pydantic.BaseModel):
    """
    Model for the data (payload) encoded within the JWT.
    This is what we get back after decoding a token.
    """
    email: Optional[EmailStr] = None
    user_id: str # We will store the user's UUID (as a string) in the 'sub'