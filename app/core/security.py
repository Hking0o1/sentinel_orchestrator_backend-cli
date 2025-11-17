import pydantic
import bcrypt  # <-- Import the new library
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

# Import the 'settings' instance from our config module
from config.settings import settings
from app.models.user import User, TokenData
from app.db.session import get_db_session
from app.db import crud

# --- Password Hashing (using bcrypt directly) ---

# Re-usable OAuth2PasswordBearer scheme.
# 'tokenUrl' points to our *login* endpoint.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain-text password against a hashed password using bcrypt.
    """
    # We must encode the strings to bytes for bcrypt
    return bcrypt.checkpw(
        plain_password.encode('utf-8'), 
        hashed_password.encode('utf-8')
    )

def get_password_hash(password: str) -> str:
    """
    Generates a secure bcrypt hash for a plain-text password.
    """
    # We must encode the password to bytes
    hashed_bytes = bcrypt.hashpw(
        password.encode('utf-8'), 
        bcrypt.gensalt()
    )
    # Decode back to a string to store in our database
    return hashed_bytes.decode('utf-8')


# --- JSON Web Token (JWT) Management ---

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Creates a new, signed JWT access token.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        # Use the default expiration time from our settings
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt

def decode_and_validate_token(token: str) -> TokenData:
    """
    Decodes a JWT, validates its signature and expiration, and returns the payload.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        email: str | None = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
        
    except JWTError:
        raise credentials_exception
    
    return token_data

# --- FastAPI Dependency ---

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db_session)
) -> User:
    """
    A FastAPI dependency that decodes a JWT token, validates it,
    and fetches the corresponding user from the database.
    
    This is the "gatekeeper" for all our protected endpoints.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials, token may be invalid or user not found.",
    )
    
    try:
        # 1. Decode the JWT to get the payload
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        
        # 2. The 'sub' field now contains the user's UUID (as a string)
        user_id_str: str | None = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
            
        # 3. Convert the string ID to a UUID object
        try:
            user_id = UUID(user_id_str)
        except ValueError:
            raise credentials_exception
            
    except JWTError:
        # This catches any error from 'jwt.decode' (e.g., expired, invalid signature)
        raise credentials_exception
    
    # 4. --- REAL DATABASE LOOKUP ---
    # Fetch the user from the database using the ID from the token.
    user = await crud.get_user(db, user_id=user_id)
    
    if user is None:
        raise credentials_exception
        
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    # 5. Return the full, database-backed User model
    return user