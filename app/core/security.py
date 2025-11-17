from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from config.settings import settings
from app.models.user import User, TokenData
from app.db.session import get_db_session
from app.db import crud

# --- Password Hashing (using passlib and bcrypt) ---

# 1. Create a CryptContext. This tells passlib which hashing algorithm to use.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 2. Re-usable OAuth2PasswordBearer scheme.
#    'tokenUrl' points to our *login* endpoint.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain-text password against a hashed password using passlib.
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Generates a secure bcrypt hash for a plain-text password using passlib.
    """
    return pwd_context.hash(password)


# --- JSON Web Token (JWT) Management ---

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Creates a new, signed JWT access token.
    
    Args:
        data: The payload to encode (e.g., {'sub': str(user.id)}).
        expires_delta: How long the token should be valid for.
        
    Returns:
        A signed JWT string.
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

# --- FastAPI Dependency (THE NEW DATABASE-DRIVEN VERSION) ---

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
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
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