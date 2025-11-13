import pydantic
import bcrypt  # <-- Import the new library
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from config.settings import settings
from app.models.user import User, UserBase, TokenData

# --- Password Hashing (using bcrypt-py) ---

# Re-usable OAuth2PasswordBearer scheme.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain-text password against a hashed password using bcrypt-py.
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
    # Decode back to a string to store in our (simulated) DB
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

def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    A FastAPI dependency that can be used in any endpoint.
    """
    token_data = decode_and_validate_token(token)
    
    # --- DATABASE LOOKUP (SIMULATED) ---
    if token_data.email == settings.FIRST_ADMIN_EMAIL:
        return User(
            id="admin_user_001",  # Provide a mock ID
            email=settings.FIRST_ADMIN_EMAIL,
            full_name="Default Admin",
            is_admin=True,      # Use 'is_admin' instead of 'role'
            is_active=True
        )
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="User not found (simulation)",
    )
