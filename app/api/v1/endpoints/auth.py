from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timedelta

from app.core.security import (
    verify_password, 
    create_access_token, 
    get_current_user
)
from app.models.user import User, LoginResponse
from app.db import crud
from app.db.session import get_db_session
from config.settings import settings

router = APIRouter()

@router.post("/token", response_model=LoginResponse)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Handles user login and returns a JWT access token AND the user object.
    This now performs a real database lookup.
    """
    
    print(f"[AUTH] Received login attempt for user: {form_data.username}")
    
    # --- REAL DATABASE LOOKUP ---
    # We fetch the user from the database by their email.
    user = await crud.get_user_by_email(db, email=form_data.username)

    # 1. Check if user exists and
    # 2. Check if the password is correct
    if not user or not verify_password(form_data.password, user.hashed_password):
        print("[AUTH] Login failed: Incorrect username or password.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    # 3. Check if the user is active
    if not user.is_active:
        print("[AUTH] Login failed: User is inactive.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Inactive user"
        )
        
    # --- Token Creation ---
    print("[AUTH] Login successful. Creating access token.")
    access_token_expires = timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    
    # The 'sub' (subject) of the token is the user's ID
    # Using the UUID 'id' is more secure and standard than email
    access_token = create_access_token(
        data={"sub": str(user.id)}, 
        expires_delta=access_token_expires
    )
    
    # Return the full LoginResponse, including the user model
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user=user  # Return the full user object from the database
    )


@router.get("/me", response_model=User)
async def read_users_me(
    current_user: User = Depends(get_current_user)
):
    """
    A protected endpoint to fetch the profile of the current user.
    
    This endpoint demonstrates how to protect a route. The 'get_current_user'
    dependency will handle all the token validation and database fetching.
    """
    return current_user