from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta

from app.core.security import (
    verify_password, 
    create_access_token, 
    get_password_hash, 
    get_current_user
)
# --- FIX: Import our new LoginResponse model ---
from app.models.user import User, LoginResponse
from config.settings import settings

router = APIRouter()

# --- FIX: Change the response_model to LoginResponse ---
@router.post("/token", response_model=LoginResponse)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """
    Handles user login and returns a JWT access token AND the user object.
    """
    
    print(f"[AUTH] Received login attempt for user: {form_data.username}")
    is_valid_user = False
    
    # --- SIMULATED USER LOOKUP ---
    if form_data.username == settings.FIRST_ADMIN_EMAIL:
        print("[AUTH] Username matches admin email.")
        try:
            hashed_password = get_password_hash(settings.FIRST_ADMIN_PASSWORD)
            print("[AUTH] Admin password from settings has been hashed.")
            
            if verify_password(form_data.password, hashed_password):
                print("[AUTH] Password verification successful.")
                is_valid_user = True
            else:
                print("[AUTH] Password verification FAILED (passwords do not match).")
        
        except Exception as e:
            print(f"[AUTH ERROR] Password verification CRASHED: {e}")
            is_valid_user = False
            
    else:
        print("[AUTH] Username does not match admin email.")

    if not is_valid_user:
        print("[AUTH] Login failed. Returning 401 Unauthorized.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    # --- Token Creation ---
    print("[AUTH] Login successful. Creating access token.")
    access_token_expires = timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    access_token = create_access_token(
        data={"sub": form_data.username}, 
        expires_delta=access_token_expires
    )
    
    # --- FIX: Return the full LoginResponse object ---
    # This now includes the user, which will fix the frontend race condition.
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user=User(
            id="admin_user_001",
            email=settings.FIRST_ADMIN_EMAIL,
            full_name="Default Admin",
            is_admin=True,
            is_active=True
        )
    )


@router.get("/me", response_model=User)
async def read_users_me(
    current_user: User = Depends(get_current_user)
):
    """
    A protected endpoint to fetch the profile of the current user.
    """
    return current_user