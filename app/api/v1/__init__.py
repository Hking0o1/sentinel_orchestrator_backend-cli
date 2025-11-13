from fastapi import APIRouter
from app.api.v1.endpoints import auth, scans

# Create the main router for API version 1
api_router_v1 = APIRouter()

# Include the authentication router
# All routes from auth.py will be prefixed with /auth
api_router_v1.include_router(
    auth.router, 
    prefix="/auth", 
    tags=["Authentication"]
)

# Include the scan management router
# All routes from scans.py will be prefixed with /scans
api_router_v1.include_router(
    scans.router, 
    prefix="/scans", 
    tags=["Scan Management"]
)