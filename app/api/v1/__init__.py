from fastapi import APIRouter
from app.api.v1.endpoints import auth, domains, internal, scans, schedules # <--- Added schedules

# Create the main router for API version 1
api_router_v1 = APIRouter()

# Include the authentication router
api_router_v1.include_router(
    auth.router, 
    prefix="/auth", 
    tags=["Authentication"]
)

# Include the scan management router
api_router_v1.include_router(
    scans.router, 
    prefix="/scans", 
    tags=["Scan Management"]
)

api_router_v1.include_router(
    domains.router,
    prefix="/domains",
    tags=["Domain Verification"]
)

# --- NEW: Include the schedules router ---
api_router_v1.include_router(
    schedules.router,
    prefix="/schedules",
    tags=["Scan Schedules"]
)
# -----------------------------------------

api_router_v1.include_router(
    internal.router,
    prefix="/internal",
    tags=["Internal"]
)
