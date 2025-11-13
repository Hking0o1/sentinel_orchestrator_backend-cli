from fastapi import APIRouter
from app.api.v1 import api_router_v1

# This is the main API router for the entire application.
api_router = APIRouter()

# Include the v1 router.
# All routes from v1 will be prefixed with /api/v1
api_router.include_router(api_router_v1, prefix="/v1")
