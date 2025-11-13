from fastapi import FastAPI
from app.api import api_router
from config.settings import settings

# Create the main FastAPI application instance
app = FastAPI(
    title="Project Sentinel - Security Orchestrator",
    description="The secure backend API for the Project Sentinel DevSecOps Platform.",
    version="1.0.0",
    # In a production app, you'd disable the docs on the public internet:
    # docs_url=None, 
    # redoc_url=None,
)

# Include the main API router
# All routes from /api/__init__.py will be included.
# This results in routes like: /api/v1/auth/token
app.include_router(api_router, prefix="/api")

# --- Root Endpoint ---
@app.get("/", tags=["Health Check"])
async def root():
    """
    A simple health check endpoint to confirm the API is running.
    This is useful for load balancers and uptime monitoring.
    """
    return {
        "status": "ok", 
        "message": "Welcome to the Project Sentinel API"
    }

# --- Real-App Event Handlers ---

@app.on_event("startup")
async def startup_event():
    """
    This code runs once, when the FastAPI application starts.
    In a real app, this is where you would:
    - Initialize your database connection pool.
    - Connect to a cache (like Redis).
    - etc.
    """
    print("FastAPI application is starting up...")
    # Example: await connect_to_database()
    # Example: await connect_to_redis()
    print("Startup complete.")


@app.on_event("shutdown")
async def shutdown_event():
    """
    This code runs once, when the FastAPI application shuts down.
    In a real app, this is where you would:
    - Gracefully close database connections.
    - Disconnect from the cache.
    """
    print("FastAPI application is shutting down...")
    # Example: await close_database_connection()
    # Example: await close_redis_connection()
    print("Shutdown complete.")

