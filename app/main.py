# from fastapi import FastAPI
# from contextlib import asynccontextmanager
# from app.api import api_router
# from config.settings import settings
# from app.db.session import engine, AsyncSessionLocal
# from app.db.base import Base
# from app.db import crud
# from app.models.user import UserCreate

# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     """
#     Application lifespan manager. This is the new, recommended
#     way to handle startup and shutdown events in FastAPI.
#     """
#     print("FastAPI application is starting up...")
    
#     # --- 1. Create database tables ---
#     async with engine.begin() as conn:
#         print("Initializing database tables...")
#         # This creates all tables that inherit from 'Base'
#         await conn.run_sync(Base.metadata.create_all)
#         print("Database tables initialized.")

#     # --- 2. Create default admin user ---
#     # This replaces our old simulation. It checks the DB
#     # and creates the admin *once* if they don't exist.
#     async with AsyncSessionLocal() as db:
#         print(f"Checking for admin user: {settings.FIRST_ADMIN_EMAIL}...")
#         admin_user = await crud.get_user_by_email(db, email=settings.FIRST_ADMIN_EMAIL)
#         if not admin_user:
#             print("Admin user not found, creating new admin...")
#             admin_in = UserCreate(
#                 email=settings.FIRST_ADMIN_EMAIL,
#                 password=settings.FIRST_ADMIN_PASSWORD,
#                 full_name="Default Admin",
#                 is_active=True,
#                 is_admin=True
#             )
#             await crud.create_user(db, user_in=admin_in)
#             print("Default admin user created successfully.")
#         else:
#             print("Admin user already exists.")
            
#     print("Startup complete.")
    
#     yield # The application is now running
    
#     # --- Shutdown ---
#     print("FastAPI application is shutting down...")
#     await engine.dispose() # Cleanly close the database connection pool
#     print("Shutdown complete.")


# # Create the main FastAPI application instance
# app = FastAPI(
#     title="Project Sentinel - Security Orchestrator",
#     description="The secure backend API for the Project Sentinel DevSecOps Platform.",
#     version="1.0.0",
#     lifespan=lifespan # Use the new lifespan context manager
# )

# # Include the main API router
# # All routes from /api/__init__.py will be included.
# # This results in routes like: /api/v1/auth/token
# app.include_router(api_router, prefix="/api")

# # --- Root Endpoint ---
# @app.get("/", tags=["Health Check"])
# async def root():
#     """
#     A simple health check endpoint to confirm the API is running.
#     This is useful for load balancers and uptime monitoring.
#     """
#     return {
#         "status": "ok", 
#         "message": "Welcome to the Project Sentinel API"
#     }

from fastapi import FastAPI
from contextlib import asynccontextmanager

from app.api import api_router
from config.settings import settings

from app.db.session import engine, AsyncSessionLocal
from app.db.base import Base
from app.db import crud
from app.models.user import UserCreate

# -----------------------------
# NEW: Scheduler lifecycle
# -----------------------------
from engine.scheduler.runtime import init_scheduler
from engine.dispatch.callbacks import init_scheduler as init_dispatch_callbacks


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.

    Handles:
    - database initialization
    - default admin bootstrap
    - Sentinel scheduler initialization (Phase 1.5)
    """

    print("FastAPI application is starting up...")

    # -------------------------------------------------
    # 1. Initialize database schema
    # -------------------------------------------------
    async with engine.begin() as conn:
        print("Initializing database tables...")
        await conn.run_sync(Base.metadata.create_all)
        print("Database tables initialized.")

    # -------------------------------------------------
    # 2. Ensure default admin user exists
    # -------------------------------------------------
    async with AsyncSessionLocal() as db:
        print(f"Checking for admin user: {settings.FIRST_ADMIN_EMAIL}...")
        admin_user = await crud.get_user_by_email(
            db, email=settings.FIRST_ADMIN_EMAIL
        )

        if not admin_user:
            print("Admin user not found, creating new admin...")
            admin_in = UserCreate(
                email=settings.FIRST_ADMIN_EMAIL,
                password=settings.FIRST_ADMIN_PASSWORD,
                full_name="Default Admin",
                is_active=True,
                is_admin=True,
            )
            await crud.create_user(db, user_in=admin_in)
            print("Default admin user created successfully.")
        else:
            print("Admin user already exists.")

    # -------------------------------------------------
    # 3. Initialize Sentinel scheduler (CRITICAL)
    # -------------------------------------------------
    print("Initializing Sentinel scheduler...")

    scheduler = init_scheduler(
        max_tokens=settings.SCHEDULER_MAX_TOKENS,
        max_concurrent_tasks=settings.SCHEDULER_MAX_CONCURRENT_TASKS,
    )

    # Register scheduler with Celery dispatch callbacks
    init_dispatch_callbacks(scheduler)

    print("Sentinel scheduler initialized successfully.")
    print("Startup complete.")

    # -------------------------------------------------
    # Application is now running
    # -------------------------------------------------
    yield

    # -------------------------------------------------
    # Shutdown phase
    # -------------------------------------------------
    print("FastAPI application is shutting down...")

    # Future:
    # - graceful scheduler shutdown
    # - task drain / metrics flush

    await engine.dispose()
    print("Shutdown complete.")


# -------------------------------------------------
# Create FastAPI application
# -------------------------------------------------
app = FastAPI(
    title="Project Sentinel - Security Orchestrator",
    description="The secure backend API for the Project Sentinel DevSecOps Platform.",
    version="1.0.0",
    lifespan=lifespan,
)

# -------------------------------------------------
# Include API routes
# -------------------------------------------------
app.include_router(api_router, prefix="/api")


# -------------------------------------------------
# Root / Health Check
# -------------------------------------------------
@app.get("/", tags=["Health Check"])
async def root():
    """
    Health check endpoint.
    Useful for load balancers and uptime monitoring.
    """
    return {
        "status": "ok",
        "message": "Welcome to the Project Sentinel API",
    }
