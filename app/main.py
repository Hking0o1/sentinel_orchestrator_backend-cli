import threading
import time
import logging
from fastapi import FastAPI
from contextlib import asynccontextmanager
from app.api import api_router
from config.settings import settings
from app.db.session import engine, AsyncSessionLocal
from app.db.base import Base
from app.db import crud
from app.models.user import UserCreate
from engine.scheduler.runtime import init_scheduler, get_scheduler
from engine.scheduler.event_bus import drain_events
from engine.dispatch.celery_dispatch import CeleryDispatcher

logger = logging.getLogger(__name__)

def start_scheduler_thread():
    scheduler = get_scheduler()
    dispatcher = CeleryDispatcher(scheduler)
    
    
    def scheduler_loop():
        logger.error("SENTINEL SCHEDULER LOOP STARTED")

        while True:
            try:
                dispatched = dispatcher.run_once()
                if dispatched:
                    logger.error("DISPATCHED %d TASK(S)", dispatched)
            except Exception:
                logger.exception("Scheduler loop error")

            time.sleep(0.5)


    threading.Thread(
        target=scheduler_loop,
        daemon=True,
        name="sentinel-scheduler-loop",
    ).start()



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

    init_scheduler(
        max_tokens=settings.SCHEDULER_MAX_TOKENS,
        max_concurrent_tasks=settings.SCHEDULER_MAX_CONCURRENT_TASKS,
    )

    start_scheduler_thread()

    print("Sentinel scheduler initialized successfully.")
    print("Startup complete.")

    yield
    
    logger.info("Sentinel shutting down")
    print("FastAPI application is shutting down...")


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

app.include_router(api_router, prefix="/api")


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
