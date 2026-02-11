import threading
import time
import logging
import os
from fastapi import FastAPI
from contextlib import asynccontextmanager
from app.api import api_router
from config.settings import settings
from app.db.session import engine, AsyncSessionLocal
from app.db.base import Base
from app.db import crud
from app.db import models as db_models  # noqa: F401
from app.models import scan as scan_models  # noqa: F401
from app.models.user import UserCreate
from engine.scheduler.runtime import (
    acquire_scheduler_process_lock,
    init_scheduler,
    get_scheduler,
)
from engine.scheduler.event_bus import drain_events
from engine.dispatch.celery_dispatch import CeleryDispatcher

logger = logging.getLogger(__name__)
_scheduler_thread_started = False
_scheduler_thread_lock = threading.Lock()

def start_scheduler_thread():
    global _scheduler_thread_started

    with _scheduler_thread_lock:
        if _scheduler_thread_started:
            logger.warning(
                "Scheduler thread already started in this process | pid=%s",
                os.getpid(),
            )
            return
        _scheduler_thread_started = True

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

    logger.info("FastAPI application startup initiated")
    

    # -------------------------------------------------
    # 1. Initialize database schema
    # -------------------------------------------------
    async with engine.begin() as conn:
        logger.info("Initializing database tables")
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables initialized")

    # -------------------------------------------------
    # 2. Ensure default admin user exists
    # -------------------------------------------------
    async with AsyncSessionLocal() as db:
        logger.info("Checking admin bootstrap user")
        admin_user = await crud.get_user_by_email(
            db, email=settings.FIRST_ADMIN_EMAIL
        )

        if not admin_user:
            logger.info("Admin user not found. Creating default admin")
            admin_in = UserCreate(
                email=settings.FIRST_ADMIN_EMAIL,
                password=settings.FIRST_ADMIN_PASSWORD,
                full_name="Default Admin",
                is_active=True,
                is_admin=True,
            )
            await crud.create_user(db, user_in=admin_in)
            logger.info("Default admin user created")
        else:
            logger.info("Default admin user already exists")

    # -------------------------------------------------
    # 3. Initialize Sentinel scheduler (CRITICAL)
    # -------------------------------------------------
    logger.info("Initializing Sentinel scheduler...")

    if acquire_scheduler_process_lock():
        try:
            init_scheduler(
                max_tokens=settings.SCHEDULER_MAX_TOKENS,
                max_concurrent_tasks=settings.SCHEDULER_MAX_CONCURRENT_TASKS,
            )
            start_scheduler_thread()
            logger.info(
                "Sentinel scheduler initialized successfully | pid=%s",
                os.getpid(),
            )
        except RuntimeError as exc:
            logger.warning(
                "Scheduler initialization skipped in pid=%s: %s",
                os.getpid(),
                exc,
            )
    else:
        logger.warning(
            "Scheduler startup skipped: lock is held by another process | pid=%s",
            os.getpid(),
        )

    logger.info("Application startup complete")

    yield
    
    logger.info("Sentinel shutting down")
    logger.info("FastAPI application shutdown initiated")


    await engine.dispose()
    logger.info("Application shutdown complete")


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
