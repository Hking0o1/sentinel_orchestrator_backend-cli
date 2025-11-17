from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from config.settings import settings
from typing import AsyncGenerator

# --- 1. Create the Async Engine ---
# This is the "factory" that creates new connections to our database.
# It uses the DATABASE_URL from our config/settings.py file.
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,  # Test connections before using them
    echo=settings.DEBUG, # Log SQL queries if in debug mode
)

# --- 2. Create the Async SessionMaker ---
# This is a "factory for sessions". A session is our "conversation"
# with the database. We will create a new one for every API request.
AsyncSessionLocal = async_sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False, # Good for async
)

async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency to get a new database session per request.
    
    This will be used in our API endpoints to ensure that each
    request gets its own session and that the session is always
    closed, even if an error occurs.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()