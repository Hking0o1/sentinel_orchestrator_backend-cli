from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
import pydantic
from urllib.parse import quote_plus # <-- NEW IMPORT

class Settings(BaseSettings):
    """
    Manages all application settings and secrets.
    Reads from environment variables (and .env file).
    """

    # --- Core Application Configuration ---
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # --- FastAPI Backend & JWT Security ---
    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ALGORITHM: str = "HS256"

    # --- Default Admin User (for first-time setup) ---
    FIRST_ADMIN_EMAIL: str
    FIRST_ADMIN_PASSWORD: str

    # --- Redis & Celery Configuration ---
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379

    @pydantic.computed_field
    @property
    def REDIS_URL(self) -> str:
        """
        Construct the full Redis URL for Celery.
        """
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"

    # --- AI & Reporting API Keys ---
    GEMINI_API_KEY: str | None = None
    NVD_API_KEY: str | None = None # For Dependency-Check

    # --- JIRA Integration (for automated ticketing) ---
    JIRA_SERVER: str | None = None
    JIRA_USERNAME: str | None = None
    JIRA_API_TOKEN: str | None = None

    # --- NEW: PostgreSQL Database Configuration ---
    POSTGRES_SERVER: str = "db"
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    
    # --- FIX: We now compute the DATABASE_URL automatically ---
    # This prevents all parsing and special character errors.
    @pydantic.computed_field
    @property
    def DATABASE_URL(self) -> str:
        """
        Construct the full async PostgreSQL connection string.
        """
        # Safely quote the password for the URL
        safe_password = quote_plus(self.POSTGRES_PASSWORD)
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{safe_password}"
            f"@{self.POSTGRES_SERVER}/{self.POSTGRES_DB}"
        )
    # --------------------------------------------------------

    # Pydantic-Settings configuration
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding='utf-8',
        case_sensitive=False
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Returns a cached instance of the Settings object.
    Using @lru_cache ensures the .env file is read only once.
    """
    return Settings()

# Create a single, globally accessible settings instance
settings = get_settings()