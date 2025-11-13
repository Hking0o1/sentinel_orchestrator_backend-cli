from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

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
    ALGORITHM: str = "HS256" # Added this line

    # --- Default Admin User (for first-time setup) ---
    
    
    FIRST_ADMIN_EMAIL: str
    FIRST_ADMIN_PASSWORD: str
    # --- Redis & Celery Configuration ---
    REDIS_URL: str = "redis://redis:6379/0"

    # --- AI & Reporting API Keys ---
    GEMINI_API_KEY: str | None = None

    # --- JIRA Integration (for automated ticketing) ---
    JIRA_SERVER: str | None = None
    JIRA_USERNAME: str | None = None
    JIRA_API_TOKEN: str | None = None

    # Pydantic-Settings configuration
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding='utf-8',
        case_sensitive=False # Allow case-insensitive env vars
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