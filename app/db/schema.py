from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection


async def ensure_legacy_schema_compatibility(conn: AsyncConnection) -> None:
    """
    Repair schema gaps that ``Base.metadata.create_all`` cannot handle.

    Older local databases may already have a ``users`` table from before
    security trust tiers were introduced. SQLAlchemy's create_all creates
    missing tables, but it will not add new columns to existing tables.
    """
    if conn.dialect.name != "postgresql":
        return

    await conn.execute(
        text(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_type
                    WHERE typname = 'trust_tier_enum'
                ) THEN
                    CREATE TYPE trust_tier_enum AS ENUM (
                        'NEW',
                        'VERIFIED',
                        'TRUSTED',
                        'SUSPENDED'
                    );
                END IF;
            END
            $$;
            """
        )
    )
    await conn.execute(
        text(
            """
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS trust_tier trust_tier_enum NOT NULL DEFAULT 'NEW'
            """
        )
    )
