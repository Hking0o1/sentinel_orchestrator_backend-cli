"""phase_1_7_security_control_layer

Revision ID: 20260217_01
Revises:
Create Date: 2026-02-17 00:00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "20260217_01"
down_revision = None
branch_labels = None
depends_on = None


trust_tier_enum = postgresql.ENUM("NEW", "VERIFIED", "TRUSTED", "SUSPENDED", name="trust_tier_enum")
domain_status_enum = postgresql.ENUM("PENDING", "VERIFIED", name="domain_status_enum")
activity_outcome_enum = postgresql.ENUM("ALLOWED", "BLOCKED", "THROTTLED", name="activity_outcome_enum")


def upgrade() -> None:
    bind = op.get_bind()
    trust_tier_enum.create(bind, checkfirst=True)
    domain_status_enum.create(bind, checkfirst=True)
    activity_outcome_enum.create(bind, checkfirst=True)

    op.add_column(
        "users",
        sa.Column(
            "trust_tier",
            sa.Enum("NEW", "VERIFIED", "TRUSTED", "SUSPENDED", name="trust_tier_enum"),
            nullable=False,
            server_default="NEW",
        ),
    )

    op.create_table(
        "domains",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("verification_token", sa.String(length=128), nullable=False),
        sa.Column("status", sa.Enum("PENDING", "VERIFIED", name="domain_status_enum"), nullable=False, server_default="PENDING"),
        sa.Column("failed_verification_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "domain", name="uq_domains_user_domain"),
    )
    op.create_index("ix_domains_user_id", "domains", ["user_id"], unique=False)
    op.create_index("ix_domains_domain", "domains", ["domain"], unique=False)

    op.create_table(
        "scan_activity",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("domain", sa.String(), nullable=True),
        sa.Column("scan_type", sa.String(length=50), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("outcome", sa.Enum("ALLOWED", "BLOCKED", "THROTTLED", name="activity_outcome_enum"), nullable=False),
        sa.Column("reason", sa.String(length=200), nullable=True),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default=sa.text("'{}'::jsonb")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_activity_user_id", "scan_activity", ["user_id"], unique=False)
    op.create_index("ix_scan_activity_domain", "scan_activity", ["domain"], unique=False)
    op.create_index("ix_scan_activity_timestamp", "scan_activity", ["timestamp"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_scan_activity_timestamp", table_name="scan_activity")
    op.drop_index("ix_scan_activity_domain", table_name="scan_activity")
    op.drop_index("ix_scan_activity_user_id", table_name="scan_activity")
    op.drop_table("scan_activity")

    op.drop_index("ix_domains_domain", table_name="domains")
    op.drop_index("ix_domains_user_id", table_name="domains")
    op.drop_table("domains")

    op.drop_column("users", "trust_tier")

    bind = op.get_bind()
    activity_outcome_enum.drop(bind, checkfirst=True)
    domain_status_enum.drop(bind, checkfirst=True)
    trust_tier_enum.drop(bind, checkfirst=True)
