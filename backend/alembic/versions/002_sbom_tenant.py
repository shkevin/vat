"""add sbom_packages, tenant_id, users

Revision ID: 002
Revises: 001
Create Date: 2025-02-23

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("tenant_id", sa.String(64), nullable=True))
    op.create_index("ix_findings_tenant_id", "findings", ["tenant_id"], unique=False)

    op.create_table(
        "sbom_packages",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("version", sa.String(128), nullable=False),
        sa.Column("license_id", sa.String(64), nullable=True),
        sa.Column("license_risk", sa.String(32), nullable=True),
        sa.Column("component", sa.String(256), nullable=True),
        sa.Column("language", sa.String(64), nullable=True),
        sa.Column("sources", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("tenant_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_sbom_packages_tenant_id", "sbom_packages", ["tenant_id"], unique=False)
    op.create_index("ix_sbom_packages_name_version", "sbom_packages", ["name", "version"], unique=False)

    op.create_table(
        "tenants",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("email", sa.String(256), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),  # admin, reviewer, read_only
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_users_tenant_id", "users")
    op.drop_table("users")
    op.drop_table("tenants")
    op.drop_index("ix_sbom_packages_name_version", "sbom_packages")
    op.drop_index("ix_sbom_packages_tenant_id", "sbom_packages")
    op.drop_table("sbom_packages")
    op.drop_index("ix_findings_tenant_id", "findings")
    op.drop_column("findings", "tenant_id")
