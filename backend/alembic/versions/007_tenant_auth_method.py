"""add tenant auth_method and auth_config for IdP

Revision ID: 007
Revises: 006
Create Date: 2026-02-24

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("auth_method", sa.String(32), nullable=False, server_default="local"),
    )
    op.add_column(
        "tenants",
        sa.Column("auth_config", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tenants", "auth_config")
    op.drop_column("tenants", "auth_method")
