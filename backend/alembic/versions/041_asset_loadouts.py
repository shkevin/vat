"""Create asset_loadouts table.

Revision ID: 041
Revises: 040
Create Date: 2026-04-29
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "041"
down_revision: Union[str, None] = "040"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_loadouts",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("owner_email", sa.String(length=256), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=True),
        sa.Column("asset_ids", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("entries", JSONB(), nullable=True),
        sa.Column(
            "shared_with_team",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_asset_loadouts_owner_email", "asset_loadouts", ["owner_email"], unique=False
    )
    op.create_index(
        "ix_asset_loadouts_tenant_id", "asset_loadouts", ["tenant_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_asset_loadouts_tenant_id", table_name="asset_loadouts")
    op.drop_index("ix_asset_loadouts_owner_email", table_name="asset_loadouts")
    op.drop_table("asset_loadouts")
