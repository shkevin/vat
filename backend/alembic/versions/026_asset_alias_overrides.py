"""Add asset alias overrides for manual grouping.

Revision ID: 026
Revises: 025
Create Date: 2026-03-21
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "026"
down_revision: Union[str, None] = "025"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_aliases",
        sa.Column("source_asset_id", sa.String(length=512), nullable=False),
        sa.Column("canonical_asset_id", sa.String(length=512), nullable=False),
        sa.Column("created_by", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "source_asset_id <> canonical_asset_id",
            name="ck_asset_aliases_no_self_alias",
        ),
        sa.PrimaryKeyConstraint("source_asset_id"),
    )
    op.create_index(
        op.f("ix_asset_aliases_canonical_asset_id"),
        "asset_aliases",
        ["canonical_asset_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_asset_aliases_canonical_asset_id"), table_name="asset_aliases")
    op.drop_table("asset_aliases")
