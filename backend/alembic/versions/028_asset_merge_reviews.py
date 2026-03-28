"""Add asset merge review decisions table.

Revision ID: 028
Revises: 027
Create Date: 2026-03-22
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "028"
down_revision: Union[str, None] = "027"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_merge_reviews",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("source_asset_id", sa.String(length=512), nullable=False),
        sa.Column("target_asset_id", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("strategy", sa.String(length=32), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("confidence", sa.String(length=16), nullable=True),
        sa.Column(
            "details", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("created_by", sa.String(length=256), nullable=True),
        sa.Column("updated_by", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_asset_id", "target_asset_id", name="uq_asset_merge_reviews_pair"
        ),
    )
    op.create_index(
        op.f("ix_asset_merge_reviews_source_asset_id"),
        "asset_merge_reviews",
        ["source_asset_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_asset_merge_reviews_target_asset_id"),
        "asset_merge_reviews",
        ["target_asset_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_asset_merge_reviews_target_asset_id"), table_name="asset_merge_reviews"
    )
    op.drop_index(
        op.f("ix_asset_merge_reviews_source_asset_id"), table_name="asset_merge_reviews"
    )
    op.drop_table("asset_merge_reviews")

