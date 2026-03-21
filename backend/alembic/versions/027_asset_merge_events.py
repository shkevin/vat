"""Add asset merge event table for reversible unmerge.

Revision ID: 027
Revises: 026
Create Date: 2026-03-21
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "027"
down_revision: Union[str, None] = "026"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_merge_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("source_asset_id", sa.String(length=512), nullable=False),
        sa.Column("target_asset_id", sa.String(length=512), nullable=False),
        sa.Column("finding_id", sa.String(length=32), nullable=False),
        sa.Column("prev_values", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("next_values", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_by", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("reverted_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_asset_merge_events_source_asset_id"),
        "asset_merge_events",
        ["source_asset_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_asset_merge_events_target_asset_id"),
        "asset_merge_events",
        ["target_asset_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_asset_merge_events_finding_id"),
        "asset_merge_events",
        ["finding_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_asset_merge_events_finding_id"), table_name="asset_merge_events")
    op.drop_index(op.f("ix_asset_merge_events_target_asset_id"), table_name="asset_merge_events")
    op.drop_index(op.f("ix_asset_merge_events_source_asset_id"), table_name="asset_merge_events")
    op.drop_table("asset_merge_events")
