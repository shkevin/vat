"""Add asset observed tags and digest conflict tables.

Revision ID: 034
Revises: 033
Create Date: 2026-03-22
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "034"
down_revision: Union[str, None] = "033"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_observed_tags",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", sa.String(length=512), nullable=False),
        sa.Column("tag", sa.String(length=128), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_scan_session_id", sa.String(length=64), nullable=True),
        sa.Column("last_digest", sa.String(length=128), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "tag", name="uq_asset_observed_tag_asset_tag"),
    )
    op.create_index(
        op.f("ix_asset_observed_tags_asset_id"),
        "asset_observed_tags",
        ["asset_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_asset_observed_tags_tag"),
        "asset_observed_tags",
        ["tag"],
        unique=False,
    )
    op.alter_column("asset_observed_tags", "observation_count", server_default=None)

    op.create_table(
        "asset_digest_conflicts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", sa.String(length=512), nullable=False),
        sa.Column("tag", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="open"),
        sa.Column(
            "digests",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("acknowledged_by", sa.String(length=256), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "tag", name="uq_asset_digest_conflict_asset_tag"),
    )
    op.create_index(
        op.f("ix_asset_digest_conflicts_asset_id"),
        "asset_digest_conflicts",
        ["asset_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_asset_digest_conflicts_tag"),
        "asset_digest_conflicts",
        ["tag"],
        unique=False,
    )
    op.alter_column("asset_digest_conflicts", "status", server_default=None)
    op.alter_column("asset_digest_conflicts", "digests", server_default=None)


def downgrade() -> None:
    op.drop_index(
        op.f("ix_asset_digest_conflicts_tag"), table_name="asset_digest_conflicts"
    )
    op.drop_index(
        op.f("ix_asset_digest_conflicts_asset_id"), table_name="asset_digest_conflicts"
    )
    op.drop_table("asset_digest_conflicts")

    op.drop_index(op.f("ix_asset_observed_tags_tag"), table_name="asset_observed_tags")
    op.drop_index(
        op.f("ix_asset_observed_tags_asset_id"), table_name="asset_observed_tags"
    )
    op.drop_table("asset_observed_tags")
