"""Drop deprecated correlation review queue tables.

Revision ID: 033
Revises: 032
Create Date: 2026-03-22
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "033"
down_revision: Union[str, None] = "032"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index(
        op.f("ix_correlation_review_decisions_decision"),
        table_name="correlation_review_decisions",
    )
    op.drop_index(
        op.f("ix_correlation_review_decisions_review_id"),
        table_name="correlation_review_decisions",
    )
    op.drop_table("correlation_review_decisions")

    op.drop_index(op.f("ix_correlation_reviews_operation_id"), table_name="correlation_reviews")
    op.drop_index(op.f("ix_correlation_reviews_status"), table_name="correlation_reviews")
    op.drop_index(op.f("ix_correlation_reviews_finding_id_b"), table_name="correlation_reviews")
    op.drop_index(op.f("ix_correlation_reviews_finding_id_a"), table_name="correlation_reviews")
    op.drop_table("correlation_reviews")


def downgrade() -> None:
    op.create_table(
        "correlation_reviews",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("finding_id_a", sa.String(length=32), nullable=False),
        sa.Column("finding_id_b", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("operation_id", sa.String(length=64), nullable=True),
        sa.Column("created_by", sa.String(length=256), nullable=True),
        sa.Column("updated_by", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id_a", "finding_id_b", name="uq_correlation_reviews_pair"),
    )
    op.create_index(
        op.f("ix_correlation_reviews_finding_id_a"),
        "correlation_reviews",
        ["finding_id_a"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_reviews_finding_id_b"),
        "correlation_reviews",
        ["finding_id_b"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_reviews_status"),
        "correlation_reviews",
        ["status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_reviews_operation_id"),
        "correlation_reviews",
        ["operation_id"],
        unique=False,
    )
    op.alter_column("correlation_reviews", "evidence", server_default=None)

    op.create_table(
        "correlation_review_decisions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("review_id", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=24), nullable=False),
        sa.Column("decided_by", sa.String(length=256), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column(
            "evidence_used",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_correlation_review_decisions_review_id"),
        "correlation_review_decisions",
        ["review_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_review_decisions_decision"),
        "correlation_review_decisions",
        ["decision"],
        unique=False,
    )
    op.alter_column("correlation_review_decisions", "evidence_used", server_default=None)

