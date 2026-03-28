"""Add non-destructive, reversible correlation edges.

Revision ID: 030
Revises: 029
Create Date: 2026-03-22
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "030"
down_revision: Union[str, None] = "029"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "correlation_edges",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("finding_id_a", sa.String(length=32), nullable=False),
        sa.Column("finding_id_b", sa.String(length=32), nullable=False),
        sa.Column("edge_type", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("operation_id", sa.String(length=64), nullable=True),
        sa.Column("created_by", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("removed_by", sa.String(length=256), nullable=True),
        sa.Column("removed_at", sa.DateTime(), nullable=True),
        sa.Column("remove_reason", sa.String(length=256), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "finding_id_a", "finding_id_b", name="uq_correlation_edges_pair"
        ),
    )
    op.create_index(
        op.f("ix_correlation_edges_finding_id_a"),
        "correlation_edges",
        ["finding_id_a"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_edges_finding_id_b"),
        "correlation_edges",
        ["finding_id_b"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_edges_active"),
        "correlation_edges",
        ["active"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_edges_operation_id"),
        "correlation_edges",
        ["operation_id"],
        unique=False,
    )
    op.alter_column("correlation_edges", "evidence", server_default=None)
    op.alter_column("correlation_edges", "active", server_default=None)


def downgrade() -> None:
    op.drop_index(op.f("ix_correlation_edges_operation_id"), table_name="correlation_edges")
    op.drop_index(op.f("ix_correlation_edges_active"), table_name="correlation_edges")
    op.drop_index(op.f("ix_correlation_edges_finding_id_b"), table_name="correlation_edges")
    op.drop_index(op.f("ix_correlation_edges_finding_id_a"), table_name="correlation_edges")
    op.drop_table("correlation_edges")

