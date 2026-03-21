"""Add daily audit ledger checkpoint table

Revision ID: 024
Revises: 023
Create Date: 2026-03-19

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "024"
down_revision: Union[str, None] = "023"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_ledger_checkpoints",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("checkpoint_date", sa.String(length=16), nullable=False),
        sa.Column(
            "retention_class",
            sa.String(length=32),
            nullable=False,
            server_default="operational",
        ),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("anchor_hash", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "checkpoint_date", "retention_class", name="uq_audit_checkpoint_date_class"
        ),
    )
    op.create_index(
        "ix_audit_ledger_checkpoints_checkpoint_date",
        "audit_ledger_checkpoints",
        ["checkpoint_date"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("audit_ledger_checkpoints")
