"""Add finding identifier facts table.

Revision ID: 032
Revises: 031
Create Date: 2026-03-22
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "032"
down_revision: Union[str, None] = "031"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "finding_identifiers",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.String(length=32), nullable=False),
        sa.Column("namespace", sa.String(length=64), nullable=False),
        sa.Column("value", sa.String(length=256), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column(
            "metadata_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "finding_id",
            "namespace",
            "value",
            "source",
            name="uq_finding_identifier",
        ),
    )
    op.create_index(
        op.f("ix_finding_identifiers_finding_id"),
        "finding_identifiers",
        ["finding_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_identifiers_namespace"),
        "finding_identifiers",
        ["namespace"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_identifiers_value"),
        "finding_identifiers",
        ["value"],
        unique=False,
    )
    op.alter_column("finding_identifiers", "metadata_json", server_default=None)


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_identifiers_value"), table_name="finding_identifiers")
    op.drop_index(
        op.f("ix_finding_identifiers_namespace"), table_name="finding_identifiers"
    )
    op.drop_index(
        op.f("ix_finding_identifiers_finding_id"), table_name="finding_identifiers"
    )
    op.drop_table("finding_identifiers")

