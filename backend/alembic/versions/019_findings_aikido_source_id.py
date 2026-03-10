"""add aikido_source_id to findings (which Aikido workspace/source)

Revision ID: 019
Revises: 018
Create Date: 2026-03-07

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "019"
down_revision: Union[str, None] = "018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("aikido_source_id", sa.String(64), nullable=True),
    )
    op.create_index(
        "ix_findings_aikido_source_id",
        "findings",
        ["aikido_source_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_findings_aikido_source_id", table_name="findings")
    op.drop_column("findings", "aikido_source_id")
