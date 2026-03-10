"""add file_path and line to findings for location-based grouping

Revision ID: 014
Revises: 013
Create Date: 2026-02-27

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "014"
down_revision: Union[str, None] = "013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("file_path", sa.String(1024), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("line", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "line")
    op.drop_column("findings", "file_path")
