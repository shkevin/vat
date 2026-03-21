"""add source_file_url to findings

Revision ID: 010
Revises: 009
Create Date: 2026-02-25

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "010"
down_revision: Union[str, None] = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings", sa.Column("source_file_url", sa.String(2048), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("findings", "source_file_url")
