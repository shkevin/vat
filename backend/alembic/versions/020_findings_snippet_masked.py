"""add snippet_masked to findings (line preview with secrets masked)

Revision ID: 020
Revises: 019
Create Date: 2026-03-08

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "020"
down_revision: Union[str, None] = "019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("snippet_masked", sa.String(512), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "snippet_masked")
