"""add branch and tag to findings

Revision ID: 009
Revises: 008
Create Date: 2026-02-25

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "009"
down_revision: Union[str, None] = "008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("branch", sa.String(128), nullable=True))
    op.add_column("findings", sa.Column("tag", sa.String(128), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "tag")
    op.drop_column("findings", "branch")
