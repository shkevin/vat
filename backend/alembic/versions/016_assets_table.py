"""Add assets table for integration-created assets (repos, containers)

Revision ID: 016
Revises: 015
Create Date: 2026-03-02

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "016"
down_revision: Union[str, None] = "015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.String(512), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("branch", sa.String(128), nullable=True),
        sa.Column("tag", sa.String(128), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("assets")
