"""Add image_digest to findings for container variant grouping (Docker Hub–style).

Revision ID: 025
Revises: 024
Create Date: 2026-03-21

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "025"
down_revision: Union[str, None] = "024"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("image_digest", sa.String(length=128), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "image_digest")
