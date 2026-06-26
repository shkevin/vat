"""Add structured risk scoring metadata to findings.

Revision ID: 047
Revises: 046
Create Date: 2026-06-26
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "047"
down_revision: Union[str, None] = "046"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("risk_scoring", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "risk_scoring")
