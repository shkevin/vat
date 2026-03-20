"""Add finding correlation fields for cross-source link/merge policy

Revision ID: 023
Revises: 022
Create Date: 2026-03-19

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "023"
down_revision: Union[str, None] = "022"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("correlation_key", sa.String(length=256), nullable=True))
    op.add_column("findings", sa.Column("correlation_confidence", sa.String(length=32), nullable=True))
    op.add_column("findings", sa.Column("correlated_to", sa.String(length=32), nullable=True))
    op.create_index("ix_findings_correlation_key", "findings", ["correlation_key"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_findings_correlation_key", table_name="findings")
    op.drop_column("findings", "correlated_to")
    op.drop_column("findings", "correlation_confidence")
    op.drop_column("findings", "correlation_key")

