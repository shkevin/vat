"""Add license_expression column to findings.

Revision ID: 040
Revises: 039
Create Date: 2026-04-29
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "040"
down_revision: Union[str, None] = "039"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("license_expression", sa.String(length=256), nullable=True),
    )
    op.create_index(
        "ix_findings_license_expression",
        "findings",
        ["license_expression"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_findings_license_expression", table_name="findings")
    op.drop_column("findings", "license_expression")
