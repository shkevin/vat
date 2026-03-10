"""add source_issue_group_id to findings (Aikido group_id)

Revision ID: 013
Revises: 012
Create Date: 2026-02-26

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "013"
down_revision: Union[str, None] = "012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("source_issue_group_id", sa.String(64), nullable=True),
    )
    op.create_index(
        "ix_findings_source_issue_group_id",
        "findings",
        ["source_issue_group_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_findings_source_issue_group_id", table_name="findings")
    op.drop_column("findings", "source_issue_group_id")
