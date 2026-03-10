"""Add grouping fields to findings (rule_id, cwe_id, ecosystem, secret_type, resource)

Revision ID: 017
Revises: 016
Create Date: 2026-03-02

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "017"
down_revision: Union[str, None] = "016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("rule_id", sa.String(256), nullable=True))
    op.add_column("findings", sa.Column("cwe_id", sa.String(32), nullable=True))
    op.add_column("findings", sa.Column("ecosystem", sa.String(64), nullable=True))
    op.add_column("findings", sa.Column("secret_type", sa.String(128), nullable=True))
    op.add_column("findings", sa.Column("resource", sa.String(512), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "resource")
    op.drop_column("findings", "secret_type")
    op.drop_column("findings", "ecosystem")
    op.drop_column("findings", "cwe_id")
    op.drop_column("findings", "rule_id")
