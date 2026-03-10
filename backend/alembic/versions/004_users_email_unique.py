"""add unique index on users.email for lookup

Revision ID: 004
Revises: 003
Create Date: 2026-02-24

"""

from typing import Sequence, Union

from alembic import op

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Case-insensitive unique: one user per email (LOWER) globally
    op.execute("CREATE UNIQUE INDEX ix_users_email ON users (LOWER(email))")


def downgrade() -> None:
    op.drop_index("ix_users_email", "users")
