"""Add index on findings.updated_at for ETag derivation.

Revision ID: 042
Revises: 041
Create Date: 2026-04-30
"""

from typing import Sequence, Union

from alembic import op

revision: str = "042"
down_revision: Union[str, None] = "041"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Cheap MAX(updated_at) lookup for ETag derivation. Concurrently so
    # the rolling production migration doesn't block writes.
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_findings_updated_at "
        "ON findings (updated_at DESC)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_findings_updated_at")
