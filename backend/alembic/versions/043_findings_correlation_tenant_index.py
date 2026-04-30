"""Composite index on findings(correlation_key, tenant_id).

Revision ID: 043
Revises: 042
Create Date: 2026-04-30

apply_correlation_linking queries `WHERE correlation_key=? AND tenant_id=?`
on every ingest. Existing single-column index on correlation_key gets
us most of the way, but at scale (10k+ rows per cluster) the additional
tenant_id filter benefits from a composite. Partial coverage on the
NULL-tenant cluster path (legacy webhook ingest before C2 was rolled).
"""

from typing import Sequence, Union

from alembic import op

revision: str = "043"
down_revision: Union[str, None] = "042"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_findings_correlation_tenant "
        "ON findings (correlation_key, tenant_id) "
        "WHERE correlation_key IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_findings_correlation_tenant")
