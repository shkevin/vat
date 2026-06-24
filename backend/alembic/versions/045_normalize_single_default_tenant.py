"""Normalize tenant-scoped rows to the default tenant.

Revision ID: 045
Revises: 044
Create Date: 2026-06-24

VAT is currently operated as a single-tenant deployment. Older rows may carry
NULL or non-default tenant ids from earlier multi-tenant experiments, which can
make assets disappear from tenant-scoped UI queries. Normalize all tenant-owned
data to ``t-default`` so the UI has one consistent tenant universe.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "045"
down_revision: Union[str, None] = "044"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DEFAULT_TENANT_ID = "t-default"
_TABLES_WITH_TENANT_ID = (
    "findings",
    "audit_events",
    "asset_loadouts",
    "sbom_packages",
    "openscap_scan_results",
    "users",
)


def _table_has_column(bind, table: str, column: str) -> bool:
    return bool(
        bind.execute(
            sa.text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = :table AND column_name = :column"
            ),
            {"table": table, "column": column},
        ).scalar()
    )


def upgrade() -> None:
    bind = op.get_bind()
    op.execute(
        sa.text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES (:id, 'Default Org', NOW(), 'local') "
            "ON CONFLICT (id) DO NOTHING"
        ).bindparams(id=DEFAULT_TENANT_ID)
    )

    for table in _TABLES_WITH_TENANT_ID:
        if not _table_has_column(bind, table, "tenant_id"):
            continue
        op.execute(
            sa.text(f"UPDATE {table} SET tenant_id = :tenant_id").bindparams(
                tenant_id=DEFAULT_TENANT_ID
            )
        )


def downgrade() -> None:
    # No-op: the original tenant ids cannot be reconstructed after normalization.
    pass
