"""Backfill NULL-tenant legacy rows to the sole tenant when one exists.

Revision ID: 044
Revises: 043
Create Date: 2026-04-30

C2 made tenant scoping fail-closed: queries no longer surface
``tenant_id IS NULL`` rows to tenant-bound callers. Existing
deployments that ingested data before multi-tenancy was wired up have
NULL-tenant rows that became invisible to their users — admins on a
single-tenant cluster suddenly couldn't see their findings/SBOM/audit.

This migration is **conservative**: it only backfills when the
deployment has exactly one tenant. In that case the NULL rows
unambiguously belong to that tenant, and assigning them is just
correcting a pre-multi-tenant artifact. On multi-tenant deployments
(>1 tenant) it no-ops and emits a notice — the operator must
disambiguate manually because there's no way to know which NULL row
belongs to which tenant.

Tables affected: findings, audit_events, asset_loadouts, sbom_packages,
openscap_scan_results.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "044"
down_revision: Union[str, None] = "043"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLES_WITH_TENANT_ID = (
    "findings",
    "audit_events",
    "asset_loadouts",
    "sbom_packages",
    "openscap_scan_results",
)


def upgrade() -> None:
    bind = op.get_bind()

    # Single-tenant guard. Only backfill when there's exactly one tenant —
    # otherwise we can't disambiguate without operator input.
    tenants = bind.execute(sa.text("SELECT id FROM tenants")).fetchall()
    if len(tenants) != 1:
        op.execute(
            "DO $$ BEGIN RAISE NOTICE "
            "'044: skipping NULL-tenant backfill (found % tenants; operator must disambiguate)', "
            f"{len(tenants)}; END $$;"
        )
        return

    target_tenant_id = tenants[0][0]
    op.execute(
        f"DO $$ BEGIN RAISE NOTICE '044: backfilling NULL-tenant rows to tenant_id=%', '{target_tenant_id}'; END $$;"
    )
    for table in _TABLES_WITH_TENANT_ID:
        # Skip tables that don't exist in this deploy (defensive — some
        # tables are conditional on optional features).
        exists = bind.execute(
            sa.text(
                "SELECT 1 FROM information_schema.tables WHERE table_name = :t"
            ),
            {"t": table},
        ).scalar()
        if not exists:
            continue
        # Skip when the column is missing — also defensive.
        col_exists = bind.execute(
            sa.text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = :t AND column_name = 'tenant_id'"
            ),
            {"t": table},
        ).scalar()
        if not col_exists:
            continue
        op.execute(
            sa.text(
                f"UPDATE {table} SET tenant_id = :tid WHERE tenant_id IS NULL"
            ).bindparams(tid=target_tenant_id)
        )


def downgrade() -> None:
    # No-op: we cannot distinguish "originally NULL" rows from rows
    # legitimately inserted under target_tenant_id after the upgrade.
    # Leave the data alone on rollback.
    pass
