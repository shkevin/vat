"""Backfill NULL tenant_id rows to t-default.

Revision ID: 049
Revises: 048
Create Date: 2026-06-26

Rows ingested before tenant normalization could retain NULL tenant_id while
still appearing in single-tenant list queries. Stamp them to the default
tenant so detail APIs and correlation queries stay consistent.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "049"
down_revision: Union[str, None] = "048"
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
    "triage_decisions",
    "decision_subject_aliases",
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
    for table in _TABLES_WITH_TENANT_ID:
        if not _table_has_column(bind, table, "tenant_id"):
            continue
        op.execute(
            sa.text(
                f"UPDATE {table} SET tenant_id = :tenant_id "
                "WHERE tenant_id IS NULL OR tenant_id = '_global'"
            ).bindparams(tenant_id=DEFAULT_TENANT_ID)
        )

    if _table_has_column(bind, "triage_decisions", "subject_key"):
        op.execute(
            sa.text(
                "UPDATE triage_decisions SET subject_key = REPLACE(subject_key, "
                "'decision:v1:_global:', 'decision:v1:t-default:') "
                "WHERE subject_key LIKE 'decision:v1:_global:%'"
            )
        )
    if _table_has_column(bind, "decision_subject_aliases", "alias_key"):
        op.execute(
            sa.text(
                "UPDATE decision_subject_aliases SET alias_key = REPLACE(alias_key, "
                "'decision:v1:_global:', 'decision:v1:t-default:') "
                "WHERE alias_key LIKE 'decision:v1:_global:%'"
            )
        )
        op.execute(
            sa.text(
                "UPDATE decision_subject_aliases SET canonical_key = REPLACE(canonical_key, "
                "'decision:v1:_global:', 'decision:v1:t-default:') "
                "WHERE canonical_key LIKE 'decision:v1:_global:%'"
            )
        )


def downgrade() -> None:
    pass
