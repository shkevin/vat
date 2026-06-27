"""Move decision-ledger tables into a dedicated `decisions` schema.

Realises the design's Phase 0 service/storage boundary. Tables are FK-free and
accessed only via the ORM (which now emits schema-qualified names), so this is a
metadata-only relocation.

Revision ID: 051
Revises: 050
Create Date: 2026-06-27
"""

from typing import Sequence, Union

from alembic import op

revision: str = "051"
down_revision: Union[str, None] = "050"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLES = (
    "triage_decisions",
    "triage_decision_revisions",
    "decision_finding_links",
    "decision_subject_aliases",
)


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS decisions")
    for table in _TABLES:
        op.execute(f"ALTER TABLE {table} SET SCHEMA decisions")


def downgrade() -> None:
    for table in _TABLES:
        op.execute(f"ALTER TABLE decisions.{table} SET SCHEMA public")
    op.execute("DROP SCHEMA IF EXISTS decisions")
