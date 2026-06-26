"""Decision ledger tables — durable triage decisions independent of findings.

Revision ID: 048
Revises: 047
Create Date: 2026-06-26
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "048"
down_revision: Union[str, None] = "047"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "triage_decisions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("subject_key", sa.String(length=512), nullable=False),
        sa.Column("subject_confidence", sa.String(length=16), nullable=False),
        sa.Column("finding_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("suppression_scope", sa.String(length=32), nullable=True),
        sa.Column("justification", sa.Text(), nullable=True),
        sa.Column("compensating_controls", sa.Text(), nullable=True),
        sa.Column("reviewer_note", sa.Text(), nullable=True),
        sa.Column("attestation", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("decision_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_by", sa.String(length=256), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_by", sa.String(length=256), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("last_finding_id", sa.String(length=32), nullable=True),
        sa.Column("last_applied_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "subject_key", name="uq_triage_decisions_subject"),
    )
    op.create_index("ix_triage_decisions_tenant_status", "triage_decisions", ["tenant_id", "status"])

    op.create_table(
        "triage_decision_revisions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("decision_id", sa.String(length=64), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("actor_id", sa.String(length=256), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("decision_id", "revision", name="uq_triage_decision_revision"),
    )
    op.create_index(
        "ix_triage_decision_revisions_decision_id",
        "triage_decision_revisions",
        ["decision_id"],
    )

    op.create_table(
        "decision_subject_aliases",
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("alias_key", sa.String(length=512), nullable=False),
        sa.Column("canonical_key", sa.String(length=512), nullable=False),
        sa.Column("reason", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "alias_key"),
    )
    op.create_index(
        "ix_decision_subject_aliases_canonical",
        "decision_subject_aliases",
        ["tenant_id", "canonical_key"],
    )

    op.create_table(
        "decision_finding_links",
        sa.Column("decision_id", sa.String(length=64), nullable=False),
        sa.Column("finding_id", sa.String(length=32), nullable=False),
        sa.Column("link_method", sa.String(length=32), nullable=False),
        sa.Column("link_confidence", sa.String(length=16), nullable=False),
        sa.Column("applied_decision_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("linked_at", sa.DateTime(), nullable=False),
        sa.Column("unlinked_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("decision_id", "finding_id"),
        sa.UniqueConstraint("decision_id", "finding_id", name="uq_decision_finding_link"),
    )
    op.create_index(
        "ix_decision_finding_links_finding_active",
        "decision_finding_links",
        ["finding_id"],
        postgresql_where=sa.text("unlinked_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_decision_finding_links_finding_active", table_name="decision_finding_links")
    op.drop_table("decision_finding_links")
    op.drop_index("ix_decision_subject_aliases_canonical", table_name="decision_subject_aliases")
    op.drop_table("decision_subject_aliases")
    op.drop_index("ix_triage_decision_revisions_decision_id", table_name="triage_decision_revisions")
    op.drop_table("triage_decision_revisions")
    op.drop_index("ix_triage_decisions_tenant_status", table_name="triage_decisions")
    op.drop_table("triage_decisions")
