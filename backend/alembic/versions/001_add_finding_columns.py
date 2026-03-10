"""create findings table

Revision ID: 001
Revises:
Create Date: 2025-02-23

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("finding_type", sa.Enum("CVE", "Secret", "IaC", "SAST", "License", name="findingtype"), nullable=False),
        sa.Column("fingerprint_id", sa.String(64), nullable=False),
        sa.Column("cve_id", sa.String(128), nullable=False),
        sa.Column("severity", sa.Enum("Critical", "High", "Medium", "Low", "Informational", name="severity"), nullable=False),
        sa.Column("status", sa.Enum("Open", "SyncedToTracker", "InReview", "Approved", "Rejected", "RiskAccepted", "FalsePositive", "Suppressed", "NotApplicable", "Mitigated", "Duplicate", "Resolved", "Reopened", name="status"), nullable=False),
        sa.Column("component_base", sa.String(256), nullable=True),
        sa.Column("component", sa.String(512), nullable=True),
        sa.Column("image", sa.String(256), nullable=True),
        sa.Column("title", sa.String(512), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source", sa.String(64), nullable=True),
        sa.Column("team", sa.String(128), nullable=True),
        sa.Column("owner", sa.String(256), nullable=True),
        sa.Column("tracker_id", sa.String(64), nullable=True),
        sa.Column("control_ref", sa.String(64), nullable=True),
        sa.Column("sla_due", sa.String(32), nullable=True),
        sa.Column("cvss", sa.String(16), nullable=True),
        sa.Column("epss", sa.String(16), nullable=True),
        sa.Column("justification", sa.Text(), nullable=True),
        sa.Column("compensating_controls", sa.Text(), nullable=True),
        sa.Column("reviewer_note", sa.Text(), nullable=True),
        sa.Column("tracker_comment", sa.Boolean(), default=False),
        sa.Column("sources", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("suppression_scope", sa.Enum("global", "contextual", name="suppressionscope"), nullable=True),
        sa.Column("attestation", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("regression_of", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("regression_count", sa.Integer(), default=0),
        sa.Column("audit", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("archived", sa.Boolean(), default=False),
        sa.Column("archived_at", sa.DateTime(), nullable=True),
        sa.Column("archived_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_findings_fingerprint_id", "findings", ["fingerprint_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_findings_fingerprint_id", "findings")
    op.drop_table("findings")
