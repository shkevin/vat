"""Add audit_events table for enterprise auditability

Revision ID: 022
Revises: 021
Create Date: 2026-03-19

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "022"
down_revision: Union[str, None] = "021"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(length=64), primary_key=True),
        sa.Column("trace_id", sa.String(length=64), nullable=False),
        sa.Column("parent_event_id", sa.String(length=64), nullable=True),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("actor_type", sa.String(length=32), nullable=False, server_default="system"),
        sa.Column("actor_id", sa.String(length=256), nullable=True),
        sa.Column("source_id", sa.String(length=128), nullable=True),
        sa.Column("parser_id", sa.String(length=64), nullable=True),
        sa.Column("asset_id", sa.String(length=512), nullable=True),
        sa.Column("finding_id", sa.String(length=32), nullable=True),
        sa.Column("decision_name", sa.String(length=128), nullable=True),
        sa.Column("decision_reason_code", sa.String(length=128), nullable=True),
        sa.Column("decision_confidence", sa.String(length=32), nullable=True),
        sa.Column("decision_result", sa.String(length=64), nullable=True),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("prev_record_hash", sa.String(length=128), nullable=True),
        sa.Column("record_hash", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("retention_class", sa.String(length=32), nullable=False, server_default="operational"),
        sa.Column("redaction_level", sa.String(length=32), nullable=False, server_default="standard"),
        sa.Column("sensitivity", sa.String(length=32), nullable=False, server_default="internal"),
        sa.Column("note", sa.Text(), nullable=True),
    )

    op.create_index("ix_audit_events_trace_id", "audit_events", ["trace_id"], unique=False)
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"], unique=False)
    op.create_index("ix_audit_events_source_id", "audit_events", ["source_id"], unique=False)
    op.create_index("ix_audit_events_parser_id", "audit_events", ["parser_id"], unique=False)
    op.create_index("ix_audit_events_asset_id", "audit_events", ["asset_id"], unique=False)
    op.create_index("ix_audit_events_finding_id", "audit_events", ["finding_id"], unique=False)
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"], unique=False)
    op.create_index("ix_audit_events_trace_created", "audit_events", ["trace_id", "created_at"], unique=False)
    op.create_index(
        "ix_audit_events_source_parser_created",
        "audit_events",
        ["source_id", "parser_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("audit_events")

