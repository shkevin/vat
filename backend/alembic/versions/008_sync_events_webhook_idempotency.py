"""sync_events, webhook_events, extend findings for source sync

Revision ID: 008
Revises: 007
Create Date: 2026-02-25

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sync_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("finding_id", sa.String(32), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target", sa.String(32), nullable=False),  # 'tracker' | 'source'
        sa.Column("target_key", sa.String(64), nullable=True),  # adapter key: 'linear', 'aikido', etc.
        sa.Column("event_type", sa.String(64), nullable=False),  # create_issue, post_decision, source_ignore, source_unignore
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_sync_events_status", "sync_events", ["status"], postgresql_where=sa.text("status IN ('pending', 'processing')"))
    op.create_index("ix_sync_events_next_retry", "sync_events", ["next_retry_at"], postgresql_where=sa.text("status = 'pending' AND next_retry_at IS NOT NULL"))
    op.create_index("ix_sync_events_finding_id", "sync_events", ["finding_id"])

    op.create_table(
        "webhook_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=True),
        sa.Column("payload_hash", sa.String(64), nullable=True),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.create_index("ix_webhook_events_idempotency_key", "webhook_events", ["idempotency_key"], unique=True)

    op.add_column("findings", sa.Column("source_issue_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("findings", sa.Column("sync_status", sa.String(32), nullable=True))
    op.add_column("findings", sa.Column("sync_failed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("sync_last_error", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "sync_last_error")
    op.drop_column("findings", "sync_failed_at")
    op.drop_column("findings", "sync_status")
    op.drop_column("findings", "source_issue_ids")
    op.drop_index("ix_webhook_events_idempotency_key", "webhook_events")
    op.drop_table("webhook_events")
    op.drop_index("ix_sync_events_finding_id", "sync_events")
    op.drop_index("ix_sync_events_next_retry", "sync_events")
    op.drop_index("ix_sync_events_status", "sync_events")
    op.drop_table("sync_events")
