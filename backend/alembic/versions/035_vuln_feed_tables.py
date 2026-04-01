"""Add vulnerability feed ingestion tables.

Revision ID: 035
Revises: 034
Create Date: 2026-04-01
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "035"
down_revision: Union[str, None] = "034"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vuln_feed_runs",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column(
            "status", sa.String(length=32), nullable=False, server_default="completed"
        ),
        sa.Column("trace_id", sa.String(length=64), nullable=True),
        sa.Column(
            "stats",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_vuln_feed_runs_source"), "vuln_feed_runs", ["source"])
    op.create_index(op.f("ix_vuln_feed_runs_status"), "vuln_feed_runs", ["status"])
    op.create_index(op.f("ix_vuln_feed_runs_trace_id"), "vuln_feed_runs", ["trace_id"])
    op.alter_column("vuln_feed_runs", "status", server_default=None)
    op.alter_column("vuln_feed_runs", "stats", server_default=None)

    op.create_table(
        "vuln_feed_sources",
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("last_status", sa.String(length=32), nullable=False, server_default="never"),
        sa.Column("last_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_etag", sa.String(length=256), nullable=True),
        sa.Column("last_checksum", sa.String(length=128), nullable=True),
        sa.Column("last_item_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("source"),
    )
    op.create_index(
        op.f("ix_vuln_feed_sources_last_status"),
        "vuln_feed_sources",
        ["last_status"],
    )
    op.alter_column("vuln_feed_sources", "last_status", server_default=None)
    op.alter_column("vuln_feed_sources", "last_item_count", server_default=None)

    op.create_table(
        "vuln_feed_records",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("record_key", sa.String(length=256), nullable=False),
        sa.Column("vulnerability_id", sa.String(length=128), nullable=True),
        sa.Column(
            "aliases",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("package_name", sa.String(length=256), nullable=True),
        sa.Column("ecosystem", sa.String(length=64), nullable=True),
        sa.Column("version", sa.String(length=128), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("published_at", sa.DateTime(), nullable=True),
        sa.Column("modified_at", sa.DateTime(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source", "record_key", name="uq_vuln_feed_records_source_key"),
    )
    op.create_index(
        op.f("ix_vuln_feed_records_source"), "vuln_feed_records", ["source"], unique=False
    )
    op.create_index(
        op.f("ix_vuln_feed_records_vulnerability_id"),
        "vuln_feed_records",
        ["vulnerability_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_vuln_feed_records_fetched_at"),
        "vuln_feed_records",
        ["fetched_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_vuln_feed_records_run_id"),
        "vuln_feed_records",
        ["run_id"],
        unique=False,
    )
    op.create_index(
        "ix_vuln_feed_records_source_vuln",
        "vuln_feed_records",
        ["source", "vulnerability_id"],
        unique=False,
    )
    op.alter_column("vuln_feed_records", "aliases", server_default=None)
    op.alter_column("vuln_feed_records", "details", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_vuln_feed_records_source_vuln", table_name="vuln_feed_records")
    op.drop_index(op.f("ix_vuln_feed_records_run_id"), table_name="vuln_feed_records")
    op.drop_index(op.f("ix_vuln_feed_records_fetched_at"), table_name="vuln_feed_records")
    op.drop_index(
        op.f("ix_vuln_feed_records_vulnerability_id"), table_name="vuln_feed_records"
    )
    op.drop_index(op.f("ix_vuln_feed_records_source"), table_name="vuln_feed_records")
    op.drop_table("vuln_feed_records")

    op.drop_index(op.f("ix_vuln_feed_sources_last_status"), table_name="vuln_feed_sources")
    op.drop_table("vuln_feed_sources")

    op.drop_index(op.f("ix_vuln_feed_runs_trace_id"), table_name="vuln_feed_runs")
    op.drop_index(op.f("ix_vuln_feed_runs_status"), table_name="vuln_feed_runs")
    op.drop_index(op.f("ix_vuln_feed_runs_source"), table_name="vuln_feed_runs")
    op.drop_table("vuln_feed_runs")
