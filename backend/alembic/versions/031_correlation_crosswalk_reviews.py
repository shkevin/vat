"""Add crosswalk and correlation review tables.

Revision ID: 031
Revises: 030
Create Date: 2026-03-22
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "031"
down_revision: Union[str, None] = "030"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "crosswalk_runs",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("source_version", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("trace_id", sa.String(length=64), nullable=True),
        sa.Column("input_checksum", sa.String(length=64), nullable=True),
        sa.Column(
            "stats",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=256), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_crosswalk_runs_source"), "crosswalk_runs", ["source"], unique=False)
    op.create_index(
        op.f("ix_crosswalk_runs_source_version"),
        "crosswalk_runs",
        ["source_version"],
        unique=False,
    )
    op.create_index(op.f("ix_crosswalk_runs_status"), "crosswalk_runs", ["status"], unique=False)
    op.create_index(
        op.f("ix_crosswalk_runs_trace_id"), "crosswalk_runs", ["trace_id"], unique=False
    )
    op.alter_column("crosswalk_runs", "stats", server_default=None)

    op.create_table(
        "crosswalk_entries",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("source_version", sa.String(length=64), nullable=False),
        sa.Column("from_namespace", sa.String(length=64), nullable=False),
        sa.Column("from_value", sa.String(length=256), nullable=False),
        sa.Column("to_namespace", sa.String(length=64), nullable=False),
        sa.Column("to_value", sa.String(length=256), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "metadata_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("last_verified_at", sa.DateTime(), nullable=True),
        sa.Column("disabled_at", sa.DateTime(), nullable=True),
        sa.Column("disabled_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "from_namespace",
            "from_value",
            "to_namespace",
            "to_value",
            "source",
            "source_version",
            name="uq_crosswalk_entries_mapping",
        ),
    )
    op.create_index(
        op.f("ix_crosswalk_entries_run_id"), "crosswalk_entries", ["run_id"], unique=False
    )
    op.create_index(
        op.f("ix_crosswalk_entries_source"), "crosswalk_entries", ["source"], unique=False
    )
    op.create_index(
        op.f("ix_crosswalk_entries_source_version"),
        "crosswalk_entries",
        ["source_version"],
        unique=False,
    )
    op.create_index(
        op.f("ix_crosswalk_entries_from_namespace"),
        "crosswalk_entries",
        ["from_namespace"],
        unique=False,
    )
    op.create_index(
        op.f("ix_crosswalk_entries_from_value"),
        "crosswalk_entries",
        ["from_value"],
        unique=False,
    )
    op.create_index(
        op.f("ix_crosswalk_entries_to_namespace"),
        "crosswalk_entries",
        ["to_namespace"],
        unique=False,
    )
    op.create_index(
        op.f("ix_crosswalk_entries_to_value"), "crosswalk_entries", ["to_value"], unique=False
    )
    op.create_index(
        op.f("ix_crosswalk_entries_active"), "crosswalk_entries", ["active"], unique=False
    )
    op.alter_column("crosswalk_entries", "active", server_default=None)
    op.alter_column("crosswalk_entries", "metadata_json", server_default=None)

    op.create_table(
        "correlation_reviews",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("finding_id_a", sa.String(length=32), nullable=False),
        sa.Column("finding_id_b", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("operation_id", sa.String(length=64), nullable=True),
        sa.Column("created_by", sa.String(length=256), nullable=True),
        sa.Column("updated_by", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id_a", "finding_id_b", name="uq_correlation_reviews_pair"),
    )
    op.create_index(
        op.f("ix_correlation_reviews_finding_id_a"),
        "correlation_reviews",
        ["finding_id_a"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_reviews_finding_id_b"),
        "correlation_reviews",
        ["finding_id_b"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_reviews_status"),
        "correlation_reviews",
        ["status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_reviews_operation_id"),
        "correlation_reviews",
        ["operation_id"],
        unique=False,
    )
    op.alter_column("correlation_reviews", "evidence", server_default=None)

    op.create_table(
        "correlation_review_decisions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("review_id", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=24), nullable=False),
        sa.Column("decided_by", sa.String(length=256), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column(
            "evidence_used",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_correlation_review_decisions_review_id"),
        "correlation_review_decisions",
        ["review_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_review_decisions_decision"),
        "correlation_review_decisions",
        ["decision"],
        unique=False,
    )
    op.alter_column("correlation_review_decisions", "evidence_used", server_default=None)


def downgrade() -> None:
    op.drop_index(
        op.f("ix_correlation_review_decisions_decision"),
        table_name="correlation_review_decisions",
    )
    op.drop_index(
        op.f("ix_correlation_review_decisions_review_id"),
        table_name="correlation_review_decisions",
    )
    op.drop_table("correlation_review_decisions")

    op.drop_index(op.f("ix_correlation_reviews_operation_id"), table_name="correlation_reviews")
    op.drop_index(op.f("ix_correlation_reviews_status"), table_name="correlation_reviews")
    op.drop_index(op.f("ix_correlation_reviews_finding_id_b"), table_name="correlation_reviews")
    op.drop_index(op.f("ix_correlation_reviews_finding_id_a"), table_name="correlation_reviews")
    op.drop_table("correlation_reviews")

    op.drop_index(op.f("ix_crosswalk_entries_active"), table_name="crosswalk_entries")
    op.drop_index(op.f("ix_crosswalk_entries_to_value"), table_name="crosswalk_entries")
    op.drop_index(op.f("ix_crosswalk_entries_to_namespace"), table_name="crosswalk_entries")
    op.drop_index(op.f("ix_crosswalk_entries_from_value"), table_name="crosswalk_entries")
    op.drop_index(op.f("ix_crosswalk_entries_from_namespace"), table_name="crosswalk_entries")
    op.drop_index(op.f("ix_crosswalk_entries_source_version"), table_name="crosswalk_entries")
    op.drop_index(op.f("ix_crosswalk_entries_source"), table_name="crosswalk_entries")
    op.drop_index(op.f("ix_crosswalk_entries_run_id"), table_name="crosswalk_entries")
    op.drop_table("crosswalk_entries")

    op.drop_index(op.f("ix_crosswalk_runs_trace_id"), table_name="crosswalk_runs")
    op.drop_index(op.f("ix_crosswalk_runs_status"), table_name="crosswalk_runs")
    op.drop_index(op.f("ix_crosswalk_runs_source_version"), table_name="crosswalk_runs")
    op.drop_index(op.f("ix_crosswalk_runs_source"), table_name="crosswalk_runs")
    op.drop_table("crosswalk_runs")

