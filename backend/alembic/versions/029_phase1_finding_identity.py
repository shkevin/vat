"""Phase 1 finding identity and observation model.

Revision ID: 029
Revises: 028
Create Date: 2026-03-22
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "029"
down_revision: Union[str, None] = "028"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "finding_observations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.String(length=32), nullable=False),
        sa.Column("scan_session_id", sa.String(length=64), nullable=False),
        sa.Column("source_name", sa.String(length=64), nullable=False),
        sa.Column("scanner_version", sa.String(length=64), nullable=True),
        sa.Column("content_version", sa.String(length=64), nullable=True),
        sa.Column("benchmark_id", sa.String(length=256), nullable=True),
        sa.Column("benchmark_family", sa.String(length=128), nullable=True),
        sa.Column("profile_scope", sa.String(length=256), nullable=True),
        sa.Column("stable_rule_key", sa.String(length=256), nullable=True),
        sa.Column("result_state", sa.String(length=32), nullable=True),
        sa.Column("raw_evidence_ref", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "finding_id",
            "scan_session_id",
            "source_name",
            name="uq_finding_observation_session_source",
        ),
    )
    op.create_index(
        op.f("ix_finding_observations_finding_id"),
        "finding_observations",
        ["finding_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_observations_scan_session_id"),
        "finding_observations",
        ["scan_session_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_observations_source_name"),
        "finding_observations",
        ["source_name"],
        unique=False,
    )

    op.create_table(
        "openscap_evidence_blobs",
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("raw_xml", sa.LargeBinary(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("sha256"),
    )

    op.add_column(
        "findings", sa.Column("stable_rule_key", sa.String(length=256), nullable=True)
    )
    op.add_column(
        "findings", sa.Column("benchmark_id", sa.String(length=256), nullable=True)
    )
    op.add_column(
        "findings", sa.Column("benchmark_family", sa.String(length=128), nullable=True)
    )
    op.add_column(
        "findings", sa.Column("profile_scope", sa.String(length=256), nullable=True)
    )
    op.add_column(
        "findings", sa.Column("content_version", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "findings",
        sa.Column(
            "needs_family_classification",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.create_index(
        op.f("ix_findings_stable_rule_key"),
        "findings",
        ["stable_rule_key"],
        unique=False,
    )
    op.create_index(
        op.f("ix_findings_benchmark_family"),
        "findings",
        ["benchmark_family"],
        unique=False,
    )
    op.alter_column("findings", "needs_family_classification", server_default=None)

    op.add_column(
        "openscap_scan_results",
        sa.Column("evidence_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "openscap_scan_results",
        sa.Column("benchmark_family", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "openscap_scan_results",
        sa.Column("content_version", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "openscap_scan_results",
        sa.Column("profile_scope", sa.String(length=256), nullable=True),
    )
    op.add_column(
        "openscap_scan_results",
        sa.Column(
            "needs_family_classification",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.create_index(
        op.f("ix_openscap_scan_results_evidence_sha256"),
        "openscap_scan_results",
        ["evidence_sha256"],
        unique=False,
    )
    op.alter_column("openscap_scan_results", "raw_xccdf_xml", nullable=True)
    op.alter_column(
        "openscap_scan_results", "needs_family_classification", server_default=None
    )


def downgrade() -> None:
    op.alter_column("openscap_scan_results", "raw_xccdf_xml", nullable=False)
    op.drop_index(
        op.f("ix_openscap_scan_results_evidence_sha256"),
        table_name="openscap_scan_results",
    )
    op.drop_column("openscap_scan_results", "needs_family_classification")
    op.drop_column("openscap_scan_results", "profile_scope")
    op.drop_column("openscap_scan_results", "content_version")
    op.drop_column("openscap_scan_results", "benchmark_family")
    op.drop_column("openscap_scan_results", "evidence_sha256")

    op.drop_index(op.f("ix_findings_benchmark_family"), table_name="findings")
    op.drop_index(op.f("ix_findings_stable_rule_key"), table_name="findings")
    op.drop_column("findings", "needs_family_classification")
    op.drop_column("findings", "content_version")
    op.drop_column("findings", "profile_scope")
    op.drop_column("findings", "benchmark_family")
    op.drop_column("findings", "benchmark_id")
    op.drop_column("findings", "stable_rule_key")

    op.drop_table("openscap_evidence_blobs")

    op.drop_index(op.f("ix_finding_observations_source_name"), table_name="finding_observations")
    op.drop_index(op.f("ix_finding_observations_scan_session_id"), table_name="finding_observations")
    op.drop_index(op.f("ix_finding_observations_finding_id"), table_name="finding_observations")
    op.drop_table("finding_observations")

