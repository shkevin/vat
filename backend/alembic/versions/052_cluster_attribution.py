"""Multi-cluster attribution: cluster_id on observations, observed_clusters on findings.

Layer 2 of the multi-cluster design. The X-VAT-Cluster header stamps which cluster
observed a finding onto each finding_observations row; observed_clusters denormalizes
the distinct set onto findings so cluster filtering is a JSONB containment query.

Revision ID: 052
Revises: 051
Create Date: 2026-07-05
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "052"
down_revision: Union[str, None] = "051"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "finding_observations",
        sa.Column("cluster_id", sa.String(length=128), nullable=True),
    )
    op.create_index(
        "ix_finding_observations_cluster_id",
        "finding_observations",
        ["cluster_id"],
    )
    op.add_column(
        "findings",
        sa.Column("observed_clusters", JSONB, nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("findings", "observed_clusters")
    op.drop_index("ix_finding_observations_cluster_id", table_name="finding_observations")
    op.drop_column("finding_observations", "cluster_id")
