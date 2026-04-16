"""Add feed correlation performance indexes.

Revision ID: 037
Revises: 036
Create Date: 2026-04-01
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "037"
down_revision: Union[str, None] = "036"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "ix_vuln_feed_records_package_name_lower",
        "vuln_feed_records",
        [sa.text("lower(package_name)")],
        unique=False,
    )
    op.create_index("ix_findings_source", "findings", ["source"], unique=False)
    op.create_index("ix_sbom_packages_component", "sbom_packages", ["component"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_sbom_packages_component", table_name="sbom_packages")
    op.drop_index("ix_findings_source", table_name="findings")
    op.drop_index("ix_vuln_feed_records_package_name_lower", table_name="vuln_feed_records")
