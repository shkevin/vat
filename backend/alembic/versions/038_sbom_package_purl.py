"""Add purl column to sbom_packages.

Revision ID: 038
Revises: 037
Create Date: 2026-04-02
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "038"
down_revision: Union[str, None] = "037"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("sbom_packages", sa.Column("purl", sa.String(length=512), nullable=True))
    op.create_index("ix_sbom_packages_purl", "sbom_packages", ["purl"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_sbom_packages_purl", table_name="sbom_packages")
    op.drop_column("sbom_packages", "purl")
