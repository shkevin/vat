"""Add purl provenance columns to sbom_packages.

Revision ID: 039
Revises: 038
Create Date: 2026-04-02
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "039"
down_revision: Union[str, None] = "038"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "sbom_packages", sa.Column("purl_source", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "sbom_packages", sa.Column("purl_confidence", sa.String(length=16), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("sbom_packages", "purl_confidence")
    op.drop_column("sbom_packages", "purl_source")
