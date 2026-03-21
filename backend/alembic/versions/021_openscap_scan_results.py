"""Add openscap_scan_results table for STIG Viewer export

Revision ID: 021
Revises: 020
Create Date: 2026-03-09

Stores raw XCCDF/OVAL XML from OpenSCAP scans so export can include
STIG Viewer-importable files (IronBank pipeline pattern).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "021"
down_revision: Union[str, None] = "020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "openscap_scan_results",
        sa.Column("asset_id", sa.String(256), primary_key=True),
        sa.Column("source_id", sa.String(64), primary_key=True),
        sa.Column("raw_xccdf_xml", sa.LargeBinary(), nullable=False),
        sa.Column("benchmark_id", sa.String(256), nullable=True),
        sa.Column("parser_id", sa.String(32), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("tenant_id", sa.String(64), nullable=True),
    )
    op.create_index(
        "ix_openscap_scan_tenant",
        "openscap_scan_results",
        ["tenant_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("openscap_scan_results")
