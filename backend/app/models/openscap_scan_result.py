"""OpenSCAP scan result model — raw XCCDF/OVAL XML for STIG Viewer export."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.tenant_scoped import TenantScopedMixin


class OpenSCAPScanResult(TenantScopedMixin, Base):
    """
    Stores raw XCCDF/OVAL XML from OpenSCAP scans.
    Used for export to STIG Viewer (IronBank pipeline pattern).
    Re-scans overwrite by (asset_id, source_id).
    """

    __tablename__ = "openscap_scan_results"

    asset_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    source_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    raw_xccdf_xml: Mapped[bytes | None] = mapped_column(LargeBinary(), nullable=True)
    evidence_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    benchmark_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    benchmark_family: Mapped[str | None] = mapped_column(String(128), nullable=True)
    content_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    profile_scope: Mapped[str | None] = mapped_column(String(256), nullable=True)
    needs_family_classification: Mapped[bool] = mapped_column(Boolean, default=False)
    parser_id: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # openscap | openscap_oval
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
