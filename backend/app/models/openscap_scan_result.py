"""OpenSCAP scan result model — raw XCCDF/OVAL XML for STIG Viewer export."""

from datetime import datetime

from sqlalchemy import DateTime, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class OpenSCAPScanResult(Base):
    """
    Stores raw XCCDF/OVAL XML from OpenSCAP scans.
    Used for export to STIG Viewer (IronBank pipeline pattern).
    Re-scans overwrite by (asset_id, source_id).
    """

    __tablename__ = "openscap_scan_results"

    asset_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    source_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    raw_xccdf_xml: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    benchmark_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    parser_id: Mapped[str] = mapped_column(String(32), nullable=False)  # openscap | openscap_oval
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
