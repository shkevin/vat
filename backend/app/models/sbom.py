"""SBOM package model — CycloneDX import, license risk. PRD §5.8."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


# License risk tiers per PRD §5.8.2
LICENSE_RISK_CRITICAL = {"AGPL-3.0", "SSPL-1.0"}
LICENSE_RISK_HIGH = {"GPL-2.0", "GPL-3.0"}
LICENSE_RISK_MEDIUM = {"LGPL-2.1", "LGPL-3.0", "MPL-2.0", "CDDL-1.0"}
LICENSE_RISK_LOW = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense", "CC0-1.0"}


def license_risk_tier(license_id: str) -> str:
    """Classify license into risk tier."""
    lid = (license_id or "").strip()
    if lid in LICENSE_RISK_CRITICAL:
        return "Critical"
    if lid in LICENSE_RISK_HIGH:
        return "High"
    if lid in LICENSE_RISK_MEDIUM:
        return "Medium"
    if lid in LICENSE_RISK_LOW:
        return "Low"
    return "Unknown"


class SbomPackage(Base):
    """SBOM package — deduplicated by name+version, source-attributed."""

    __tablename__ = "sbom_packages"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # hash(name|version|component)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    license_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    license_risk: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)  # Critical|High|Medium|Low|Unknown
    component: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)  # image or service
    language: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    sources: Mapped[list] = mapped_column(JSONB, default=list)  # [{name, importedAt}]
    tenant_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
