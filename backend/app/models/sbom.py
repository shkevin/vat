"""SBOM package model — CycloneDX import, license risk. PRD §5.8."""

import re
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.tenant_scoped import TenantScopedMixin


# License risk tiers per PRD §5.8.2
LICENSE_RISK_CRITICAL = {"AGPL-3.0", "SSPL-1.0"}
LICENSE_RISK_HIGH = {"GPL-2.0", "GPL-3.0"}
LICENSE_RISK_MEDIUM = {"LGPL-2.1", "LGPL-3.0", "MPL-2.0", "CDDL-1.0"}
LICENSE_RISK_LOW = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unlicense",
    "CC0-1.0",
}

_LICENSE_RISK_ORDER = ["Critical", "High", "Medium", "Low", "Unknown"]
_LICENSE_RISK_RANK = {name: idx for idx, name in enumerate(_LICENSE_RISK_ORDER)}

_LICENSE_RISK_BY_ID: dict[str, str] = {}
for _license_id in LICENSE_RISK_CRITICAL:
    _LICENSE_RISK_BY_ID[_license_id.lower()] = "Critical"
for _license_id in LICENSE_RISK_HIGH:
    _LICENSE_RISK_BY_ID[_license_id.lower()] = "High"
for _license_id in LICENSE_RISK_MEDIUM:
    _LICENSE_RISK_BY_ID[_license_id.lower()] = "Medium"
for _license_id in LICENSE_RISK_LOW:
    _LICENSE_RISK_BY_ID[_license_id.lower()] = "Low"

_SPDX_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
_SPDX_OPERATORS = {"AND", "OR", "WITH"}
_SPDX_SUFFIXES = ("-or-later", "-only")


def _normalize_spdx_token(token: str) -> str:
    normalized = (token or "").strip()
    if not normalized:
        return ""
    if normalized.upper() in _SPDX_OPERATORS:
        return ""
    if normalized.endswith("+"):
        normalized = normalized[:-1]
    lower = normalized.lower()
    for suffix in _SPDX_SUFFIXES:
        if lower.endswith(suffix):
            normalized = normalized[: -len(suffix)]
            break
    return normalized.strip()


def _iter_license_ids(license_expression: str) -> list[str]:
    expression = (license_expression or "").strip()
    if not expression:
        return []
    tokens = [_normalize_spdx_token(tok) for tok in _SPDX_TOKEN_RE.findall(expression)]
    tokens = [tok for tok in tokens if tok]
    if tokens:
        return tokens
    fallback = _normalize_spdx_token(expression)
    return [fallback] if fallback else []


def license_risk_tier(license_id: str) -> str:
    """Classify a SPDX id/expression into a single risk tier."""
    candidates = _iter_license_ids(license_id)
    if not candidates:
        return "Unknown"
    best = "Unknown"
    for candidate in candidates:
        tier = _LICENSE_RISK_BY_ID.get(candidate.lower())
        if not tier:
            continue
        if _LICENSE_RISK_RANK[tier] < _LICENSE_RISK_RANK[best]:
            best = tier
    return best


class SbomPackage(TenantScopedMixin, Base):
    """SBOM package — deduplicated by name+version, source-attributed."""

    __tablename__ = "sbom_packages"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True
    )  # hash(name|version|component)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    license_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    license_risk: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )  # Critical|High|Medium|Low|Unknown
    component: Mapped[Optional[str]] = mapped_column(
        String(256), nullable=True, index=True
    )  # image or service
    language: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    purl: Mapped[Optional[str]] = mapped_column(String(512), nullable=True, index=True)
    purl_source: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )  # authoritative|derived
    purl_confidence: Mapped[Optional[str]] = mapped_column(
        String(16), nullable=True
    )  # high|medium
    sources: Mapped[list] = mapped_column(JSONB, default=list)  # [{name, importedAt}]
    tenant_id: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
