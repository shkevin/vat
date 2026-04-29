"""Finding model — core schema per PRD §8.3."""

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class FindingType(str, enum.Enum):
    SCA = "SCA"  # Software Composition Analysis (was CVE — CVE is an identifier, not a classifier)
    Secret = "Secret"
    IaC = "IaC"
    SAST = "SAST"
    License = "License"


class Severity(str, enum.Enum):
    Critical = "Critical"
    High = "High"
    Medium = "Medium"
    Low = "Low"
    Informational = "Informational"


class Status(str, enum.Enum):
    Open = "Open"
    SyncedToTracker = "SyncedToTracker"
    InReview = "InReview"
    Approved = "Approved"
    Rejected = "Rejected"
    RiskAccepted = "RiskAccepted"
    FalsePositive = "FalsePositive"
    Suppressed = "Suppressed"
    NotApplicable = "NotApplicable"
    Mitigated = "Mitigated"
    Duplicate = "Duplicate"
    Resolved = "Resolved"
    Reopened = "Reopened"


class SuppressionScope(str, enum.Enum):
    global_ = "global"  # False Positive
    contextual = "contextual"  # Suppressed


class Finding(Base):
    """Core finding entity."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    finding_type: Mapped[FindingType] = mapped_column(Enum(FindingType), nullable=False)
    fingerprint_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    cve_id: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    status: Mapped[Status] = mapped_column(Enum(Status), nullable=False)
    previous_status: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )  # for revert
    component_base: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    component: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )  # e.g. "runc 1.1.11"
    image: Mapped[Optional[str]] = mapped_column(
        String(256), nullable=True
    )  # e.g. "api-server:latest"
    branch: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )  # git branch for multi-branch repos
    tag: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )  # container image tag
    image_digest: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )  # manifest digest sha256:… (same digest = same image; multiple tags)
    title: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_file_url: Mapped[Optional[str]] = mapped_column(
        String(2048), nullable=True
    )  # Direct URL from source (e.g. Aikido)
    file_path: Mapped[Optional[str]] = mapped_column(
        String(1024), nullable=True
    )  # For location-based grouping (SAST, Secret, IaC)
    line: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    snippet_masked: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )  # Line preview with secrets masked

    # Grouping-relevant (optional; parsers populate when available)
    rule_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    ecosystem: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    secret_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    resource: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    license_expression: Mapped[Optional[str]] = mapped_column(
        String(256), nullable=True, index=True
    )
    # Phase 1 OpenSCAP identity metadata
    stable_rule_key: Mapped[Optional[str]] = mapped_column(
        String(256), nullable=True, index=True
    )
    benchmark_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    benchmark_family: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, index=True
    )
    profile_scope: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    content_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    needs_family_classification: Mapped[bool] = mapped_column(Boolean, default=False)

    source: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )  # primary source name
    team: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    control_ref: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    sla_due: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )  # ISO date
    cvss: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    epss: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    compensating_controls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewer_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tracker_comment: Mapped[bool] = mapped_column(Boolean, default=False)

    sources: Mapped[dict] = mapped_column(JSONB, default=list)  # [{name, importedAt}]
    suppression_scope: Mapped[Optional[SuppressionScope]] = mapped_column(
        Enum(SuppressionScope, values_callable=lambda obj: [e.value for e in obj]),
        nullable=True,
    )
    attestation: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    regression_of: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True
    )  # [finding_id]
    regression_count: Mapped[int] = mapped_column(Integer, default=0)
    audit: Mapped[list] = mapped_column(
        JSONB, default=list
    )  # [{ts, user, action, note}]

    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    archived_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tenant_id: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )

    # External links: [{adapter_key, kind, issue_id, url, created_at, ...}]. Unified for sources and trackers.
    external_links: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    # Cross-source correlation metadata (distinct from replay dedup fingerprint).
    correlation_key: Mapped[Optional[str]] = mapped_column(
        String(256), nullable=True, index=True
    )
    correlation_confidence: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    correlated_to: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    @property
    def tracker_id(self) -> Optional[str]:
        """Primary tracker issue_id for UI. First tracker link wins."""
        for link in self.external_links or []:
            if isinstance(link, dict) and link.get("kind") == "tracker":
                return link.get("issue_id")
        return None

    # Aikido's group_id — when source is Aikido, use for grouping (matches Aikido dashboard)
    source_issue_group_id: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )
    # Aikido source/workspace id — which Aikido integration (for per-source tracker mapping)
    aikido_source_id: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )
    sync_status: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )  # open | pending_sync | synced | sync_failed
    sync_failed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sync_last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    # Aikido's first_detected_at — when the issue was first found by the scanner. Used for report trend alignment.
    first_detected_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )
    # Aikido's closed_at — when the issue was closed/resolved. Used for report trend alignment.
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
