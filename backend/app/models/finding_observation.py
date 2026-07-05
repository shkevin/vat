"""Per-scan observation history for findings (Phase 1)."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class FindingObservation(Base):
    __tablename__ = "finding_observations"
    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "scan_session_id",
            "source_name",
            name="uq_finding_observation_session_source",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    scan_session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Cluster that observed this finding (X-VAT-Cluster). Multi-cluster attribution:
    # distinct cluster_id over a finding's observations = the clusters it appears in.
    cluster_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    scanner_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    content_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    benchmark_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    benchmark_family: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    profile_scope: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    stable_rule_key: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    result_state: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    raw_evidence_ref: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

