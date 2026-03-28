"""Observed container tags per canonical asset."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AssetObservedTag(Base):
    __tablename__ = "asset_observed_tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    tag: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_scan_session_id: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    last_digest: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
