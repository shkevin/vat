"""Tracks per-finding changes made during manual asset merge."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AssetMergeEvent(Base):
    __tablename__ = "asset_merge_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_asset_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    target_asset_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    prev_values: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    next_values: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    reverted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
