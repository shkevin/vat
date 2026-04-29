"""Asset loadout — named, persisted set of asset entries.

Replaces the localStorage-only ``vat-asset-loadouts`` so loadouts survive
across browsers/devices and can later be shared across a team within a
tenant. ``shared_with_team=True`` makes the loadout visible to all users
in the same tenant; ``False`` keeps it private to the owner.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


def _new_id() -> str:
    return f"ldo-{uuid.uuid4().hex[:12]}"


class AssetLoadout(Base):
    __tablename__ = "asset_loadouts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_new_id)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    owner_email: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    asset_ids: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    # Optional richer entries (with branch/tag context). Same shape as
    # FavoriteEntry on the frontend. When unset, asset_ids is authoritative.
    entries: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(JSONB, nullable=True)
    shared_with_team: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
