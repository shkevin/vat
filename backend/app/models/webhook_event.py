"""Webhook event model — idempotency for inbound webhooks."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import DateTime, String, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class WebhookEvent(Base):
    """Idempotency keys for webhook processing."""

    __tablename__ = "webhook_events"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, server_default=text("gen_random_uuid()")
    )
    # Migration 008 explicitly creates ix_webhook_events_idempotency_key with
    # unique=True on this column. Don't also pass unique=True here — it
    # makes SQLAlchemy auto-create a duplicate index on Base.metadata.create_all
    # (test paths / fresh-DB bootstrap), wasting space and write amplification.
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    payload_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    result: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
