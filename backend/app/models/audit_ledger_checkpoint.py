"""Daily audit ledger checkpoint anchors."""

from datetime import datetime

from sqlalchemy import DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditLedgerCheckpoint(Base):
    """Tamper-evidence anchor hash by day and retention class."""

    __tablename__ = "audit_ledger_checkpoints"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    checkpoint_date: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    retention_class: Mapped[str] = mapped_column(String(32), nullable=False, default="operational")
    event_count: Mapped[int] = mapped_column(nullable=False, default=0)
    anchor_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("checkpoint_date", "retention_class", name="uq_audit_checkpoint_date_class"),
    )

