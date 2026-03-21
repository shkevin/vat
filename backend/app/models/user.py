"""User and Tenant models — RBAC, multi-tenant foundation. v2.0."""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

AUTH_METHOD_LOCAL = "local"
AUTH_METHOD_GOOGLE = "google"
AUTH_METHOD_GENERIC_OIDC = "generic_oidc"
AUTH_METHOD_SAML = "saml"


class Tenant(Base):
    """Tenant for multi-tenant isolation."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    auth_method: Mapped[str] = mapped_column(
        String(32), nullable=False, default=AUTH_METHOD_LOCAL
    )
    auth_config: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)


class User(Base):
    """User with tenant and role for RBAC."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("tenants.id"), nullable=True, index=True
    )
    email: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # admin | reviewer | read_only
    password_hash: Mapped[Optional[str]] = mapped_column(
        String(256), nullable=True
    )  # for local login
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# Role constants for RBAC
ROLE_ADMIN = "admin"
ROLE_REVIEWER = "reviewer"
ROLE_READ_ONLY = "read_only"
