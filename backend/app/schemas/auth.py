"""Auth schemas — user context for request processing."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class UserContext:
    """Resolved user with tenant and role.

    ``tenant_id`` is the tenant this caller acts within. ``cross_tenant`` is
    set when the caller is explicitly authorized to operate across all tenants
    (e.g. an admin API key bound to ``cross_tenant=True``). When
    ``cross_tenant`` is False and ``tenant_id`` is None, scoped queries must
    fail closed rather than returning unscoped rows.
    """

    user_id: str
    email: str
    tenant_id: Optional[str]
    role: str  # admin | reviewer | read_only
    raw_identity: str  # original identity string (for audit when no DB user)
    cross_tenant: bool = False
