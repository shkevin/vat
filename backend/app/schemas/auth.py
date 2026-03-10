"""Auth schemas — user context for request processing."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class UserContext:
    """Resolved user with tenant and role."""

    user_id: str
    email: str
    tenant_id: Optional[str]
    role: str  # admin | reviewer | read_only
    raw_identity: str  # original identity string (for audit when no DB user)
