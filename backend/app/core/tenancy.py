"""Tenant defaults for the current single-tenant VAT deployment."""

DEFAULT_TENANT_ID = "t-default"


def default_tenant_id(_tenant_id: str | None = None) -> str:
    """Return the only tenant VAT should use while multi-tenancy is disabled."""
    return DEFAULT_TENANT_ID
