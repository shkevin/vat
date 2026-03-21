"""Tenant schemas."""

from typing import Any, Optional

try:
    from pydantic import BaseModel, ConfigDict, Field

    _PYDANTIC_V2 = True
except ImportError:  # pragma: no cover - compatibility for pydantic v1 test environments
    from pydantic import BaseModel, Field

    _PYDANTIC_V2 = False


class TenantCreate(BaseModel):
    id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(..., min_length=1, max_length=128)
    auth_method: str = Field(
        default="local", pattern=r"^(local|google|generic_oidc|saml)$"
    )


class TenantRead(BaseModel):
    if _PYDANTIC_V2:
        model_config = ConfigDict(from_attributes=True)
    else:
        class Config:
            orm_mode = True

    id: str
    name: str
    auth_method: str = "local"
    auth_config: Optional[dict[str, Any]] = None


class TenantUpdate(BaseModel):
    auth_method: Optional[str] = Field(
        default=None, pattern=r"^(local|google|generic_oidc|saml)$"
    )
