"""User schemas."""

from typing import Optional

try:
    from pydantic import BaseModel, ConfigDict, EmailStr, Field

    _PYDANTIC_V2 = True
except (
    ImportError
):  # pragma: no cover - compatibility for pydantic v1 test environments
    from pydantic import BaseModel, EmailStr, Field

    _PYDANTIC_V2 = False


class UserCreate(BaseModel):
    id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    tenant_id: Optional[str] = None
    email: EmailStr
    role: str = Field(..., pattern=r"^(admin|reviewer|read_only)$")


class UserUpdate(BaseModel):
    tenant_id: Optional[str] = None
    role: Optional[str] = Field(None, pattern=r"^(admin|reviewer|read_only)$")


class UserRead(BaseModel):
    if _PYDANTIC_V2:
        model_config = ConfigDict(from_attributes=True)
    else:

        class Config:
            orm_mode = True

    id: str
    tenant_id: Optional[str]
    email: str
    role: str
