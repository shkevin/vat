"""Users API — CRUD for user provisioning."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_admin
from app.core.database import get_db
from app.models.user import User
from app.schemas.auth import UserContext
from app.schemas.user_schema import UserCreate, UserRead, UserUpdate

router = APIRouter()


@router.get("", response_model=list[UserRead])
async def list_users(
    db: AsyncSession = Depends(get_db),
    tenant_id: Optional[str] = Query(None),
    _ctx: UserContext = Depends(require_admin),
):
    """List users. Admin only. Optional tenant_id filter."""
    q = select(User)
    if tenant_id:
        q = q.where(User.tenant_id == tenant_id)
    q = q.order_by(User.email)
    result = await db.execute(q)
    users = result.scalars().all()
    return [UserRead.model_validate(u) for u in users]


@router.post("", response_model=UserRead, status_code=201)
async def create_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Create a user. Admin only."""
    user = User(
        id=body.id,
        tenant_id=body.tenant_id,
        email=body.email,
        role=body.role,
    )
    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail=str(e))
    return UserRead.model_validate(user)


@router.patch("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: str,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Update a user. Admin only."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if body.tenant_id is not None:
        user.tenant_id = body.tenant_id
    if body.role is not None:
        user.role = body.role
    await db.commit()
    await db.refresh(user)
    return UserRead.model_validate(user)


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Delete a user. Admin only. Cannot delete the last admin."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == "admin":
        admin_count = await db.scalar(select(func.count()).select_from(User).where(User.role == "admin"))
        if admin_count <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the last admin. At least one admin must remain.",
            )
    await db.delete(user)
    await db.commit()
