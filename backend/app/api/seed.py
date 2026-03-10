"""Seed API — for loading development/demo data via script."""

import bcrypt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_admin
from app.core.database import get_db
from app.schemas.auth import UserContext
from app.services.findings_service import create_findings_bulk
from app.services.sbom import import_sbom

router = APIRouter()


class SeedRequest(BaseModel):
    findings: list[dict] = []
    sbom: list[dict] = []  # [{ component, source, bom }]
    tenants: list[dict] = []
    users: list[dict] = []


@router.post("")
async def seed_all(
    body: SeedRequest,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Load seed data: findings, SBOM, tenants, users.
    Admin only. For development and demo use.
    """
    result = {"findings": 0, "sbom_created": 0, "sbom_updated": 0, "tenants": 0, "users": 0}

    try:
        if body.findings:
            count = await create_findings_bulk(db, body.findings)
            result["findings"] = count

        for item in body.sbom:
            bom = item.get("bom", item)
            component = item.get("component")
            source = item.get("source", "manual")
            created, updated = await import_sbom(db, bom, source=source, component=component)
            result["sbom_created"] += created
            result["sbom_updated"] += updated

        for t in body.tenants:
            tid = t.get("id")
            name = t.get("name", "")
            if tid:
                await db.execute(
                    text(
                        "INSERT INTO tenants (id, name, created_at) VALUES (:id, :name, NOW()) "
                        "ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name"
                    ),
                    {"id": tid, "name": name},
                )
                result["tenants"] += 1
        if body.tenants:
            await db.commit()

        for u in body.users:
            uid = u.get("id")
            tenant_id = u.get("tenant_id")
            email = u.get("email", "")
            role = u.get("role", "reviewer")
            password = u.get("password")
            password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8") if password else None
            if uid:
                await db.execute(
                    text(
                        "INSERT INTO users (id, tenant_id, email, role, password_hash, created_at) "
                        "VALUES (:id, :tenant_id, :email, :role, :password_hash, NOW()) "
                        "ON CONFLICT (id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id, email = EXCLUDED.email, "
                        "role = EXCLUDED.role, password_hash = COALESCE(EXCLUDED.password_hash, users.password_hash)"
                    ),
                    {"id": uid, "tenant_id": tenant_id, "email": email, "role": role, "password_hash": password_hash},
                )
                result["users"] += 1
        if body.users:
            await db.commit()

        return {
            **result,
            "message": f"Seeded {result['findings']} findings, {result['sbom_created']}+{result['sbom_updated']} SBOM packages, {result['tenants']} tenants, {result['users']} users",
        }
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail=str(e.orig) if e.orig else str(e))
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
