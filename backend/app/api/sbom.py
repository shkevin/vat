"""SBOM API — CycloneDX import, list packages, download. PRD §5.8."""

import csv
import io
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_reviewer
from app.core.database import get_db
from app.schemas.auth import UserContext
from app.services.sbom import import_sbom, list_sbom_packages

router = APIRouter()

# Cap upload bodies to limit DoS surface. CycloneDX docs are typically <5 MB;
# the cap is generous but bounded so a single client cannot OOM the worker.
MAX_SBOM_BYTES = 25 * 1024 * 1024


def _validate_cyclonedx(doc: object) -> dict:
    if not isinstance(doc, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CycloneDX document",
        )
    if "bomFormat" not in doc and "components" not in doc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Not a valid CycloneDX document (missing bomFormat or components)",
        )
    return doc


@router.post("/import")
async def post_sbom_import(
    file: UploadFile = File(...),
    source: str = "manual",
    component: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Import CycloneDX JSON SBOM. Source: manual | aikido | ci.

    Tenant scope is derived from the caller; cross-tenant admins must use a
    cross-tenant admin key.
    """
    if not file.filename or not file.filename.lower().endswith(".json"):
        raise HTTPException(status_code=400, detail="Expected JSON file")
    content = await file.read()
    if len(content) > MAX_SBOM_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"SBOM exceeds {MAX_SBOM_BYTES} bytes",
        )
    try:
        doc = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    doc = _validate_cyclonedx(doc)
    if not ctx.cross_tenant and ctx.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant scope required to import SBOM",
        )
    created, updated = await import_sbom(
        db,
        doc,
        source=source,
        component=component,
        tenant_id=ctx.tenant_id,
    )
    return {
        "created": created,
        "updated": updated,
        "message": f"Imported {created} new, {updated} updated packages",
    }


@router.post("/import/json")
async def post_sbom_import_json(
    body: dict,
    source: str = "manual",
    component: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Import CycloneDX from JSON body (e.g. paste or CI webhook)."""
    body = _validate_cyclonedx(body)
    if not ctx.cross_tenant and ctx.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant scope required to import SBOM",
        )
    created, updated = await import_sbom(
        db,
        body,
        source=source,
        component=component,
        tenant_id=ctx.tenant_id,
    )
    return {
        "created": created,
        "updated": updated,
        "message": f"Imported {created} new, {updated} updated packages",
    }


@router.get("/packages")
async def get_sbom_packages(
    component: Optional[str] = None,
    limit: int = 500,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """List SBOM packages with optional filters. Scoped to caller's tenant."""
    packages = await list_sbom_packages(
        db,
        component=component,
        tenant_id=ctx.tenant_id,
        cross_tenant=ctx.cross_tenant,
        limit=limit,
    )
    return packages


@router.get("/packages/download")
async def download_sbom_packages(
    component: Optional[str] = None,
    format: str = "csv",
    limit: int = 2000,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Download SBOM packages for an asset as CSV or JSON. component filters by asset name."""
    packages = await list_sbom_packages(
        db,
        component=component,
        tenant_id=ctx.tenant_id,
        cross_tenant=ctx.cross_tenant,
        limit=limit,
    )
    safe_component = (component or "all").replace("/", "-").replace("\\", "-")[:50]
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if format == "json":
        content = json.dumps(packages, indent=2)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="sbom-{safe_component}-{date_str}.json"'
            },
        )

    # CSV
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["Package", "Version", "License", "License Risk", "Component", "Language"]
    )
    for p in packages:
        writer.writerow(
            [
                p.get("name", ""),
                p.get("version", ""),
                p.get("licenseId", ""),
                p.get("licenseRisk", ""),
                p.get("component", ""),
                p.get("language", ""),
            ]
        )
    content = buf.getvalue()
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="sbom-{safe_component}-{date_str}.csv"'
        },
    )
