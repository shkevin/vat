"""SBOM API — CycloneDX import, list packages, download. PRD §5.8."""

import csv
import io
import json
from typing import Optional

from fastapi import APIRouter, Depends, UploadFile, File
from fastapi.responses import StreamingResponse

from app.core.auth import get_current_user_optional
from app.core.database import get_db
from app.services.sbom import import_sbom, list_sbom_packages
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()


@router.post("/import")
async def post_sbom_import(
    file: UploadFile = File(...),
    source: str = "manual",
    component: Optional[str] = None,
    tenant_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    user: str = Depends(get_current_user_optional),
):
    """
    Import CycloneDX JSON SBOM. Source: manual | aikido | ci.
    When source=aikido, dedupes with existing Aikido SBOM data.
    """
    if not file.filename or not file.filename.lower().endswith(".json"):
        return {"error": "Expected JSON file"}
    content = await file.read()
    import json
    try:
        doc = json.loads(content)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}"}
    if "bomFormat" not in doc and "components" not in doc:
        return {"error": "Not a valid CycloneDX document (missing bomFormat or components)"}
    created, updated = await import_sbom(db, doc, source=source, component=component, tenant_id=tenant_id)
    return {"created": created, "updated": updated, "message": f"Imported {created} new, {updated} updated packages"}


@router.post("/import/json")
async def post_sbom_import_json(
    body: dict,
    source: str = "manual",
    component: Optional[str] = None,
    tenant_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    user: str = Depends(get_current_user_optional),
):
    """Import CycloneDX from JSON body (e.g. paste or CI webhook)."""
    if "bomFormat" not in body and "components" not in body:
        return {"error": "Not a valid CycloneDX document (missing bomFormat or components)"}
    created, updated = await import_sbom(db, body, source=source, component=component, tenant_id=tenant_id)
    return {"created": created, "updated": updated, "message": f"Imported {created} new, {updated} updated packages"}


@router.get("/packages")
async def get_sbom_packages(
    component: Optional[str] = None,
    tenant_id: Optional[str] = None,
    limit: int = 500,
    db: AsyncSession = Depends(get_db),
):
    """List SBOM packages with optional filters."""
    packages = await list_sbom_packages(db, component=component, tenant_id=tenant_id, limit=limit)
    return packages


@router.get("/packages/download")
async def download_sbom_packages(
    component: Optional[str] = None,
    tenant_id: Optional[str] = None,
    format: str = "csv",
    limit: int = 2000,
    db: AsyncSession = Depends(get_db),
):
    """Download SBOM packages for an asset as CSV or JSON. component filters by asset name."""
    packages = await list_sbom_packages(db, component=component, tenant_id=tenant_id, limit=limit)
    safe_component = (component or "all").replace("/", "-").replace("\\", "-")[:50]
    date_str = __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d")

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
    writer.writerow(["Package", "Version", "License", "License Risk", "Component", "Language"])
    for p in packages:
        writer.writerow([
            p.get("name", ""),
            p.get("version", ""),
            p.get("licenseId", ""),
            p.get("licenseRisk", ""),
            p.get("component", ""),
            p.get("language", ""),
        ])
    content = buf.getvalue()
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="sbom-{safe_component}-{date_str}.csv"'
        },
    )
