"""Export API — full bundle download (assets, findings, SBOM, Executive Summary)."""

from datetime import datetime

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_context
from app.core.database import get_db
from app.schemas.auth import UserContext
from app.services.export_service import build_export_bundle

router = APIRouter()


@router.get("/bundle")
async def get_export_bundle(
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
):
    """
    Download a ZIP bundle containing:
    - assets-findings.json: all assets and their findings
    - sbom-cyclonedx.json: SBOM in CycloneDX 1.4 format
    - executive-summary-yearly.html: Executive Summary - Yearly (All Instances) report
    - stig/: OpenSCAP XCCDF/OVAL results (one file per asset) for STIG Viewer and XACTA import
    """
    data = await build_export_bundle(db, tenant_id=ctx.tenant_id)
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    filename = f"vat-export-{date_str}.zip"
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
