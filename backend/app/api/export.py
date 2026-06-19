"""Export API — full bundle download (assets, findings, SBOM, Executive Summary)."""

from datetime import datetime, timezone
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_context
from app.core.database import get_db
from app.schemas.auth import UserContext
from app.services.audit_events import emit_audit_event, new_trace_id
from app.services.export_service import ExportBundleOptions, build_export_bundle

router = APIRouter()
logger = logging.getLogger("uvicorn.error")


@router.get("/bundle")
async def get_export_bundle(
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
    include_archived: Annotated[
        bool, Query(description="Include archived findings in JSON/CSV/PDF")
    ] = False,
    finding_date_from: Annotated[
        str | None,
        Query(
            description="ISO datetime: filter findings by firstDetectedAt/created (inclusive)"
        ),
    ] = None,
    finding_date_to: Annotated[
        str | None,
        Query(
            description="ISO datetime: filter findings by firstDetectedAt/created (inclusive)"
        ),
    ] = None,
    include_audit_events: Annotated[
        bool, Query(description="Embed system audit-events.json in the bundle")
    ] = True,
    apply_asset_filter: Annotated[
        bool,
        Query(description="When true, scope export bundle to provided asset_id values"),
    ] = False,
    asset_id: Annotated[
        list[str] | None,
        Query(
            description="Repeatable asset id filter; applies only when apply_asset_filter=true"
        ),
    ] = None,
    audit_date_from: Annotated[
        str | None, Query(description="ISO datetime: audit event lower bound")
    ] = None,
    audit_date_to: Annotated[
        str | None, Query(description="ISO datetime: audit event upper bound")
    ] = None,
    audit_limit: Annotated[
        int, Query(ge=1, le=50000, description="Max audit rows in bundle")
    ] = 20000,
):
    """
    Download a ZIP bundle containing:
    - evidence-manifest.json: export scope, VAT version, SHA-256 of each payload file
    - assets-findings.json, findings.csv, waivers.json, waivers.csv
    - auditor-workbook.xlsx: auditor workbook (findings, waivers, STIG Viewer index, XCCDF rule table)
    - compliance-summary.pdf, executive-summary-yearly.html
    - audit-events.json (optional)
    - sbom-cyclonedx.json, sbom/by-asset/*.cdx.json
    - stig/: XCCDF/OVAL XML for STIG Viewer import, README-STIG-Viewer.txt, manifest.json
    """
    options = ExportBundleOptions(
        include_archived=include_archived,
        finding_date_from=finding_date_from,
        finding_date_to=finding_date_to,
        include_audit_events=include_audit_events,
        apply_asset_filter=apply_asset_filter,
        asset_ids=asset_id,
        audit_date_from=audit_date_from,
        audit_date_to=audit_date_to,
        audit_limit=audit_limit,
    )
    data = await build_export_bundle(db, ctx=ctx, options=options)
    # Export bundle generation should always produce a system audit event, even
    # when there were no prior audit rows.
    try:
        await emit_audit_event(
            db,
            trace_id=new_trace_id(),
            event_type="export.bundle.generated",
            actor_type="user",
            actor_id=ctx.email or ctx.user_id,
            decision_name="export_bundle",
            decision_reason_code="manual_export",
            decision_confidence="high",
            decision_result="generated",
            data={
                "tenantId": ctx.tenant_id,
                "bundleSizeBytes": len(data),
                "includeArchived": include_archived,
                "includeAuditEvents": include_audit_events,
            },
            retention_class="compliance",
        )
        await db.commit()
    except Exception:
        await db.rollback()
        logger.exception("failed to emit export.bundle.generated audit event")
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = f"vat-export-{date_str}.zip"
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
