"""VAT data API — findings + assets in one response."""

import json
import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_context
from app.core.database import get_db
from app.schemas.auth import UserContext
from app.services.assets_service import get_assets_with_findings
from app.services.findings_service import (
    enrich_findings_with_source_group_severity,
    list_findings,
)
from app.services.grouping import finding_to_api_dict_with_group_key

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("")
async def get_vat_data(
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
    archived: Optional[bool] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    type: Optional[str] = None,
    asset: Optional[str] = None,
    search: Optional[str] = None,
    search_fields: Optional[str] = None,
    limit: int = 0,
    page: int = 1,
    page_size: int = 500,
    include_assets: bool = True,
    include_zero_assets: bool = True,
    include_asset_findings: bool = False,
    full: bool = False,
):
    """
    Return findings and assets in one response.
    Assets include integration-created records (e.g. Aikido repos with 0 findings).
    """
    page = max(1, page)
    page_size = max(1, min(page_size, 2000))
    effective_limit = 0 if full else (limit if limit > 0 else page_size)
    offset = 0 if effective_limit == 0 else (page - 1) * effective_limit

    t_start = time.perf_counter()
    findings = await list_findings(
        db,
        tenant_id=ctx.tenant_id,
        archived=archived,
        status=status,
        severity=severity,
        source=source,
        finding_type=type,
        asset=asset,
        search=search,
        search_fields=search_fields,
        limit=effective_limit,
        offset=offset,
    )
    t_list = time.perf_counter()
    rows = [finding_to_api_dict_with_group_key(f) for f in findings]
    t_serialize_findings = time.perf_counter()
    rows = await enrich_findings_with_source_group_severity(db, rows)
    t_enrich = time.perf_counter()

    assets = []
    if include_assets:
        assets = await get_assets_with_findings(
            db,
            findings_dicts=rows,
            include_zero_assets=include_zero_assets,
            include_findings=include_asset_findings,
        )
    t_assets = time.perf_counter()

    payload = {
        "findings": rows,
        "assets": assets,
        "meta": {
            "page": page,
            "pageSize": effective_limit if effective_limit > 0 else len(rows),
            "hasMore": effective_limit > 0 and len(rows) == effective_limit,
            "includeAssets": include_assets,
            "includeZeroAssets": include_zero_assets,
            "includeAssetFindings": include_asset_findings,
        },
    }
    body = json.dumps(payload, default=str)
    t_json = time.perf_counter()

    timing = {
        "list_findings_ms": round((t_list - t_start) * 1000, 1),
        "serialize_findings_ms": round((t_serialize_findings - t_list) * 1000, 1),
        "enrich_findings_ms": round((t_enrich - t_serialize_findings) * 1000, 1),
        "build_assets_ms": round((t_assets - t_enrich) * 1000, 1),
        "json_encode_ms": round((t_json - t_assets) * 1000, 1),
        "total_ms": round((t_json - t_start) * 1000, 1),
        "findings_count": len(rows),
        "assets_count": len(assets),
        "payload_kb": round(len(body) / 1024, 1),
        "full": full,
    }
    logger.info("vat_data timing: %s", json.dumps(timing))

    return Response(
        content=body,
        media_type="application/json",
        headers={"X-VAT-Timing": json.dumps(timing)},
    )
