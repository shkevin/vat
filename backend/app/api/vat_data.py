"""VAT data API — findings + assets in one response."""

import hashlib
import json
import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_context, tenant_filter
from app.core.database import get_db
from app.models.asset import Asset
from app.models.asset_alias import AssetAlias
from app.models.finding import Finding
from app.schemas.auth import UserContext
from app.services.assets_service import get_assets_with_findings
from app.services.findings_service import (
    enrich_findings_with_source_group_severity,
    list_findings,
)
from app.services.grouping import finding_to_api_dict_with_group_key

logger = logging.getLogger(__name__)
router = APIRouter()


async def _vat_data_etag(
    db: AsyncSession,
    *,
    ctx: UserContext,
    archived: Optional[bool],
    status: Optional[str],
    severity: Optional[str],
    source: Optional[str],
    finding_type: Optional[str],
    asset: Optional[str],
    search: Optional[str],
    search_fields: Optional[str],
    limit: int,
    page: int,
    page_size: int,
    include_assets: bool,
    include_zero_assets: bool,
    include_asset_findings: bool,
    slim: bool,
    full: bool,
) -> str:
    """Derive a content-keyed ETag from the most recent mutation timestamps.

    Any finding/asset/alias change bumps the ETag — readers always get
    the freshest data when something mutates, and 304 the rest of the
    time. ``query_signature`` mixes the request shape so different filter
    combinations don't share a key.
    """
    finding_q = select(
        func.max(Finding.updated_at), func.count(Finding.id)
    ).where(tenant_filter(Finding, ctx))
    if archived is not None:
        finding_q = finding_q.where(Finding.archived == archived)
    f_max, f_count = (await db.execute(finding_q)).one()
    a_max = (
        await db.execute(select(func.max(Asset.id)))
    ).scalar() or ""
    al_max = (
        await db.execute(select(func.max(AssetAlias.updated_at)))
    ).scalar()
    sig = "|".join(
        [
            str(f_max.isoformat()) if f_max else "",
            str(f_count or 0),
            str(a_max),
            str(al_max.isoformat()) if al_max else "",
            str(ctx.tenant_id or ""),
            "X" if ctx.cross_tenant else "S",
            str(archived),
            str(status or ""),
            str(severity or ""),
            str(source or ""),
            str(finding_type or ""),
            str(asset or ""),
            str(search or ""),
            str(search_fields or ""),
            str(limit),
            str(page),
            str(page_size),
            str(include_assets),
            str(include_zero_assets),
            str(include_asset_findings),
            str(slim),
            str(full),
        ]
    )
    return 'W/"' + hashlib.sha256(sig.encode()).hexdigest()[:16] + '"'


@router.get("")
async def get_vat_data(
    request: Request,
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
    slim: bool = True,
):
    """
    Return findings and assets in one response.
    Assets include integration-created records (e.g. Aikido repos with 0 findings).
    """
    # ETag short-circuit: a content-derived weak ETag built from
    # (max(findings.updated_at), count, max(asset_id), max(alias.updated_at))
    # plus the request shape. Mutations bump it; identical re-requests 304
    # with no body. Cuts the 45s polling traffic to near-zero on idle clusters.
    etag = await _vat_data_etag(
        db,
        ctx=ctx,
        archived=archived,
        status=status,
        severity=severity,
        source=source,
        finding_type=type,
        asset=asset,
        search=search,
        search_fields=search_fields,
        limit=limit,
        page=page,
        page_size=page_size,
        include_assets=include_assets,
        include_zero_assets=include_zero_assets,
        include_asset_findings=include_asset_findings,
        slim=slim,
        full=full,
    )
    if request.headers.get("if-none-match") == etag:
        return Response(
            status_code=304,
            headers={
                "ETag": etag,
                "Cache-Control": "private, must-revalidate",
            },
        )

    page = max(1, page)
    page_size = max(1, min(page_size, 2000))
    effective_limit = 0 if full else (limit if limit > 0 else page_size)
    offset = 0 if effective_limit == 0 else (page - 1) * effective_limit

    t_start = time.perf_counter()
    findings = await list_findings(
        db,
        ctx=ctx,
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
        slim=slim,
    )
    t_list = time.perf_counter()
    rows = [finding_to_api_dict_with_group_key(f, slim=slim) for f in findings]
    t_serialize_findings = time.perf_counter()
    rows = await enrich_findings_with_source_group_severity(db, rows)
    t_enrich = time.perf_counter()

    assets = []
    if include_assets:
        assets = await get_assets_with_findings(
            db,
            findings_dicts=rows,
            ctx=ctx,
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
        headers={
            "X-VAT-Timing": json.dumps(timing),
            "ETag": etag,
            "Cache-Control": "private, must-revalidate",
        },
    )
