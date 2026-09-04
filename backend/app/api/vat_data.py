"""VAT data API — findings + assets in one response."""

import asyncio
import hashlib
import json
import logging
import time
from typing import AsyncIterator, Optional

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import StreamingResponse
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
    apply_source_group_severity,
    load_source_group_severity_map,
    stream_findings,
)
from app.services.grouping import finding_to_api_dict_with_group_key

logger = logging.getLogger(__name__)
router = APIRouter()

# Rows per DB fetch and per JSON chunk. Big enough that per-batch overhead is
# noise, small enough that one batch's encode does not starve the event loop.
_BATCH_SIZE = 2000
_SEP = (",", ":")


async def stream_vat_data_body(
    rows: list[dict],
    assets: list[dict],
    meta: dict,
    batch_size: int = _BATCH_SIZE,
) -> AsyncIterator[bytes]:
    """Emit the vat-data JSON object in chunks.

    Findings go out ``batch_size`` at a time instead of through one json.dumps
    over the whole payload — that built a ~200 MB string and held the event loop
    for the entire encode. Each batch is encoded as an array and stripped of its
    brackets so the pieces concatenate into one valid array.

    Compact separators throughout: the batch joins are written by hand, so
    letting json.dumps use its default ", "/": " would make the spacing
    inconsistent across batch boundaries — and on a payload this size the
    padding is not free either.
    """
    yield b'{"findings":['
    for i in range(0, len(rows), batch_size):
        chunk = json.dumps(rows[i : i + batch_size], default=str, separators=_SEP)[1:-1]
        yield (b"," if i else b"") + chunk.encode()
        await asyncio.sleep(0)
    yield b'],"assets":'
    yield json.dumps(assets, default=str, separators=_SEP).encode()
    yield b',"meta":'
    yield json.dumps(meta, default=str, separators=_SEP).encode()
    yield b"}"



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
    a_max, a_count = (
        await db.execute(select(func.max(Asset.id), func.count(Asset.id)))
    ).one()
    al_max, al_count = (
        await db.execute(
            select(
                func.max(AssetAlias.updated_at),
                func.count(AssetAlias.source_asset_id),
            )
        )
    ).one()
    sig = "|".join(
        [
            str(f_max.isoformat()) if f_max else "",
            str(f_count or 0),
            str(a_max or ""),
            str(a_count or 0),
            str(al_max.isoformat()) if al_max else "",
            str(al_count or 0),
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

    # Collect in batches over a server-side cursor rather than materializing
    # ~130k ORM rows in one db.execute. Each batch is a separate await, so the
    # event loop gets a turn and /health keeps answering while this runs.
    group_map = await load_source_group_severity_map(db)
    rows: list[dict] = []
    async for batch in stream_findings(
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
        batch_size=_BATCH_SIZE,
    ):
        # Build then extend, rather than slicing rows[-len(batch):] — an empty
        # batch makes that slice the whole list.
        batch_rows = [finding_to_api_dict_with_group_key(f, slim=slim) for f in batch]
        apply_source_group_severity(batch_rows, group_map)
        rows.extend(batch_rows)
        # The DB await above already yields, but a fully-cached partition can
        # come back without suspending. Make the turn unconditional.
        await asyncio.sleep(0)
    t_rows = time.perf_counter()

    assets = []
    if include_assets:
        assets = await get_assets_with_findings(
            db,
            findings_dicts=rows,
            ctx=ctx,
            include_zero_assets=include_zero_assets,
            include_findings=include_asset_findings,
            include_finding_derived_assets=False,
        )
    t_assets = time.perf_counter()

    meta = {
        "page": page,
        "pageSize": effective_limit if effective_limit > 0 else len(rows),
        "hasMore": effective_limit > 0 and len(rows) == effective_limit,
        "includeAssets": include_assets,
        "includeZeroAssets": include_zero_assets,
        "includeAssetFindings": include_asset_findings,
    }

    # Everything that can fail has already run, so a mid-stream error can no
    # longer truncate a body we have committed a 200 to. From here on it is
    # only json.dumps over data we hold.
    async def _body() -> AsyncIterator[bytes]:
        t_stream_start = time.perf_counter()
        async for chunk in stream_vat_data_body(rows, assets, meta, _BATCH_SIZE):
            yield chunk
        t_done = time.perf_counter()
        logger.info(
            "vat_data timing: %s",
            json.dumps(
                {
                    "collect_rows_ms": round((t_rows - t_start) * 1000, 1),
                    "build_assets_ms": round((t_assets - t_rows) * 1000, 1),
                    "stream_body_ms": round((t_done - t_stream_start) * 1000, 1),
                    "total_ms": round((t_done - t_start) * 1000, 1),
                    "findings_count": len(rows),
                    "assets_count": len(assets),
                    "full": full,
                    "streamed": True,
                }
            ),
        )

    return StreamingResponse(
        _body(),
        media_type="application/json",
        headers={
            "ETag": etag,
            "Cache-Control": "private, must-revalidate",
        },
    )
