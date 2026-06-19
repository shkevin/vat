"""Findings API routes."""

import inspect
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_context, require_admin, require_reviewer
from app.core.config import get_settings
from app.core.database import get_db
from app.models.finding import Finding
from app.schemas.auth import UserContext
from app.schemas.finding import (
    FindingArchive,
    FindingBulkUpdate,
    FindingRead,
    FindingRevert,
    FindingUpdate,
)
from app.services.findings_service import (
    archive_finding,
    bulk_update_findings,
    get_finding,
    list_findings,
    override_fingerprint,
    revert_finding,
    unarchive_finding,
    update_finding,
)
from app.services.grouping import (
    finding_to_api_dict_with_group_key,
    get_finding_group_key,
)
from app.services.correlation_edges import (
    deactivate_edge,
    list_active_edges_for_finding,
    list_edges_by_operation_id,
    list_edges_for_finding,
    reactivate_edge,
)
from app.services.crosswalks import ingest_crosswalk_entries, resolve_crosswalk_values
from app.services.sync_service import sync_single_finding_to_tracker
from app.tasks.sync_tasks import trigger_sync_worker

router = APIRouter()


def _finding_visible(ctx: UserContext, finding: Finding) -> bool:
    """Tenant-scope check for a single finding. Fails closed when the caller
    has no tenant and is not cross-tenant: a NULL-tenant finding (legacy
    webhook ingest) is no longer visible to arbitrary callers."""
    if ctx.cross_tenant:
        return True
    if ctx.tenant_id is None:
        return False
    return finding.tenant_id == ctx.tenant_id


class CorrelationEdgeActionRequest(BaseModel):
    reason: str = Field(default="manual action", max_length=256)


class CrosswalkEntryRequest(BaseModel):
    from_namespace: str = Field(..., max_length=64)
    from_value: str = Field(..., max_length=256)
    to_namespace: str = Field(..., max_length=64)
    to_value: str = Field(..., max_length=256)
    confidence: Optional[str] = Field(default="medium", max_length=16)
    score: Optional[float] = None
    active: Optional[bool] = True
    metadata: Optional[dict] = None


class CrosswalkRunRequest(BaseModel):
    source: str = Field(..., max_length=64)
    source_version: str = Field(..., max_length=64)
    entries: list[CrosswalkEntryRequest]


@router.get("")
async def get_findings(
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
    limit: int = Query(default=get_settings().finding_default_limit, ge=1, le=2000),
):
    """
    List findings with optional filters.
    - status: Filter by status (e.g. Open, In Review)
    - severity: Filter by severity (Critical, High, etc.)
    - source: Filter by source name (e.g. Aikido)
    - type: Filter by finding type (SCA, Secret, IaC, SAST, License)
    - asset: Filter by component or image (partial match)
    - search: Free-text search across CVE ID, title, component, image, team, owner
    - search_fields: Comma-separated fields to search (cve_id, title, component, image, team, owner). Omit to search all.
    """
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
        limit=limit,
    )
    return [finding_to_api_dict_with_group_key(f) for f in findings]


@router.get("/groups")
async def get_findings_groups(
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
    archived: Optional[bool] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    type: Optional[str] = None,
    asset: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """
    Return findings pre-grouped by group key. Per §13.6: groupKey, severity (max), findingCount, findings (embedded).
    Pagination: limit/offset on groups; total for UI.
    """
    scan_limit = get_settings().finding_groups_scan_limit
    findings = await list_findings(
        db,
        ctx=ctx,
        archived=archived,
        status=status,
        severity=severity,
        source=source,
        finding_type=type,
        asset=asset,
        limit=scan_limit,
    )
    # Group by key
    from collections import defaultdict

    SEV_ORDER = ("Critical", "High", "Medium", "Low", "Informational")

    def _sev_index(s: str) -> int:
        try:
            return SEV_ORDER.index(s)
        except ValueError:
            return 999

    groups_map: dict[str, list] = defaultdict(list)
    for f in findings:
        key = get_finding_group_key(f)
        groups_map[key].append(f)

    # Build group entries: groupKey, severity (max), findingCount, findings (embedded)
    groups_list = []
    for key, flist in groups_map.items():
        max_sev = max(flist, key=lambda x: _sev_index(x.severity.value))
        groups_list.append(
            {
                "groupKey": key,
                "severity": max_sev.severity.value,
                "findingCount": len(flist),
                "findings": [finding_to_api_dict_with_group_key(f) for f in flist],
            }
        )
    # Sort by worst severity
    groups_list.sort(key=lambda g: _sev_index(g["severity"]))
    total = len(groups_list)
    # Paginate
    page = groups_list[offset : offset + limit]
    return {"groups": page, "total": total, "scanLimitApplied": len(findings) >= scan_limit}


@router.post("/bulk")
async def post_bulk_update(
    body: FindingBulkUpdate,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Bulk update findings to a shared status and justification. Sync to tracker/source enqueued."""
    user = ctx.email or ctx.raw_identity
    findings = await bulk_update_findings(
        db,
        body.ids,
        body.status,
        body.justification,
        ctx=ctx,
        user=user,
    )
    return {"updated": len(findings), "message": f"Updated {len(findings)} findings"}


@router.get("/{finding_id}")
async def get_finding_by_id(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
):
    """Get a single finding by ID."""
    finding = await get_finding(db, finding_id)
    if finding and not _finding_visible(ctx, finding):
        raise HTTPException(status_code=404, detail="Finding not found")
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding_to_api_dict_with_group_key(finding)


@router.patch("/{finding_id}")
async def patch_finding(
    finding_id: str,
    body: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Update a finding. Accepts camelCase from frontend. Sync to tracker/source enqueued."""
    user = ctx.email or ctx.raw_identity
    finding = await get_finding(db, finding_id)
    if finding and not _finding_visible(ctx, finding):
        raise HTTPException(status_code=404, detail="Finding not found")
    data = body.model_dump(exclude_unset=True)
    finding = await update_finding(db, finding_id, data, user=user)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding_to_api_dict_with_group_key(finding)


@router.post("/{finding_id}/archive")
async def post_archive_finding(
    finding_id: str,
    body: FindingArchive,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Archive a finding with a reason."""
    user = ctx.email or ctx.raw_identity
    finding = await get_finding(db, finding_id)
    if finding and not _finding_visible(ctx, finding):
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = await archive_finding(db, finding_id, body.reason, user=user)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding_to_api_dict_with_group_key(finding)


@router.post("/{finding_id}/revert")
async def post_revert_finding(
    finding_id: str,
    body: FindingRevert,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Revert finding to previous status. Reason required. PRD §5.4.3."""
    user = ctx.email or ctx.raw_identity
    finding = await get_finding(db, finding_id)
    if finding and not _finding_visible(ctx, finding):
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = await revert_finding(db, finding_id, body.reason, user=user)
    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found or no previous status to revert to",
        )
    return finding_to_api_dict_with_group_key(finding)


@router.post("/{finding_id}/unarchive")
async def post_unarchive_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Unarchive a finding."""
    user = ctx.email or ctx.raw_identity
    finding = await get_finding(db, finding_id)
    if finding and not _finding_visible(ctx, finding):
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = await unarchive_finding(db, finding_id, user=user)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding_to_api_dict_with_group_key(finding)


@router.post("/{finding_id}/override-fingerprint")
async def post_override_fingerprint(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Override fingerprint when dedup incorrectly merged. PRD §5.1.2."""
    user = ctx.email or ctx.raw_identity
    finding = await get_finding(db, finding_id)
    if finding and not _finding_visible(ctx, finding):
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = await override_fingerprint(db, finding_id, user=user)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding_to_api_dict_with_group_key(finding)


@router.post("/{finding_id}/sync-to-tracker")
async def post_sync_finding_to_tracker(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_admin),
):
    """Enqueue create_issue for a single finding. For dev/troubleshooting before bulk sync."""
    finding = await get_finding(db, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if ctx.tenant_id and finding.tenant_id and finding.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    result = await sync_single_finding_to_tracker(db, finding_id)
    if result["enqueued"]:
        trigger_sync_worker(countdown=1)
    return result


@router.get("/{finding_id}/correlations")
async def get_finding_correlations(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
):
    """List active, undirected correlation edges for a finding."""
    finding = await get_finding(db, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if ctx.tenant_id and finding.tenant_id and finding.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    edges = await list_active_edges_for_finding(db, finding_id)
    out = []
    for e in edges:
        peer = e.finding_id_b if e.finding_id_a == finding_id else e.finding_id_a
        out.append(
            {
                "edge_id": e.id,
                "peer_finding_id": peer,
                "edge_type": e.edge_type,
                "confidence": e.confidence,
                "evidence": e.evidence or {},
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
        )
    return {"finding_id": finding_id, "count": len(out), "edges": out}


@router.post("/{finding_id}/correlations/{peer_finding_id}/remove")
async def remove_finding_correlation(
    finding_id: str,
    peer_finding_id: str,
    body: CorrelationEdgeActionRequest,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Soft-deactivate a correlation edge (reversible, non-destructive)."""
    left = await get_finding(db, finding_id)
    right = await get_finding(db, peer_finding_id)
    if not left or not right:
        raise HTTPException(status_code=404, detail="Finding not found")
    if ctx.tenant_id and (
        (left.tenant_id and left.tenant_id != ctx.tenant_id)
        or (right.tenant_id and right.tenant_id != ctx.tenant_id)
    ):
        raise HTTPException(status_code=404, detail="Finding not found")

    actor = ctx.email or ctx.raw_identity or "reviewer"
    row = await deactivate_edge(
        db,
        finding_id_left=finding_id,
        finding_id_right=peer_finding_id,
        removed_by=actor,
        remove_reason=body.reason or "manual uncorrelate",
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Correlation edge not found")
    await db.commit()
    return {
        "deactivated": True,
        "finding_id": finding_id,
        "peer_finding_id": peer_finding_id,
        "operation_id": row.operation_id,
    }


@router.post("/{finding_id}/correlations/{peer_finding_id}/restore")
async def restore_finding_correlation(
    finding_id: str,
    peer_finding_id: str,
    body: CorrelationEdgeActionRequest,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Restore a previously deactivated correlation edge."""
    left = await get_finding(db, finding_id)
    right = await get_finding(db, peer_finding_id)
    if not left or not right:
        raise HTTPException(status_code=404, detail="Finding not found")
    if ctx.tenant_id and (
        (left.tenant_id and left.tenant_id != ctx.tenant_id)
        or (right.tenant_id and right.tenant_id != ctx.tenant_id)
    ):
        raise HTTPException(status_code=404, detail="Finding not found")
    actor = ctx.email or ctx.raw_identity or "reviewer"
    row = await reactivate_edge(
        db,
        finding_id_left=finding_id,
        finding_id_right=peer_finding_id,
        reactivated_by=actor,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Correlation edge not found")
    await db.commit()
    return {
        "restored": True,
        "finding_id": finding_id,
        "peer_finding_id": peer_finding_id,
        "operation_id": row.operation_id,
        "note": body.reason,
    }


@router.get("/{finding_id}/correlations/history")
async def get_finding_correlation_history(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
):
    """List active and inactive correlation edges for audit history."""
    finding = await get_finding(db, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if ctx.tenant_id and finding.tenant_id and finding.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    edges = await list_edges_for_finding(db, finding_id, include_inactive=True)
    out = []
    for e in edges:
        peer = e.finding_id_b if e.finding_id_a == finding_id else e.finding_id_a
        out.append(
            {
                "edge_id": e.id,
                "peer_finding_id": peer,
                "edge_type": e.edge_type,
                "confidence": e.confidence,
                "evidence": e.evidence or {},
                "active": e.active,
                "operation_id": e.operation_id,
                "created_by": e.created_by,
                "created_at": e.created_at.isoformat() if e.created_at else None,
                "updated_at": e.updated_at.isoformat() if e.updated_at else None,
                "removed_by": e.removed_by,
                "removed_at": e.removed_at.isoformat() if e.removed_at else None,
                "remove_reason": e.remove_reason,
            }
        )
    return {"finding_id": finding_id, "count": len(out), "edges": out}


@router.get("/correlations/operations/{operation_id}")
async def get_correlation_operation_history(
    operation_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
):
    """Query correlation-edge history by operation_id for audit workflows."""
    edges = await list_edges_by_operation_id(db, operation_id)
    if not edges:
        return {"operation_id": operation_id, "count": 0, "edges": []}

    ids: set[str] = set()
    for edge in edges:
        ids.add(edge.finding_id_a)
        ids.add(edge.finding_id_b)

    tenant_map: dict[str, str | None] = {}
    if ids:
        rows = await db.execute(
            select(Finding.id, Finding.tenant_id).where(Finding.id.in_(ids))
        )
        all_rows = rows.all()
        if inspect.isawaitable(all_rows):
            all_rows = await all_rows
        tenant_map = {str(fid): tid for fid, tid in all_rows}
        if ctx.tenant_id and any(fid not in tenant_map for fid in ids):
            for fid in ids:
                if fid in tenant_map:
                    continue
                finding = await get_finding(db, fid)
                tenant_map[fid] = getattr(finding, "tenant_id", None)

    out = []
    for e in edges:
        if ctx.tenant_id:
            left_tid = tenant_map.get(e.finding_id_a)
            right_tid = tenant_map.get(e.finding_id_b)
            if (left_tid and left_tid != ctx.tenant_id) or (
                right_tid and right_tid != ctx.tenant_id
            ):
                continue
        out.append(
            {
                "edge_id": e.id,
                "finding_id_a": e.finding_id_a,
                "finding_id_b": e.finding_id_b,
                "edge_type": e.edge_type,
                "confidence": e.confidence,
                "evidence": e.evidence or {},
                "active": e.active,
                "operation_id": e.operation_id,
                "created_by": e.created_by,
                "created_at": e.created_at.isoformat() if e.created_at else None,
                "updated_at": e.updated_at.isoformat() if e.updated_at else None,
                "removed_by": e.removed_by,
                "removed_at": e.removed_at.isoformat() if e.removed_at else None,
                "remove_reason": e.remove_reason,
            }
        )
    return {"operation_id": operation_id, "count": len(out), "edges": out}


@router.post("/crosswalk/runs")
async def post_crosswalk_run(
    body: CrosswalkRunRequest,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_admin),
):
    actor = ctx.email or ctx.raw_identity
    run = await ingest_crosswalk_entries(
        db,
        source=body.source.strip(),
        source_version=body.source_version.strip(),
        entries=[e.model_dump() for e in body.entries],
        created_by=actor,
    )
    await db.commit()
    return {
        "run_id": run.id,
        "source": run.source,
        "source_version": run.source_version,
        "status": run.status,
        "stats": run.stats,
    }


@router.get("/crosswalk/resolve")
async def get_crosswalk_resolve(
    from_namespace: str,
    from_value: str,
    to_namespace: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_reviewer),
):
    rows = await resolve_crosswalk_values(
        db,
        from_namespace=from_namespace,
        from_value=from_value,
        to_namespace=to_namespace,
    )
    return {
        "count": len(rows),
        "mappings": [
            {
                "id": r.id,
                "from_namespace": r.from_namespace,
                "from_value": r.from_value,
                "to_namespace": r.to_namespace,
                "to_value": r.to_value,
                "confidence": r.confidence,
                "source": r.source,
                "source_version": r.source_version,
                "active": r.active,
            }
            for r in rows
        ],
    }
