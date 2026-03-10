"""Findings API routes."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_context, require_admin, require_reviewer
from app.core.database import get_db
from app.schemas.auth import UserContext
from app.schemas.finding import FindingArchive, FindingBulkUpdate, FindingRead, FindingRevert, FindingUpdate
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
from app.services.grouping import get_finding_group_key
from app.services.sync_service import sync_single_finding_to_tracker
from app.tasks.sync_tasks import trigger_sync_worker
router = APIRouter()


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
    limit: int = 0,  # 0 = no limit
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
        tenant_id=ctx.tenant_id,
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
    return [FindingRead.model_validate(f).to_api_dict() for f in findings]


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
    limit: int = 100,
    offset: int = 0,
):
    """
    Return findings pre-grouped by group key. Per §13.6: groupKey, severity (max), findingCount, findings (embedded).
    Pagination: limit/offset on groups; total for UI.
    """
    findings = await list_findings(
        db,
        tenant_id=ctx.tenant_id,
        archived=archived,
        status=status,
        severity=severity,
        source=source,
        finding_type=type,
        asset=asset,
        limit=0,  # fetch all for grouping, then paginate groups
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
        groups_list.append({
            "groupKey": key,
            "severity": max_sev.severity.value,
            "findingCount": len(flist),
            "findings": [FindingRead.model_validate(f).to_api_dict() for f in flist],
        })
    # Sort by worst severity
    groups_list.sort(key=lambda g: _sev_index(g["severity"]))
    total = len(groups_list)
    # Paginate
    page = groups_list[offset : offset + limit]
    return {"groups": page, "total": total}


@router.post("/bulk")
async def post_bulk_update(
    body: FindingBulkUpdate,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Bulk update findings to a shared status and justification. Sync to tracker/source enqueued."""
    user = ctx.email or ctx.raw_identity
    findings = await bulk_update_findings(
        db, body.ids, body.status, body.justification, tenant_id=ctx.tenant_id, user=user
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
    if finding and ctx.tenant_id and finding.tenant_id and finding.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingRead.model_validate(finding).to_api_dict()


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
    if finding and ctx.tenant_id and finding.tenant_id and finding.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    data = body.model_dump(exclude_unset=True)
    finding = await update_finding(db, finding_id, data, user=user)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingRead.model_validate(finding).to_api_dict()


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
    if finding and ctx.tenant_id and finding.tenant_id and finding.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = await archive_finding(db, finding_id, body.reason, user=user)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingRead.model_validate(finding).to_api_dict()


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
    if finding and ctx.tenant_id and finding.tenant_id and finding.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = await revert_finding(db, finding_id, body.reason, user=user)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found or no previous status to revert to")
    return FindingRead.model_validate(finding).to_api_dict()


@router.post("/{finding_id}/unarchive")
async def post_unarchive_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Unarchive a finding."""
    user = ctx.email or ctx.raw_identity
    finding = await get_finding(db, finding_id)
    if finding and ctx.tenant_id and finding.tenant_id and finding.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = await unarchive_finding(db, finding_id, user=user)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingRead.model_validate(finding).to_api_dict()


@router.post("/{finding_id}/override-fingerprint")
async def post_override_fingerprint(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """Override fingerprint when dedup incorrectly merged. PRD §5.1.2."""
    user = ctx.email or ctx.raw_identity
    finding = await get_finding(db, finding_id)
    if finding and ctx.tenant_id and finding.tenant_id and finding.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = await override_fingerprint(db, finding_id, user=user)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingRead.model_validate(finding).to_api_dict()


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
