"""Assets API — asset discovery, grouping overrides, and admin operations."""

from datetime import datetime
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_context, require_admin, require_reviewer
from app.core.config import get_settings
from app.core.database import get_db
from app.models.asset import Asset
from app.models.asset_digest_conflict import AssetDigestConflict
from app.models.asset_alias import AssetAlias
from app.models.asset_merge_event import AssetMergeEvent
from app.models.asset_merge_review import AssetMergeReview
from app.models.finding import Finding, Status
from app.schemas.auth import UserContext
from app.services.asset_aliases import (
    record_merge_event,
    repoint_aliases,
    resolve_canonical_asset_id,
    upsert_asset_alias,
)
from app.services.asset_merge_suggestions import suggest_asset_merge_targets
from app.services.asset_resolver import infer_asset_kind
from app.services.assets_service import (
    container_merge_group_key,
    finding_value_matches_merge_source,
    get_assets_with_findings,
    merge_candidate_image_like_prefixes,
)
from app.services.container_asset_observations import (
    migrate_observations_for_asset_merge,
)
from app.services.correlation_linking import apply_correlation_linking

router = APIRouter()


def _escape_sql_like_prefix(prefix: str) -> str:
    return prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class AssetGroupRequest(BaseModel):
    target_asset_id: str = Field(..., min_length=1, max_length=512)
    reassign_existing_findings: bool = True


class AssetUnmergeRequest(BaseModel):
    source_asset_id: str = Field(..., min_length=1, max_length=512)


class AssetMergeReviewUpsertRequest(BaseModel):
    status: str = Field(..., min_length=1, max_length=16)
    note: str | None = Field(default=None, max_length=2000)
    strategy: str | None = Field(default=None, max_length=32)
    score: float | None = None
    confidence: str | None = Field(default=None, max_length=16)
    details: dict | None = None

    @field_validator("status")
    @classmethod
    def _status_valid(cls, value: str) -> str:
        v = (value or "").strip().lower()
        if v not in {"pending", "approved", "denied"}:
            raise ValueError("status must be one of: pending, approved, denied")
        return v


class DigestConflictAckRequest(BaseModel):
    acknowledged: bool = True


def _serialize_merge_review(row: AssetMergeReview) -> dict:
    return {
        "id": row.id,
        "source_asset_id": row.source_asset_id,
        "target_asset_id": row.target_asset_id,
        "status": row.status,
        "note": row.note,
        "strategy": row.strategy,
        "score": row.score,
        "confidence": row.confidence,
        "details": row.details or {},
        "created_by": row.created_by,
        "updated_by": row.updated_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _append_finding_audit(
    finding: Finding,
    *,
    actor: str | None,
    action: str,
    note: str | None = None,
) -> None:
    audit = list(finding.audit or [])
    audit.append(
        {
            "ts": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "user": actor or "system",
            "action": action,
            "note": note,
        }
    )
    finding.audit = audit


def _serialize_digest_conflict(row: AssetDigestConflict) -> dict:
    return {
        "id": row.id,
        "asset_id": row.asset_id,
        "tag": row.tag,
        "status": row.status,
        "digests": list(row.digests or []),
        "acknowledged_by": row.acknowledged_by,
        "acknowledged_at": row.acknowledged_at.isoformat()
        if row.acknowledged_at
        else None,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
    }


@router.get("/{asset_id:path}/merge-suggestions")
async def get_asset_merge_suggestions(
    asset_id: str,
    limit: int = Query(default=10, ge=1, le=50),
    include_reviewed: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_reviewer),
):
    source_asset_id = (asset_id or "").strip()
    if not source_asset_id:
        raise HTTPException(status_code=422, detail="asset_id is required")
    suggestions = await suggest_asset_merge_targets(db, source_asset_id, limit=50)
    review_rows = (
        (
            await db.execute(
                select(AssetMergeReview).where(
                    AssetMergeReview.source_asset_id == source_asset_id
                )
            )
        )
        .scalars()
        .all()
    )
    review_by_target = {r.target_asset_id: r for r in review_rows}

    out: list[dict] = []
    for s in suggestions:
        review = review_by_target.get((s.get("target_asset_id") or "").strip())
        if review and not include_reviewed and review.status in {"denied", "approved"}:
            continue
        merged = dict(s)
        if review:
            merged["review_status"] = review.status
            merged["review_note"] = review.note
            merged["review_updated_at"] = (
                review.updated_at.isoformat() if review.updated_at else None
            )
        out.append(merged)
        if len(out) >= int(limit):
            break
    return {
        "source_asset_id": source_asset_id,
        "count": len(out),
        "suggestions": out,
    }


@router.get("/{asset_id:path}/merge-reviews")
async def list_asset_merge_reviews(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_reviewer),
):
    source_asset_id = (asset_id or "").strip()
    if not source_asset_id:
        raise HTTPException(status_code=422, detail="asset_id is required")
    rows = (
        (
            await db.execute(
                select(AssetMergeReview)
                .where(AssetMergeReview.source_asset_id == source_asset_id)
                .order_by(
                    AssetMergeReview.updated_at.desc(), AssetMergeReview.id.desc()
                )
            )
        )
        .scalars()
        .all()
    )
    return {
        "source_asset_id": source_asset_id,
        "count": len(rows),
        "reviews": [_serialize_merge_review(r) for r in rows],
    }


@router.put("/{asset_id:path}/merge-reviews/{target_asset_id:path}")
async def upsert_asset_merge_review(
    asset_id: str,
    target_asset_id: str,
    body: AssetMergeReviewUpsertRequest,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    source_asset_id = (asset_id or "").strip()
    target_id = (target_asset_id or "").strip()
    if not source_asset_id or not target_id:
        raise HTTPException(
            status_code=422, detail="source and target asset ids are required"
        )
    if source_asset_id == target_id:
        raise HTTPException(
            status_code=400, detail="source and target asset ids must differ"
        )

    row = (
        await db.execute(
            select(AssetMergeReview).where(
                AssetMergeReview.source_asset_id == source_asset_id,
                AssetMergeReview.target_asset_id == target_id,
            )
        )
    ).scalar_one_or_none()

    now = datetime.utcnow()
    actor = getattr(ctx, "email", None)
    if row is None:
        row = AssetMergeReview(
            source_asset_id=source_asset_id,
            target_asset_id=target_id,
            status=body.status,
            note=(body.note or None),
            strategy=(body.strategy or None),
            score=body.score,
            confidence=(body.confidence or None),
            details=(body.details or {}),
            created_by=actor,
            updated_by=actor,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
    else:
        row.status = body.status
        row.note = body.note or None
        row.strategy = body.strategy or row.strategy
        row.score = body.score if body.score is not None else row.score
        row.confidence = body.confidence or row.confidence
        row.details = body.details or row.details or {}
        row.updated_by = actor
        row.updated_at = now

    await db.commit()
    await db.refresh(row)
    return _serialize_merge_review(row)


@router.delete("/{asset_id:path}/merge-reviews/{target_asset_id:path}")
async def delete_asset_merge_review(
    asset_id: str,
    target_asset_id: str,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_reviewer),
):
    source_asset_id = (asset_id or "").strip()
    target_id = (target_asset_id or "").strip()
    if not source_asset_id or not target_id:
        raise HTTPException(
            status_code=422, detail="source and target asset ids are required"
        )
    row = (
        await db.execute(
            select(AssetMergeReview).where(
                AssetMergeReview.source_asset_id == source_asset_id,
                AssetMergeReview.target_asset_id == target_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Merge review not found")
    await db.delete(row)
    await db.commit()
    return {
        "deleted": True,
        "source_asset_id": source_asset_id,
        "target_asset_id": target_id,
    }


@router.get("/{asset_id:path}/digest-conflicts")
async def list_asset_digest_conflicts(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_reviewer),
):
    source_asset_id = (asset_id or "").strip()
    if not source_asset_id:
        raise HTTPException(status_code=422, detail="asset_id is required")
    rows = (
        (
            await db.execute(
                select(AssetDigestConflict)
                .where(AssetDigestConflict.asset_id == source_asset_id)
                .order_by(AssetDigestConflict.last_seen_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return {
        "asset_id": source_asset_id,
        "count": len(rows),
        "conflicts": [_serialize_digest_conflict(r) for r in rows],
    }


@router.put("/{asset_id:path}/digest-conflicts/{tag:path}/ack")
async def acknowledge_asset_digest_conflict(
    asset_id: str,
    tag: str,
    body: DigestConflictAckRequest,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    source_asset_id = (asset_id or "").strip()
    tag_value = (tag or "").strip()
    if not source_asset_id or not tag_value:
        raise HTTPException(status_code=422, detail="asset_id and tag are required")
    row = (
        await db.execute(
            select(AssetDigestConflict).where(
                AssetDigestConflict.asset_id == source_asset_id,
                AssetDigestConflict.tag == tag_value,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Digest conflict not found")

    if body.acknowledged:
        row.status = "acknowledged"
        row.acknowledged_by = getattr(ctx, "email", None)
        row.acknowledged_at = datetime.utcnow()
    else:
        row.status = "open"
        row.acknowledged_by = None
        row.acknowledged_at = None

    await db.commit()
    await db.refresh(row)
    return _serialize_digest_conflict(row)


@router.get("")
async def list_assets(
    include_findings: bool = Query(
        default=False, description="Include nested findings payload"
    ),
    limit: int = Query(default=0, ge=0, le=10000),
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
):
    """
    Discover canonical asset ids for CI/source targeting.
    Returns persisted assets plus findings-derived assets.
    """
    assets = await get_assets_with_findings(db, tenant_id=ctx.tenant_id, limit=limit)
    out = []
    for a in assets:
        aid = (a.get("id") or "").strip()
        kind = infer_asset_kind(aid, "")
        item = {
            "id": aid,
            "name": a.get("name") or aid,
            "type": a.get("type"),
            "source": a.get("source"),
            "branch": a.get("branch"),
            "tag": a.get("tag"),
            "kind": kind,
            "openCount": a.get("openCount"),
            "inReviewCount": a.get("inReviewCount"),
        }
        if include_findings:
            item["findings"] = a.get("findings") or []
        out.append(item)
    return {"count": len(out), "assets": out}


@router.delete("/{asset_id:path}")
async def delete_asset(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_admin),
):
    """
    Delete an asset and all findings that belong to this asset key.

    Asset key matching follows the frontend grouping logic:
    - finding.image == asset_id OR finding.component == asset_id
    """
    findings_q = delete(Finding).where(
        (Finding.image == asset_id) | (Finding.component == asset_id)
    )
    if ctx.tenant_id is not None:
        findings_q = findings_q.where(
            (Finding.tenant_id == ctx.tenant_id) | (Finding.tenant_id.is_(None))
        )
    findings_result = await db.execute(findings_q)
    findings_deleted = findings_result.rowcount or 0

    asset_result = await db.execute(delete(Asset).where(Asset.id == asset_id))
    asset_deleted = (asset_result.rowcount or 0) > 0

    if findings_deleted == 0 and not asset_deleted:
        await db.rollback()
        raise HTTPException(status_code=404, detail="Asset not found")

    await db.commit()
    return {"deleted_findings": findings_deleted, "deleted_asset": asset_deleted}


@router.post("/{asset_id:path}/group")
async def group_asset_into_target(
    asset_id: str,
    body: AssetGroupRequest,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_admin),
):
    """
    Group/merge one asset key into another canonical asset key.

    Effects:
    - stores a persistent alias so future ingests auto-map source -> canonical
    - rewrites existing findings that still reference source asset key
    - removes the source asset row
    """
    source_asset_id = (asset_id or "").strip()
    requested_target = (body.target_asset_id or "").strip()
    if not source_asset_id or not requested_target:
        raise HTTPException(
            status_code=422, detail="source and target asset ids are required"
        )

    canonical_target = await resolve_canonical_asset_id(db, requested_target)
    if not canonical_target:
        canonical_target = requested_target
    if source_asset_id == canonical_target:
        raise HTTPException(
            status_code=400, detail="source asset id must differ from target asset id"
        )
    # Manual merge mode: allow admin grouping directly without requiring
    # an approved review precondition.

    await upsert_asset_alias(
        db,
        source_asset_id=source_asset_id,
        canonical_asset_id=canonical_target,
        created_by=getattr(ctx, "email", None),
    )
    repointed_aliases = await repoint_aliases(
        db, old_canonical_id=source_asset_id, new_canonical_id=canonical_target
    )

    observations_migration = await migrate_observations_for_asset_merge(
        db,
        source_asset_id=source_asset_id,
        canonical_target=canonical_target,
    )

    source_asset = await db.get(Asset, source_asset_id)
    target_asset = await db.get(Asset, canonical_target)
    created_target_asset = False
    if not target_asset:
        target_asset = Asset(
            id=canonical_target,
            name=canonical_target,
            type=(source_asset.type if source_asset else "package"),
            source=(source_asset.source if source_asset else "manual-grouping"),
            branch=(source_asset.branch if source_asset else None),
            tag=(source_asset.tag if source_asset else None),
        )
        db.add(target_asset)
        created_target_asset = True

    findings_updated = 0
    findings_merged = 0
    changed_findings: list[
        tuple[Finding, dict[str, str | None], dict[str, str | None]]
    ] = []
    if body.reassign_existing_findings:
        src_container_key = container_merge_group_key(source_asset_id)
        match_ors = [
            Finding.image == source_asset_id,
            Finding.component == source_asset_id,
        ]
        if src_container_key:
            for prefix in merge_candidate_image_like_prefixes(source_asset_id):
                pat = _escape_sql_like_prefix(prefix) + "%"
                match_ors.append(Finding.image.ilike(pat, escape="\\"))
                match_ors.append(Finding.component.ilike(pat, escape="\\"))
        q = select(Finding).where(or_(*match_ors))
        if ctx.tenant_id is not None:
            q = q.where(
                or_(Finding.tenant_id == ctx.tenant_id, Finding.tenant_id.is_(None))
            )
        result = await db.execute(q)
        raw_rows = list(result.scalars().all())
        rows: list[Finding] = []
        seen_ids: set = set()
        for finding in raw_rows:
            if finding.id in seen_ids:
                continue
            if not (
                finding_value_matches_merge_source(
                    finding.image,
                    source_asset_id,
                    source_container_key=src_container_key,
                )
                or finding_value_matches_merge_source(
                    finding.component,
                    source_asset_id,
                    source_container_key=src_container_key,
                )
                or finding_value_matches_merge_source(
                    finding.tag,
                    source_asset_id,
                    source_container_key=src_container_key,
                )
            ):
                continue
            seen_ids.add(finding.id)
            rows.append(finding)
        for finding in rows:
            changed = False
            prev_values: dict[str, str | None] = {}
            next_values: dict[str, str | None] = {}
            if finding_value_matches_merge_source(
                finding.image,
                source_asset_id,
                source_container_key=src_container_key,
            ):
                prev_values["image"] = finding.image
                finding.image = canonical_target
                next_values["image"] = canonical_target
                changed = True
            if finding_value_matches_merge_source(
                finding.component,
                source_asset_id,
                source_container_key=src_container_key,
            ):
                prev_values["component"] = finding.component
                finding.component = canonical_target
                next_values["component"] = canonical_target
                changed = True
            if changed:
                findings_updated += 1
                _append_finding_audit(
                    finding,
                    actor=getattr(ctx, "email", None),
                    action="Asset merge reassigned finding",
                    note=f"{source_asset_id} -> {canonical_target}",
                )
                changed_findings.append((finding, prev_values, next_values))

        # Consolidate moved findings with existing target findings by logical group key.
        # Non-destructive policy: keep canonical finding, mark moved duplicates as Duplicate + correlated_to.
        if changed_findings:
            await db.flush()
            moved_ids = {f.id for f, _, _ in changed_findings}
            candidates_q = select(Finding).where(
                or_(
                    Finding.image == canonical_target,
                    Finding.tag == canonical_target,
                    Finding.component == canonical_target,
                )
            )
            if ctx.tenant_id is not None:
                candidates_q = candidates_q.where(
                    or_(Finding.tenant_id == ctx.tenant_id, Finding.tenant_id.is_(None))
                )
            candidate_rows = list((await db.execute(candidates_q)).scalars().all())

            for finding, prev_values, next_values in changed_findings:
                f_type = finding.finding_type
                f_img = str(finding.image or "").strip().lower()
                f_branch = str(finding.branch or "").strip().lower()
                f_tag = str(finding.tag or "").strip().lower()
                f_pkg = str(finding.component_base or "").strip().lower()

                peers = [
                    r
                    for r in candidate_rows
                    if r.id != finding.id
                    and r.finding_type == f_type
                    and str(r.image or "").strip().lower() == f_img
                    and str(r.branch or "").strip().lower() == f_branch
                    and str(r.tag or "").strip().lower() == f_tag
                    and str(r.component_base or "").strip().lower() == f_pkg
                ]
                if len(peers) == 0:
                    continue
                # Keep an existing target finding as canonical when available.
                canonical = sorted(
                    peers, key=lambda r: (r.id in moved_ids, r.created_at, r.id)
                )[0]
                if finding.correlated_to != canonical.id:
                    prev_values.setdefault("correlated_to", finding.correlated_to)
                    finding.correlated_to = canonical.id
                    next_values["correlated_to"] = canonical.id
                if finding.status != Status.Duplicate:
                    prev_values.setdefault("status", str(finding.status.value))
                    finding.status = Status.Duplicate
                    next_values["status"] = Status.Duplicate.value
                _append_finding_audit(
                    finding,
                    actor=getattr(ctx, "email", None),
                    action="Asset merge consolidated duplicate",
                    note=f"Canonical finding: {canonical.id}",
                )
                findings_merged += 1

        for finding, prev_values, next_values in changed_findings:
            await record_merge_event(
                db,
                source_asset_id=source_asset_id,
                target_asset_id=canonical_target,
                finding_id=finding.id,
                prev_values=prev_values,
                next_values=next_values,
                created_by=getattr(ctx, "email", None),
            )

    source_deleted = False
    if source_asset:
        await db.delete(source_asset)
        source_deleted = True

    # Parity with ingest correlation behavior: run the same linker policy for moved findings.
    # Scope is intentionally limited to findings that were rewritten during this merge operation.
    if (
        body.reassign_existing_findings
        and changed_findings
        and get_settings().correlation_linking_enabled
    ):
        trace_id = f"asset-merge-{uuid.uuid4().hex}"
        for finding, _, _ in changed_findings:
            await apply_correlation_linking(
                db,
                finding,
                trace_id=trace_id,
                source_id="asset_group",
                parser_id="manual_asset_merge",
            )

    await db.commit()
    return {
        "source_asset_id": source_asset_id,
        "target_asset_id": canonical_target,
        "findings_updated": findings_updated,
        "findings_merged": findings_merged,
        "alias_saved": True,
        "repointed_aliases": repointed_aliases,
        "observations_migration": observations_migration,
        "created_target_asset": created_target_asset,
        "deleted_source_asset": source_deleted,
    }


@router.get("/{asset_id:path}/aliases")
async def list_asset_aliases(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    canonical_id = (asset_id or "").strip()
    result = await db.execute(
        select(AssetAlias)
        .where(AssetAlias.canonical_asset_id == canonical_id)
        .order_by(AssetAlias.source_asset_id.asc())
    )
    rows = list(result.scalars().all())
    return {
        "canonical_asset_id": canonical_id,
        "aliases": [
            {
                "source_asset_id": r.source_asset_id,
                "canonical_asset_id": r.canonical_asset_id,
                "created_by": r.created_by,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


@router.post("/{asset_id:path}/unmerge")
async def unmerge_asset_alias(
    asset_id: str,
    body: AssetUnmergeRequest,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_admin),
):
    canonical_id = (asset_id or "").strip()
    source_id = (body.source_asset_id or "").strip()
    if not canonical_id or not source_id:
        raise HTTPException(
            status_code=422, detail="canonical and source asset ids are required"
        )
    if source_id == canonical_id:
        raise HTTPException(
            status_code=400, detail="source and canonical ids must differ"
        )

    alias = await db.get(AssetAlias, source_id)
    if not alias or alias.canonical_asset_id != canonical_id:
        raise HTTPException(
            status_code=404, detail="Alias not found for canonical asset"
        )

    result = await db.execute(
        select(AssetMergeEvent)
        .where(
            AssetMergeEvent.source_asset_id == source_id,
            AssetMergeEvent.target_asset_id == canonical_id,
            AssetMergeEvent.reverted_at.is_(None),
        )
        .order_by(AssetMergeEvent.id.asc())
    )
    events = list(result.scalars().all())

    restored_findings = 0
    for ev in events:
        finding = await db.get(Finding, ev.finding_id)
        if not finding:
            ev.reverted_at = ev.reverted_at or alias.updated_at
            continue
        if ctx.tenant_id is not None and finding.tenant_id not in (None, ctx.tenant_id):
            continue

        changed = False
        prev_values = ev.prev_values or {}
        next_values = ev.next_values or {}
        for field in ("image", "component", "tag", "correlated_to", "status"):
            if field not in prev_values or field not in next_values:
                continue
            prev = prev_values.get(field)
            nxt = next_values.get(field)
            current_raw = getattr(finding, field, None)
            current = (
                current_raw.value if hasattr(current_raw, "value") else current_raw
            ) or ""
            current = str(current).strip()
            expected_current = str(nxt).strip() if nxt is not None else ""
            if current == expected_current:
                setattr(finding, field, prev)
                changed = True
        if changed:
            restored_findings += 1
            _append_finding_audit(
                finding,
                actor=getattr(ctx, "email", None),
                action="Asset unmerge restored finding fields",
                note=f"{canonical_id} -> {source_id}",
            )
        ev.reverted_at = ev.reverted_at or alias.updated_at

    # Remove alias so future ingests stop canonicalizing this source id.
    await db.delete(alias)

    # Recreate source asset row if needed (merge deletes it).
    source_asset = await db.get(Asset, source_id)
    if not source_asset:
        target_asset = await db.get(Asset, canonical_id)
        db.add(
            Asset(
                id=source_id,
                name=source_id,
                type=(target_asset.type if target_asset else "package"),
                source=(target_asset.source if target_asset else "manual-unmerge"),
                branch=None,
                tag=None,
            )
        )

    await db.commit()
    return {
        "canonical_asset_id": canonical_id,
        "source_asset_id": source_id,
        "alias_removed": True,
        "restored_findings": restored_findings,
    }
