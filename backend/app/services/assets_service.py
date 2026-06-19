"""Assets service — combine Asset records with findings-derived assets."""

from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.asset_digest_conflict import AssetDigestConflict
from app.models.asset_observed_tag import AssetObservedTag
from app.models.finding import Finding
from app.schemas.finding import FindingRead
from app.core.auth import tenant_filter

if TYPE_CHECKING:
    from app.schemas.auth import UserContext
from app.services.asset_resolver import infer_asset_kind
from app.services.asset_type_infer import infer_asset_type_from_findings
from app.services.container_ref_normalization import (
    apply_container_asset_path_aliases,
    normalize_container_ref,
)
from app.services.metric_semantics import (
    is_open_risk,
    is_overdue_open_risk,
    is_verified_disposition,
)

SEV_ORDER = ("Critical", "High", "Medium", "Low", "Informational")

# ORA weights (matches frontend ora.ts)
ORA_WEIGHTS = {"critical": 10, "high": 4, "medium": 0.5, "low": 0.25}
ORA_CAPS = {"low": 10, "medium": 30}


def _container_image_group_key(image: str, _tag: Optional[str]) -> str:
    """Match frontend containerImageGroupKey — canonical registry path (correlation-aligned).

    For repo-shape refs (bitnamilegacy/foo, kamiwaza/bar) the same alias
    rules that strip docker.io/ from container refs must apply: the Asset
    row is stored alias-stripped, so the grouping key has to match it or
    findings end up in a "ghost" group at the un-stripped path with no
    Asset row, surfacing as zero-finding orphans on the frontend.
    """
    img = (image or "").strip()
    if not img:
        return img
    kind = infer_asset_kind(img, "")
    if kind in ("container", "repo"):
        return apply_container_asset_path_aliases(
            normalize_container_ref(img).canonical_asset_key
        )
    return img


def container_merge_group_key(source_asset_id: str) -> str | None:
    """
    Grouping key for a merge *source* when it is container-like.
    Matches get_assets_with_findings / frontend container list grouping.
    """
    src = (source_asset_id or "").strip()
    if not src or infer_asset_kind(src, "") != "container":
        return None
    return _container_image_group_key(src, None)


def merge_candidate_image_like_prefixes(source_asset_id: str) -> list[str]:
    """
    Distinct repo prefixes (no tag) to find findings.image/component rows that differ
    only by registry prefix or tag/digest suffix from the merge source.
    """
    s = (source_asset_id or "").strip()
    if not s:
        return []
    out: set[str] = {s}
    if infer_asset_kind(s, "") != "container":
        return sorted(out, key=len, reverse=True)
    n = normalize_container_ref(s)
    k = apply_container_asset_path_aliases(n.canonical_asset_key)
    out.add(k)
    out.add(n.canonical_asset_key)
    low = k.lower()
    if low.startswith("docker.io/"):
        out.add(k[len("docker.io/") :])
    return sorted({x for x in out if x}, key=len, reverse=True)


def finding_value_matches_merge_source(
    field_value: str | None,
    source_asset_id: str,
    *,
    source_container_key: str | None,
) -> bool:
    """Whether this finding column should be rewritten to the merge target."""
    val = (field_value or "").strip()
    src = (source_asset_id or "").strip()
    if not val or not src:
        return False
    if val == src:
        return True
    if source_container_key is None:
        return False
    if infer_asset_kind(val, "") != "container":
        return False
    return _container_image_group_key(val, None) == source_container_key


def _asset_key_from_finding(f: Finding) -> str:
    """Match frontend assetUtils.assetKey: image or component only. Branches/tags on asset page."""
    img = (f.image or "").strip()
    comp = (f.component or "").strip()
    if img:
        tag_val = getattr(f, "tag", None)
        tag_s = tag_val.strip() if isinstance(tag_val, str) else None
        return _container_image_group_key(img, tag_s)
    if comp:
        return comp
    return f"unknown-{f.id}"


def _severity_to_key(sev: str) -> str:
    s = (sev or "").lower()
    if s == "critical":
        return "critical"
    if s == "high":
        return "high"
    if s in ("medium", "moderate"):
        return "medium"
    if s == "low":
        return "low"
    return "info"


def _compute_ora_score(counts: dict[str, int]) -> int:
    """ORA 0-100, higher = safer. Matches frontend computeORAScore."""
    penalty = 0
    penalty += counts.get("critical", 0) * ORA_WEIGHTS["critical"]
    penalty += counts.get("high", 0) * ORA_WEIGHTS["high"]
    med = counts.get("medium", 0) * ORA_WEIGHTS["medium"]
    penalty += min(med, ORA_CAPS["medium"])
    low = counts.get("low", 0) * ORA_WEIGHTS["low"]
    penalty += min(low, ORA_CAPS["low"])
    return max(0, min(100, round(100 - penalty)))


def _finding_to_api_dict(f: Finding) -> dict:
    return FindingRead.model_validate(f).to_api_dict()


def _days_left(sla_due: Optional[str]) -> Optional[int]:
    """Days until SLA due. Negative = overdue. None if no date."""
    if not sla_due:
        return None
    from datetime import datetime, timezone

    try:
        if sla_due.endswith("Z"):
            dt = datetime.fromisoformat(sla_due.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(sla_due)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = dt - datetime.now(timezone.utc)
        return delta.days
    except (ValueError, TypeError):
        return None


def _asset_key_from_dict(d: dict) -> str:
    """Group findings like _asset_key_from_finding (camelCase API dicts)."""
    img = (d.get("image") or "").strip()
    comp = (d.get("component") or "").strip()
    tag = (d.get("tag") or "").strip() or None
    if img:
        return _container_image_group_key(img, tag)
    if comp:
        return comp
    return f"unknown-{d.get('id', '')}"


def _build_asset_payload(
    asset_key: str,
    findings: list[dict],
    sev_order: tuple[str, ...] = SEV_ORDER,
    asset_type: str | None = None,
    asset_branch: str | None = None,
    asset_tag: str | None = None,
    include_findings: bool = True,
) -> dict[str, Any]:
    """Build asset dict matching frontend Asset shape."""
    status_breakdown: dict[str, int] = {}
    open_count = 0
    in_review_count = 0
    overdue_count = 0
    verified_count = 0
    worst_idx = -1
    for d in findings:
        status = d.get("status") or "Open"
        status_breakdown[status] = status_breakdown.get(status, 0) + 1
        if is_open_risk(status):
            open_count += 1
        if status == "In Review":
            in_review_count += 1
        if is_overdue_open_risk(status, d.get("slaDue")):
            overdue_count += 1
        if is_verified_disposition(status):
            verified_count += 1
        sev = (d.get("severity") or "").strip()
        idx = sev_order.index(sev) if sev in sev_order else -1
        if idx >= 0 and (worst_idx < 0 or idx < worst_idx):
            worst_idx = idx

    verified_pct = (
        round((verified_count / len(findings)) * 1000) / 10 if findings else 100
    )
    open_findings = [
        d
        for d in findings
        if is_open_risk(d.get("status") or "Open")
    ]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for d in open_findings:
        k = _severity_to_key(d.get("severity") or "")
        if k in counts:
            counts[k] += 1
    ora_pct = _compute_ora_score(counts) if open_findings else 100

    # When findings exist, infer from all of them (dynamic). Asset row type only for 0-finding rows.
    resolved_type = (
        infer_asset_type_from_findings(findings)
        if findings
        else (asset_type or "package")
    )
    # ``tag`` is a variant identifier (container tag / branch-like value), not an asset id.
    # Do not derive it heuristically from package versions or image ref strings.
    # For container assets, select the most frequent explicit finding tag, then stable sort.
    tag = None
    if resolved_type == "container":
        tag_counts: dict[str, int] = {}
        for d in findings:
            raw = d.get("tag")
            if not isinstance(raw, str):
                continue
            t = raw.strip()
            if not t:
                continue
            lower = t.lower()
            if (
                t == asset_key
                or "/images/" in lower
                or lower.startswith("docker.io/")
                or lower.startswith("ghcr.io/")
            ):
                continue
            tag_counts[t] = int(tag_counts.get(t, 0)) + 1
        if tag_counts:
            tag = sorted(tag_counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        elif isinstance(asset_tag, str) and asset_tag.strip():
            tag = asset_tag.strip()
    elif isinstance(asset_tag, str) and asset_tag.strip():
        tag = asset_tag.strip()
    return {
        "id": asset_key,
        "name": asset_key,
        "type": resolved_type,
        "branch": asset_branch,
        "tag": tag,
        "findings": findings if include_findings else [],
        "findingIds": [d.get("id") for d in findings if d.get("id")] if not include_findings else [],
        "openCount": open_count,
        "inReviewCount": in_review_count,
        "statusBreakdown": status_breakdown,
        "worstSeverity": sev_order[worst_idx] if worst_idx >= 0 else "Informational",
        "overdueCount": overdue_count,
        "verifiedPct": verified_pct,
        "oraPct": ora_pct,
    }


async def get_assets_with_findings(
    db: AsyncSession,
    *,
    findings_dicts: Optional[list[dict]] = None,
    ctx: Optional["UserContext"] = None,
    archived: Optional[bool] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    finding_type: Optional[str] = None,
    asset: Optional[str] = None,
    search: Optional[str] = None,
    search_fields: Optional[str] = None,
    limit: int = 0,
    include_zero_assets: bool = True,
    include_findings: bool = True,
) -> list[dict[str, Any]]:
    """
    Return assets (Asset records + findings-derived) with findings.
    Asset records ensure repos/containers with zero findings appear.
    Pass findings_dicts to avoid double fetch; otherwise uses list_findings.
    """
    if findings_dicts is None:
        from app.services.findings_service import (
            enrich_findings_with_source_group_severity,
            list_findings,
        )

        findings = await list_findings(
            db,
            ctx=ctx,
            archived=archived,
            status=status,
            severity=severity,
            source=source,
            finding_type=finding_type,
            asset=asset,
            search=search,
            search_fields=search_fields,
            limit=limit,
        )
        findings_dicts = [FindingRead.model_validate(f).to_api_dict() for f in findings]
        findings_dicts = await enrich_findings_with_source_group_severity(
            db, findings_dicts
        )

    by_key: dict[str, list[dict]] = {}
    for d in findings_dicts:
        key = _asset_key_from_dict(d)
        by_key.setdefault(key, []).append(d)

    # Add Asset records that have no findings when requested.
    asset_records: dict[str, Asset] = {}
    if include_zero_assets:
        asset_q = select(Asset)
        # Current Asset rows are global integration inventory records and do
        # not carry tenant_id in the live schema. Apply tenant scoping only
        # when the model/schema supports it; tenant-scoped findings above
        # still constrain all finding-derived assets.
        if ctx is not None and hasattr(Asset, "tenant_id"):
            asset_q = asset_q.where(tenant_filter(Asset, ctx))
        result = await db.execute(asset_q)
        asset_records = {a.id: a for a in result.scalars().all()}
        for aid in asset_records:
            if aid not in by_key:
                by_key[aid] = []

    # Build asset payloads (include type and branch from Asset record when available)
    payloads = [
        _build_asset_payload(
            k,
            flist,
            asset_type=getattr(asset_records.get(k), "type", None),
            asset_branch=getattr(asset_records.get(k), "branch", None),
            asset_tag=getattr(asset_records.get(k), "tag", None),
            include_findings=include_findings,
        )
        for k, flist in by_key.items()
    ]
    asset_ids = [p["id"] for p in payloads]
    if not asset_ids:
        return payloads

    observed_rows = (
        (
            await db.execute(
                select(AssetObservedTag).where(AssetObservedTag.asset_id.in_(asset_ids))
            )
        )
        .scalars()
        .all()
    )
    observed_by_asset: dict[str, list[dict[str, Any]]] = {}
    for row in observed_rows:
        observed_by_asset.setdefault(row.asset_id, []).append(
            {
                "tag": row.tag,
                "firstSeenAt": row.first_seen_at.isoformat()
                if row.first_seen_at
                else None,
                "lastSeenAt": row.last_seen_at.isoformat()
                if row.last_seen_at
                else None,
                "observationCount": int(row.observation_count or 0),
                "lastDigest": row.last_digest,
            }
        )

    conflict_rows = (
        (
            await db.execute(
                select(AssetDigestConflict).where(
                    AssetDigestConflict.asset_id.in_(asset_ids),
                    AssetDigestConflict.status == "open",
                )
            )
        )
        .scalars()
        .all()
    )
    open_conflicts: dict[str, list[dict[str, Any]]] = {}
    for row in conflict_rows:
        open_conflicts.setdefault(row.asset_id, []).append(
            {
                "tag": row.tag,
                "digests": list(row.digests or []),
                "firstSeenAt": row.first_seen_at.isoformat()
                if row.first_seen_at
                else None,
                "lastSeenAt": row.last_seen_at.isoformat()
                if row.last_seen_at
                else None,
            }
        )

    for payload in payloads:
        aid = payload["id"]
        tags = observed_by_asset.get(aid, [])
        tags.sort(key=lambda t: (t.get("tag") or ""))
        payload["observedTags"] = tags
        conflicts = open_conflicts.get(aid, [])
        payload["digestConflictOpen"] = len(conflicts) > 0
        payload["digestConflicts"] = conflicts

    return payloads
