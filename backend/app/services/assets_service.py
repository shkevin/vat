"""Assets service — combine Asset records with findings-derived assets."""

from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.finding import Finding
from app.schemas.finding import FindingRead
from app.services.asset_type_infer import infer_asset_type_from_findings

SEV_ORDER = ("Critical", "High", "Medium", "Low", "Informational")

# ORA weights (matches frontend ora.ts)
ORA_WEIGHTS = {"critical": 10, "high": 4, "medium": 0.5, "low": 0.25}
ORA_CAPS = {"low": 10, "medium": 30}


def _container_image_group_key(image: str, tag: Optional[str]) -> str:
    """Match frontend containerImageGroupKey — one asset row per image, not per tag."""
    img = (image or "").strip()
    if not img:
        return img
    if img.startswith("containers/images/"):
        return img.split(":")[0]
    t = (tag or "").strip()
    if t:
        last_colon = img.rfind(":")
        if last_colon > 0:
            after = img[last_colon + 1 :]
            if "/" not in after and after == t:
                return img[:last_colon]
    last_slash = img.rfind("/")
    last_colon = img.rfind(":")
    if last_colon > last_slash >= 0:
        after = img[last_colon + 1 :]
        if "/" not in after:
            return img[:last_colon]
    return img


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
        if status == "Open":
            open_count += 1
        if status == "In Review":
            in_review_count += 1
        if status not in (
            "Resolved",
            "False Positive",
            "Duplicate",
            "Not Applicable",
            "Approved",
            "Suppressed",
        ):
            days = _days_left(d.get("slaDue"))
            if days is not None and days < 0:
                overdue_count += 1
        if status in (
            "Resolved",
            "False Positive",
            "Approved",
            "Suppressed",
            "Not Applicable",
            "Duplicate",
        ):
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
        if d.get("status")
        not in (
            "Resolved",
            "False Positive",
            "Duplicate",
            "Not Applicable",
            "Approved",
            "Suppressed",
        )
    ]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for d in open_findings:
        k = _severity_to_key(d.get("severity") or "")
        if k in counts:
            counts[k] += 1
    ora_pct = _compute_ora_score(counts) if open_findings else 100

    tag = None
    if findings:
        c = findings[0].get("component") or ""
        img = findings[0].get("image") or ""
        import re

        ver_match = re.search(r"\d+\.\d+(\.\d+)?", c)
        if ver_match:
            tag = ver_match.group(0)
        elif ":" in img:
            tag = img.split(":")[1]

    # When findings exist, infer from all of them (dynamic). Asset row type only for 0-finding rows.
    resolved_type = (
        infer_asset_type_from_findings(findings)
        if findings
        else (asset_type or "package")
    )
    return {
        "id": asset_key,
        "name": asset_key,
        "type": resolved_type,
        "branch": asset_branch,
        "tag": tag,
        "findings": findings,
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
    tenant_id: Optional[str] = None,
    archived: Optional[bool] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    finding_type: Optional[str] = None,
    asset: Optional[str] = None,
    search: Optional[str] = None,
    search_fields: Optional[str] = None,
    limit: int = 0,
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
            tenant_id=tenant_id,
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

    # Add Asset records that have no findings; build asset_id -> Asset map for type
    result = await db.execute(select(Asset))
    asset_records: dict[str, Asset] = {a.id: a for a in result.scalars().all()}
    for aid in asset_records:
        if aid not in by_key:
            by_key[aid] = []

    # Build asset payloads (include type and branch from Asset record when available)
    return [
        _build_asset_payload(
            k,
            flist,
            asset_type=getattr(asset_records.get(k), "type", None),
            asset_branch=getattr(asset_records.get(k), "branch", None),
        )
        for k, flist in by_key.items()
    ]
