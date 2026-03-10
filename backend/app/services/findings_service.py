"""Findings service — list, create, filter."""

import uuid
from typing import Any, Optional

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from datetime import datetime

from app.models.finding import Finding, FindingType, Severity, Status, SuppressionScope
from app.services.sync_service import (
    SOURCE_IGNORE_STATUSES,
    TRACKER_DECISION_STATUSES,
    _supports_outbound_sync,
    enqueue_source_ignore,
    enqueue_source_unignore,
    enqueue_tracker_post_decision,
)
from app.tasks.sync_tasks import trigger_sync_worker
from app.schemas.finding import FindingCreate, FindingRead, STATUS_DISPLAY

# Reverse: display format -> enum value. Aikido "ignored" maps to Suppressed (same semantics).
STATUS_FROM_DISPLAY = {v: k for k, v in STATUS_DISPLAY.items()} | {
    "Open": "Open",
    "Approved": "Approved",
    "Rejected": "Rejected",
    "Suppressed": "Suppressed",
    "Ignored": "Suppressed",  # Aikido ignored = VAT Suppressed; display as Suppressed, same counts
    "Mitigated": "Mitigated",
    "Duplicate": "Duplicate",
    "Resolved": "Resolved",
    "Reopened": "Reopened",
    "Synced to Tracker": "SyncedToTracker",
    "In Review": "InReview",
    "Risk Accepted": "RiskAccepted",
    "False Positive": "FalsePositive",
    "Not Applicable": "NotApplicable",
}


def _status_to_enum(s: str) -> Status:
    val = STATUS_FROM_DISPLAY.get(s, s)
    return Status(val)


# Source names that have dashboard-style group metadata (group_id -> severity). Used for grouped severity display.
_SOURCES_WITH_GROUP_METADATA = ("Aikido",)


def _normalize_group_severity(sev: str) -> str:
    """Normalize severity from source format to VAT display format."""
    s = (sev or "").lower()
    if s == "critical":
        return "Critical"
    if s == "high":
        return "High"
    if s in ("medium", "moderate"):
        return "Medium"
    if s == "low":
        return "Low"
    return "Informational"


async def enrich_findings_with_source_group_severity(
    db: AsyncSession, rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Enrich finding dicts with sourceGroupSeverity when the source provides group-level severity.
    Used for grouped display so VAT shows the source's canonical group severity instead of max.
    """
    from app.services.aikido_dashboard_sync import get_aikido_dashboard_cached

    data = await get_aikido_dashboard_cached(db)
    if not data or not isinstance(data.get("issueGroups"), list):
        return rows

    group_map: dict[str, str] = {}
    for g in data["issueGroups"]:
        if not isinstance(g, dict):
            continue
        gid = g.get("id") or g.get("group_id")
        if gid is None:
            continue
        sev = g.get("severity")
        if not sev:
            continue
        gid_str = str(gid).strip()
        if not gid_str:
            continue
        for src in _SOURCES_WITH_GROUP_METADATA:
            group_map[f"{src}:{gid_str}"] = _normalize_group_severity(str(sev))

    for d in rows:
        src = (d.get("source") or "").strip()
        sid_raw = d.get("sourceIssueGroupId")
        if not src or sid_raw is None:
            continue
        sid = str(sid_raw).strip()
        if not sid:
            continue
        key = f"{src}:{sid}"
        if key in group_map:
            d["sourceGroupSeverity"] = group_map[key]
    return rows


async def list_findings(
    db: AsyncSession,
    *,
    tenant_id: Optional[str] = None,
    archived: Optional[bool] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    finding_type: Optional[str] = None,
    asset: Optional[str] = None,
    search: Optional[str] = None,
    search_fields: Optional[str] = None,
    limit: int = 0,  # 0 = no limit
) -> list[Finding]:
    """List findings with optional filters."""
    q = select(Finding)
    if tenant_id is not None:
        # Include findings for this tenant OR global (tenant_id=None) so bootstrap/webhook findings are visible
        q = q.where((Finding.tenant_id == tenant_id) | (Finding.tenant_id.is_(None)))
    if archived is not None:
        q = q.where(Finding.archived == archived)
    if status:
        parts = [p.strip() for p in status.split(",") if p.strip()]
        if parts:
            enums = []
            for p in parts:
                try:
                    enums.append(_status_to_enum(p))
                except ValueError:
                    pass
            if enums:
                q = q.where(Finding.status.in_(enums))
    if severity:
        parts = [p.strip() for p in severity.split(",") if p.strip()]
        if parts:
            sevs = []
            for p in parts:
                try:
                    sevs.append(Severity(p))
                except ValueError:
                    pass
            if sevs:
                q = q.where(Finding.severity.in_(sevs))
    if source:
        parts = [p.strip() for p in source.split(",") if p.strip()]
        if parts:
            q = q.where(Finding.source.in_(parts))
    if finding_type:
        parts = [p.strip() for p in finding_type.split(",") if p.strip()]
        if parts:
            types = []
            for p in parts:
                try:
                    types.append(FindingType(p))
                except ValueError:
                    pass
            if types:
                q = q.where(Finding.finding_type.in_(types))
    if asset:
        q = q.where(
            (Finding.component.ilike(f"%{asset}%")) | (Finding.image.ilike(f"%{asset}%"))
        )
    if search:
        term = f"%{search}%"
        fields = [p.strip().lower() for p in (search_fields or "").split(",") if p.strip()]
        if not fields:
            fields = ["cve_id", "title", "component", "image", "team", "owner"]
        clauses = []
        if "cve_id" in fields:
            clauses.append(Finding.cve_id.ilike(term))
        if "title" in fields:
            clauses.append(Finding.title.ilike(term))
        if "component" in fields:
            clauses.append(Finding.component.ilike(term))
        if "image" in fields:
            clauses.append(Finding.image.ilike(term))
        if "team" in fields:
            clauses.append(Finding.team.ilike(term))
        if "owner" in fields:
            clauses.append(Finding.owner.ilike(term))
        if clauses:
            q = q.where(or_(*clauses))
    q = q.order_by(Finding.created_at.desc())
    if limit > 0:
        q = q.limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


async def get_finding(db: AsyncSession, finding_id: str) -> Finding | None:
    """Get a single finding by ID."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    return result.scalar_one_or_none()


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


SYNCABLE_TRACKER_FIELDS = {"status", "severity", "title", "labels"}


async def _enqueue_tracker_update_issue_if_supported(
    db: AsyncSession, finding: Finding, changed_fields: list[str]
) -> None:
    """Enqueue update_issue for each tracker link when adapter supports it and fields are syncable."""
    from app.api.settings import get_labels, get_tracker_key
    from app.adapters.registry import TRACKER_ADAPTER_REGISTRY
    from app.services.external_links_service import get_all_tracker_links
    from app.services.sync_service import enqueue_tracker_update_issue

    if not changed_fields:
        return
    syncable = set(changed_fields) & SYNCABLE_TRACKER_FIELDS
    if not syncable:
        return

    tracker_key = await get_tracker_key(db)
    adapter_cls = TRACKER_ADAPTER_REGISTRY.get(tracker_key)
    if not adapter_cls or not adapter_cls().get_capabilities().supports_update_issue:
        return

    for link in get_all_tracker_links(finding):
        if link.get("adapter_key") != tracker_key:
            continue
        finding_dict = {
            "cveId": finding.cve_id,
            "cve_id": finding.cve_id,
            "title": finding.title,
            "severity": finding.severity.value if finding.severity else None,
            "status": finding.status.value if finding.status else None,
        }
        labels_cfg = await get_labels(db)
        label_names = [l.get("name") for l in labels_cfg if l.get("name")]
        from app.api.settings import labels_to_configs

        label_configs = labels_to_configs(labels_cfg)
        if "labels" not in syncable and label_names:
            syncable = set(syncable) | {"labels"}
        await enqueue_tracker_update_issue(
            db, finding, tracker_key, finding_dict, list(syncable), label_names=label_names, label_configs=label_configs
        )
        break
    trigger_sync_worker(countdown=2)


async def _enqueue_sync_on_status_change(db: AsyncSession, finding: Finding, new_status: Status, user: str) -> None:
    """Enqueue tracker/source sync when status changes. Universal for all adapters."""
    from app.api.settings import get_source_config, get_tracker_key
    from app.services.external_links_service import get_source_issue_id, has_tracker_link

    enqueued = False

    # Tracker: post decision for terminal statuses
    tracker_key = await get_tracker_key(db)
    if new_status in TRACKER_DECISION_STATUSES and has_tracker_link(finding, tracker_key):
        evt = await enqueue_tracker_post_decision(db, finding, tracker_key, user)
        if evt:
            enqueued = True

    # Source: ignore for FP/Suppressed/etc (skip push-only sources)
    if new_status in SOURCE_IGNORE_STATUSES:
        from app.services.external_links_service import get_all_source_links

        for link in get_all_source_links(finding):
            source_name = link.get("adapter_key")
            if source_name and get_source_issue_id(finding, source_name):
                cfg = await get_source_config(db, source_name)
                if cfg and _supports_outbound_sync(cfg):
                    adapter_key = (cfg.get("adapter") or cfg.get("type") or source_name.lower()).lower()
                    scope = "global" if finding.suppression_scope and finding.suppression_scope.value == "global" else "contextual"
                    evt = await enqueue_source_ignore(db, finding, adapter_key, scope, source_name=source_name)
                    if evt:
                        enqueued = True

    # Source: unignore on Reopened
    if new_status == Status.Reopened:
        from app.services.external_links_service import get_all_source_links

        for link in get_all_source_links(finding):
            source_name = link.get("adapter_key")
            if source_name and get_source_issue_id(finding, source_name):
                cfg = await get_source_config(db, source_name)
                if cfg and _supports_outbound_sync(cfg):
                    adapter_key = (cfg.get("adapter") or cfg.get("type") or source_name.lower()).lower()
                    evt = await enqueue_source_unignore(db, finding, adapter_key, source_name=source_name)
                    if evt:
                        enqueued = True

    if enqueued:
        trigger_sync_worker(countdown=2)


async def update_finding(db: AsyncSession, finding_id: str, data: dict, *, user: str = "security@co.com") -> Finding | None:
    """Update a finding. Returns updated finding or None if not found."""
    finding = await get_finding(db, finding_id)
    if not finding:
        return None
    old_status = finding.status
    if "status" in data and data["status"]:
        new_status = _status_to_enum(data["status"])
        if new_status != finding.status:
            finding.previous_status = finding.status.value
            finding.status = new_status
    if "justification" in data:
        finding.justification = data["justification"]
    if "compensating_controls" in data:
        finding.compensating_controls = data["compensating_controls"]
    if "reviewer_note" in data:
        finding.reviewer_note = data["reviewer_note"]
    if "suppression_scope" in data:
        finding.suppression_scope = _suppression_scope(data["suppression_scope"])
    if "attestation" in data:
        finding.attestation = data["attestation"]
    audit = list(finding.audit or [])
    audit.append({"ts": _now(), "user": user, "action": "Finding updated", "note": data.get("justification", "")[:80] or None})
    finding.audit = audit
    await db.flush()

    changed_fields: list[str] = []
    if "status" in data and finding.status != old_status:
        changed_fields.append("status")
    if "status" in data and finding.status != old_status:
        await _enqueue_sync_on_status_change(db, finding, finding.status, user)

    if changed_fields:
        await _enqueue_tracker_update_issue_if_supported(db, finding, changed_fields)

    await db.commit()
    await db.refresh(finding)
    return finding


async def revert_finding(db: AsyncSession, finding_id: str, reason: str, *, user: str = "security@co.com") -> Finding | None:
    """Revert finding to previous status. PRD §5.4.3. Returns updated finding or None."""
    finding = await get_finding(db, finding_id)
    if not finding or not finding.previous_status:
        return None
    try:
        prev_enum = _status_to_enum(finding.previous_status)
    except ValueError:
        return None
    current = finding.status
    target = prev_enum.value
    finding.status = prev_enum
    finding.previous_status = current.value
    audit = list(finding.audit or [])
    audit.append({
        "ts": _now(),
        "user": user,
        "action": f'Reverted "{current.value}" → "{target}"',
        "note": reason[:200] if reason else None,
    })
    finding.audit = audit
    await db.flush()
    await _enqueue_sync_on_status_change(db, finding, prev_enum, user)
    await db.commit()
    await db.refresh(finding)
    return finding


async def archive_finding(db: AsyncSession, finding_id: str, reason: str, *, user: str = "security@co.com") -> Finding | None:
    """Archive a finding. Returns updated finding or None if not found."""
    finding = await get_finding(db, finding_id)
    if not finding:
        return None
    finding.archived = True
    finding.archived_at = datetime.utcnow()
    finding.archived_reason = reason
    audit = list(finding.audit or [])
    audit.append({"ts": _now(), "user": user, "action": "Finding archived", "note": reason})
    finding.audit = audit
    await db.commit()
    await db.refresh(finding)
    return finding


async def unarchive_finding(db: AsyncSession, finding_id: str, *, user: str = "security@co.com") -> Finding | None:
    """Unarchive a finding."""
    finding = await get_finding(db, finding_id)
    if not finding:
        return None
    finding.archived = False
    finding.archived_at = None
    finding.archived_reason = None
    audit = list(finding.audit or [])
    audit.append({"ts": _now(), "user": user, "action": "Finding unarchived", "note": None})
    finding.audit = audit
    await db.commit()
    await db.refresh(finding)
    return finding


async def override_fingerprint(
    db: AsyncSession, finding_id: str, *, user: str = "security@co.com"
) -> Finding | None:
    """Override fingerprint to prevent incorrect dedup merges. PRD §5.1.2."""
    finding = await get_finding(db, finding_id)
    if not finding:
        return None
    old_fp = finding.fingerprint_id
    new_fp = f"{old_fp}_override_{uuid.uuid4().hex[:12]}"
    finding.fingerprint_id = new_fp
    audit = list(finding.audit or [])
    audit.append({
        "ts": _now(),
        "user": user,
        "action": "Fingerprint override",
        "note": f"Manual override: was incorrectly merged. New fingerprint prevents future merges.",
    })
    finding.audit = audit
    await db.commit()
    await db.refresh(finding)
    return finding


async def bulk_update_findings(
    db: AsyncSession,
    ids: list[str],
    status: str,
    justification: str,
    *,
    tenant_id: Optional[str] = None,
    user: str = "security@co.com",
) -> list[Finding]:
    """Bulk update findings to a new status. Returns list of updated findings."""
    q = select(Finding).where(Finding.id.in_(ids))
    if tenant_id is not None:
        q = q.where(Finding.tenant_id == tenant_id)
    result = await db.execute(q)
    findings = list(result.scalars().all())
    new_status = _status_to_enum(status)
    action_note = justification[:80] if justification else None
    for f in findings:
        if new_status != f.status:
            f.previous_status = f.status.value
        f.status = new_status
        f.justification = justification or f.justification
        audit = list(f.audit or [])
        audit.append({"ts": _now(), "user": user, "action": f"Bulk: {status}", "note": action_note})
        f.audit = audit
    await db.flush()
    for f in findings:
        await _enqueue_sync_on_status_change(db, f, new_status, user)
    await db.commit()
    for f in findings:
        await db.refresh(f)
    return findings


async def create_finding(db: AsyncSession, data: FindingCreate) -> Finding:
    """Create a single finding."""
    finding = Finding(
        id=data.id if hasattr(data, "id") else f"f-{data.fingerprint_id[:8]}",
        finding_type=data.finding_type,
        fingerprint_id=data.fingerprint_id,
        cve_id=data.cve_id,
        severity=data.severity,
        status=data.status,
        component_base=data.component_base,
        component=data.component,
        image=data.image,
        title=data.title,
        description=data.description,
        source=data.source,
        team=data.team,
        owner=data.owner,
        control_ref=data.control_ref,
        sla_due=data.sla_due,
        cvss=data.cvss,
        epss=data.epss,
        justification=data.justification,
        compensating_controls=data.compensating_controls,
        reviewer_note=data.reviewer_note,
        tracker_comment=data.tracker_comment,
        sources=data.sources,
        regression_of=data.regression_of,
        regression_count=data.regression_count or 0,
        audit=data.audit,
    )
    db.add(finding)
    await db.commit()
    await db.refresh(finding)
    return finding


def _suppression_scope(s: str | None) -> SuppressionScope | None:
    if not s:
        return None
    return SuppressionScope.global_ if s == "global" else SuppressionScope.contextual


async def create_findings_bulk(db: AsyncSession, items: list[dict], *, replace: bool = True) -> int:
    """Create multiple findings from seed data. Returns count created.
    When replace=True (default), truncates existing findings first for idempotent dev/demo seeding."""
    if replace:
        await db.execute(delete(Finding))
        await db.flush()
    for item in items:
        finding = Finding(
            id=item["id"],
            finding_type=FindingType(item["findingType"]),
            fingerprint_id=item["fingerprintId"],
            cve_id=item["cveId"],
            severity=Severity(item["severity"]),
            status=_status_to_enum(item["status"]),
            component_base=item.get("componentBase"),
            component=item.get("component"),
            image=item.get("image"),
            title=item.get("title"),
            description=item.get("description"),
            source=item.get("source"),
            team=item.get("team"),
            owner=item.get("owner"),
            control_ref=item.get("controlRef"),
            sla_due=item.get("slaDue"),
            cvss=item.get("cvss"),
            epss=item.get("epss"),
            justification=item.get("justification"),
            compensating_controls=item.get("compensatingControls"),
            reviewer_note=item.get("reviewerNote"),
            tracker_comment=item.get("trackerComment", False),
            sources=item.get("sources", []),
            suppression_scope=_suppression_scope(item.get("suppressionScope")),
            attestation=item.get("attestation"),
            regression_of=item.get("regressionOf"),
            regression_count=item.get("regressionCount", 0),
            audit=item.get("audit", []),
            archived=item.get("archived", False),
            archived_at=None,
            archived_reason=item.get("archivedReason"),
        )
        db.add(finding)
    await db.commit()
    return len(items)
