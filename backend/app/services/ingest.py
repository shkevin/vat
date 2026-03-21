"""Ingest service — processes webhook events, deduplicates, persists. PRD §5.1."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingType, Severity, Status
from app.schemas.vat import VatFindingSchema, VatFindingType, VatSeverity
from app.services.correlation import correlation_key_for_payload
from app.services.findings_service import _status_to_enum
from app.services.dedup import (
    component_base,
    make_fingerprint,
    make_fingerprint_for_source_issue,
)
from app.services.sla import SLA_DAYS


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso_datetime(s: str | None) -> datetime | None:
    """Parse ISO datetime string to naive UTC datetime for DB (TIMESTAMP WITHOUT TIME ZONE)."""
    if not s or not isinstance(s, str) or not s.strip():
        return None
    s = s.strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        elif "+" not in s and "-" in s[-6:]:
            pass
        elif "+" not in s:
            s = s + "+00:00"
        dt = datetime.fromisoformat(s).astimezone(timezone.utc)
        return dt.replace(tzinfo=None)  # naive UTC for DB
    except (ValueError, TypeError):
        return None


def _vat_severity_to_model(sev: VatSeverity) -> Severity:
    """Map VAT severity to model enum."""
    return Severity(sev.value)


_SEVERITY_ORDER = (
    Severity.Critical,
    Severity.High,
    Severity.Medium,
    Severity.Low,
    Severity.Informational,
)


def _max_severity(a: Severity, b: Severity) -> Severity:
    """Return the more severe of two severities (for merge: take max)."""
    try:
        ia = _SEVERITY_ORDER.index(a)
    except ValueError:
        ia = 2  # default Medium
    try:
        ib = _SEVERITY_ORDER.index(b)
    except ValueError:
        ib = 2
    return a if ia <= ib else b


def _vat_type_to_model(ft: VatFindingType) -> FindingType:
    """Map canonical finding type to model enum."""
    return FindingType(ft.value)


def _compute_sla_due(finding_type: FindingType, severity: Severity) -> str:
    """Compute SLA due date from type and severity."""
    days = SLA_DAYS.get(
        (finding_type.value, severity.value), SLA_DAYS.get(("SCA", "Medium"), 30)
    )
    now = datetime.now(timezone.utc)
    due = now + timedelta(days=days)
    return due.strftime("%Y-%m-%d")


async def ingest_finding(
    db: AsyncSession,
    payload: VatFindingSchema,
    source_name: str = "Aikido",
    tenant_id: str | None = None,
    *,
    auto_sync_to_tracker: bool = True,
    aikido_source_id: str | None = None,
) -> tuple[Finding, bool]:
    """
    Ingest a finding from canonical payload. Deduplicates by fingerprint.
    Returns (finding, created) where created=True if new, False if merged.
    When created and auto_sync_to_tracker=True, enqueues tracker create_issue (source-agnostic).
    """
    cve_id = payload.cve_id
    component = payload.component or payload.component_base or ""
    comp_base = payload.component_base or (
        component_base(component) if component else None
    )
    image = payload.image or ""
    branch = getattr(payload, "branch", None) or ""
    tag = getattr(payload, "tag", None) or ""
    corr_key, corr_conf = correlation_key_for_payload(
        finding_type=str(payload.finding_type.value),
        image=image,
        branch=branch,
        tag=tag,
        cve_id=cve_id,
        component=component,
        ecosystem=getattr(payload, "ecosystem", None),
        rule_id=getattr(payload, "rule_id", None),
        file_path=getattr(payload, "file_path", None),
    )
    # When source provides source_issue_id, use 1:1 fingerprint so VAT count matches source (e.g. Aikido).
    # Otherwise use CVE+component+image+branch+tag for cross-source dedup.
    sid = getattr(payload, "source_issue_id", None)
    if sid and str(sid).strip():
        fp = make_fingerprint_for_source_issue(
            source_name, str(sid).strip(), image=image, branch=branch, tag=tag
        )
    else:
        # Include source_name so findings from different parsers (e.g. vat-local-gitleaks vs
        # vat-local-trivy) remain separate — enables "Group findings" toggle to show instances.
        fp = make_fingerprint(
            cve_id,
            component,
            image=image,
            branch=branch,
            tag=tag,
            source_name=source_name,
        )

    finding_type = _vat_type_to_model(payload.finding_type)
    severity = _vat_severity_to_model(payload.severity)
    title = payload.title or cve_id
    description = payload.description or ""

    source_entry = {"name": source_name, "importedAt": _now()}
    audit_entry = {
        "ts": _now(),
        "user": "system",
        "action": f"Imported from {source_name} scan",
        "note": None,
    }

    # Check for existing by fingerprint (dedup is global)
    result = await db.execute(select(Finding).where(Finding.fingerprint_id == fp))
    existing = result.scalar_one_or_none()

    # Migration: when using source_issue_id fp, existing findings may have old CVE+component fp.
    # Fall back to lookup by external_links so we update them and migrate fingerprint.
    if not existing and sid and str(sid).strip():
        from app.services.external_links_service import find_finding_by_external_id

        existing = await find_finding_by_external_id(db, source_name, str(sid).strip())
        if existing and existing.fingerprint_id != fp:
            existing.fingerprint_id = fp
            audit = list(existing.audit or [])
            audit.append(
                {
                    "ts": _now(),
                    "user": "system",
                    "action": "Fingerprint migrated",
                    "note": "1:1 source mapping",
                }
            )
            existing.audit = audit

    if existing:
        # Merge: append source (avoid duplicate), add audit
        sources = list(existing.sources or [])
        if not any(
            s.get("name") == source_name for s in sources if isinstance(s, dict)
        ):
            sources.append(source_entry)
            existing.sources = sources
        if getattr(payload, "source_issue_id", None):
            from app.services.external_links_service import add_source_link

            source_url = getattr(payload, "source_issue_url", None)
            add_source_link(
                existing,
                source_name,
                str(payload.source_issue_id),
                url=source_url
                if source_url and isinstance(source_url, str) and source_url.strip()
                else None,
            )
        if (
            getattr(payload, "source_issue_group_id", None)
            and not existing.source_issue_group_id
        ):
            existing.source_issue_group_id = payload.source_issue_group_id
        if aikido_source_id and not existing.aikido_source_id:
            existing.aikido_source_id = aikido_source_id
        audit = list(existing.audit or [])
        audit.append(
            {
                "ts": _now(),
                "user": "system",
                "action": "Deduplication merge",
                "note": f"Re-import from {source_name}",
            }
        )
        existing.audit = audit
        if tenant_id and not existing.tenant_id:
            existing.tenant_id = tenant_id
        # Backfill image/component/branch/tag for asset grouping when existing has none (e.g. from old bootstrap)
        if payload.image and not existing.image:
            existing.image = payload.image
        if payload.component and not existing.component:
            existing.component = payload.component
        if getattr(payload, "branch", None) and not existing.branch:
            existing.branch = payload.branch
        if getattr(payload, "tag", None) and not existing.tag:
            existing.tag = payload.tag
        if getattr(payload, "source_file_url", None) and not existing.source_file_url:
            existing.source_file_url = payload.source_file_url
        if getattr(payload, "file_path", None) and not existing.file_path:
            existing.file_path = payload.file_path
        if getattr(payload, "line", None) is not None and existing.line is None:
            existing.line = payload.line
        if getattr(payload, "snippet_masked", None) and not existing.snippet_masked:
            existing.snippet_masked = payload.snippet_masked
        if corr_key and not existing.correlation_key:
            existing.correlation_key = corr_key
            existing.correlation_confidence = corr_conf
        # Backfill grouping fields when existing has none
        for attr in ("rule_id", "cwe_id", "ecosystem", "secret_type", "resource"):
            pv = getattr(payload, attr, None)
            if pv and not getattr(existing, attr, None):
                setattr(existing, attr, pv)
        # Backfill first_detected_at when existing has none (for report trend alignment)
        fd = _parse_iso_datetime(getattr(payload, "first_detected_at", None))
        if fd and not existing.first_detected_at:
            existing.first_detected_at = fd
        # Backfill closed_at when existing has none (for report trend alignment)
        cd = _parse_iso_datetime(getattr(payload, "closed_at", None))
        if cd and not existing.closed_at:
            existing.closed_at = cd
        # Backfill title/description when empty (e.g. from old Aikido adapter)
        if payload.title and (not existing.title or existing.title == existing.cve_id):
            existing.title = payload.title
        if payload.description and not (existing.description or "").strip():
            existing.description = payload.description
        # Take max severity when merging (incoming may be higher than first-seen; fixes VAT vs Aikido mismatch)
        new_sev = _max_severity(existing.severity, severity)
        if new_sev != existing.severity:
            existing.severity = new_sev
            existing.sla_due = _compute_sla_due(finding_type, new_sev)
        # Sync status from source when Aikido reports ignored/closed
        payload_status = getattr(payload, "status", None)
        if payload_status and payload_status not in ("Open", "Reopened"):
            try:
                source_status = _status_to_enum(payload_status)
                if source_status in (
                    Status.Resolved,
                    Status.Suppressed,
                    Status.FalsePositive,
                    Status.NotApplicable,
                ):
                    existing.status = source_status
                    if cd:
                        existing.closed_at = cd
                    audit.append(
                        {
                            "ts": _now(),
                            "user": "system",
                            "action": "Status synced from source",
                            "note": payload_status,
                        }
                    )
            except (ValueError, KeyError):
                pass
        # If previously Resolved, treat as regression per PRD §5.6 (only when source says open)
        elif existing.status == Status.Resolved:
            existing.status = Status.Reopened
            existing.closed_at = None
            regression_of = list(existing.regression_of or [])
            regression_of.append(existing.id)
            existing.regression_of = regression_of
            existing.regression_count = (existing.regression_count or 0) + 1
            audit.append(
                {
                    "ts": _now(),
                    "user": "system",
                    "action": "Regression detected",
                    "note": "Scanner re-detected previously resolved finding",
                }
            )
        await db.commit()
        await db.refresh(existing)
        return existing, False

    # Create new finding
    finding_id = f"f-{fp[:8]}"
    sla_due = _compute_sla_due(finding_type, severity)

    source_issue_group_id = getattr(payload, "source_issue_group_id", None)

    external_links: list = []
    if getattr(payload, "source_issue_id", None):
        from datetime import datetime, timezone

        source_url = getattr(payload, "source_issue_url", None)
        external_links = [
            {
                "adapter_key": source_name,
                "kind": "source",
                "issue_id": str(payload.source_issue_id),
                "url": source_url
                if source_url and isinstance(source_url, str) and source_url.strip()
                else None,
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        ]

    # Use source status when provided (e.g. Aikido ignored/closed)
    initial_status = Status.Open
    payload_status = getattr(payload, "status", None)
    if payload_status and payload_status not in ("Open", "Reopened"):
        try:
            initial_status = _status_to_enum(payload_status)
        except (ValueError, KeyError):
            pass

    first_detected = _parse_iso_datetime(getattr(payload, "first_detected_at", None))
    closed = _parse_iso_datetime(getattr(payload, "closed_at", None))

    finding = Finding(
        id=finding_id,
        finding_type=finding_type,
        fingerprint_id=fp,
        cve_id=cve_id,
        severity=severity,
        status=initial_status,
        component_base=comp_base,
        component=payload.component or None,
        image=payload.image,
        branch=getattr(payload, "branch", None),
        tag=getattr(payload, "tag", None),
        title=title,
        description=description,
        source_file_url=getattr(payload, "source_file_url", None),
        file_path=getattr(payload, "file_path", None),
        line=getattr(payload, "line", None),
        snippet_masked=getattr(payload, "snippet_masked", None),
        rule_id=getattr(payload, "rule_id", None),
        cwe_id=getattr(payload, "cwe_id", None),
        ecosystem=getattr(payload, "ecosystem", None),
        secret_type=getattr(payload, "secret_type", None),
        resource=getattr(payload, "resource", None),
        first_detected_at=first_detected,
        closed_at=closed,
        source=source_name,
        team=payload.team,
        owner=payload.owner,
        sla_due=sla_due,
        cvss=payload.cvss,
        epss=payload.epss,
        sources=[source_entry],
        audit=[audit_entry],
        tenant_id=tenant_id,
        external_links=external_links,
        source_issue_group_id=source_issue_group_id,
        aikido_source_id=aikido_source_id if source_name == "Aikido" else None,
        correlation_key=corr_key,
        correlation_confidence=corr_conf,
        correlated_to=None,
    )
    db.add(finding)
    await db.commit()
    await db.refresh(finding)

    if auto_sync_to_tracker:
        from app.services.sync_service import maybe_enqueue_tracker_for_new_finding

        await maybe_enqueue_tracker_for_new_finding(db, finding, auto_sync=True)
        await db.commit()
        await db.refresh(finding)

    return finding, True
