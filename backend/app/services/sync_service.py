"""Universal sync service — queue-based outbound sync for tracker and source adapters.

Fault-tolerant, adapter-agnostic. Push-only sources (CI, manual) skip source sync.
Uses VAT schemas and credential resolver.
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import and_, func, or_, select, type_coerce, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters import aikido, linear  # noqa: F401 — ensure adapters registered
from app.adapters.registry import SOURCE_ADAPTER_REGISTRY, TRACKER_ADAPTER_REGISTRY
from app.models.finding import Finding, Status
from app.services.external_links_service import (
    add_tracker_link,
    get_source_issue_id,
    get_source_issue_url,
    get_tracker_issue_id,
    get_tracker_issue_uuid,
    has_tracker_link,
    remove_tracker_link,
)
from app.models.sync_event import SyncEvent
from app.api.settings import labels_to_configs
from app.schemas.vat import (
    VatSourceIgnoreRequest,
    VatSourceUnignoreRequest,
    VatTrackerCreateIssueRequest,
    VatTrackerPostDecisionRequest,
    VatTrackerUpdateIssueRequest,
)
from app.services.credential_resolver import SettingsCredentialResolver

logger = logging.getLogger(__name__)

_credential_resolver = SettingsCredentialResolver()

# Terminal statuses that warrant posting decision to tracker
TRACKER_DECISION_STATUSES = {
    Status.Approved,
    Status.Rejected,
    Status.RiskAccepted,
    Status.FalsePositive,
    Status.Suppressed,
    Status.NotApplicable,
    Status.Duplicate,
    Status.Resolved,
}

# Statuses that warrant source ignore (FP, Suppressed, Resolved)
SOURCE_IGNORE_STATUSES = {
    Status.FalsePositive,
    Status.Suppressed,
    Status.NotApplicable,
    Status.Duplicate,
    Status.Resolved,
}


def _is_aikido_finding(finding: Finding) -> bool:
    """True when finding is from Aikido (use Aikido's tracker; skip VAT Linear create_issue for these)."""
    if (finding.source or "").strip().lower() == "aikido":
        return True
    if (finding.source_issue_group_id or "").strip():
        return True  # Aikido-specific; other sources don't set this
    return False


def _get_backoff_seconds(attempts: int) -> float:
    """Exponential backoff: 60, 120, 240, ... max 3600."""
    return min(60 * (2**attempts), 3600)


def _record_tracker_created_correctly(
    db: AsyncSession, finding: Finding, tracker_key: str, finding_dict: dict
) -> None:
    """
    Record a completed update_issue so backfill_tracker_corrections skips this finding.
    Used when we CREATE (not link) — the issue was created correctly with labels, no correction needed.
    """
    issue_id = get_tracker_issue_id(finding, tracker_key)
    issue_uuid = get_tracker_issue_uuid(finding, tracker_key)
    from app.schemas.vat import VatTrackerUpdateIssueRequest

    request = VatTrackerUpdateIssueRequest(
        issue_id=issue_id or "",
        finding=finding_dict,
        changed_fields=[],
        issue_uuid=issue_uuid,
    )
    evt = SyncEvent(
        finding_id=finding.id,
        target="tracker",
        target_key=tracker_key,
        event_type="update_issue",
        payload=request.model_dump(),
        status="completed",
        completed_at=datetime.now(timezone.utc),
    )
    db.add(evt)


async def reset_failed_tracker_events(db: AsyncSession, target_key: str) -> int:
    """
    Reset failed tracker sync events to pending so they retry after config fix.
    Also resets finding sync_status from sync_failed to pending_sync.
    Returns count of events reset.
    """
    from datetime import datetime, timezone

    result = await db.execute(
        select(SyncEvent).where(
            SyncEvent.target == "tracker",
            SyncEvent.target_key == target_key,
            SyncEvent.status == "failed",
        )
    )
    events = list(result.scalars().all())
    if not events:
        return 0
    finding_ids = [e.finding_id for e in events]
    await db.execute(
        update(SyncEvent)
        .where(
            SyncEvent.target == "tracker",
            SyncEvent.target_key == target_key,
            SyncEvent.status == "failed",
        )
        .values(
            status="pending",
            attempts=0,
            last_error=None,
            next_retry_at=None,
            updated_at=datetime.now(timezone.utc),
        )
    )
    await db.execute(
        update(Finding)
        .where(
            Finding.id.in_(finding_ids),
            Finding.sync_status == "sync_failed",
        )
        .values(sync_status="pending_sync", sync_last_error=None, sync_failed_at=None)
    )
    return len(events)


def _supports_outbound_sync(source_config: dict) -> bool:
    """Push sources (CI, manual) do not support sync back. Webhook sources do."""
    auth_type = (
        source_config.get("authType") or source_config.get("auth_type") or "webhook"
    ).lower()
    if auth_type == "push":
        return False
    return source_config.get("supportsOutboundSync", True)


async def enqueue_sync_event(
    db: AsyncSession,
    finding_id: str,
    target: str,
    target_key: str,
    event_type: str,
    payload: dict,
) -> SyncEvent:
    """Enqueue an outbound sync event. Returns the created event."""
    event = SyncEvent(
        finding_id=finding_id,
        target=target,
        target_key=target_key,
        event_type=event_type,
        payload=payload,
        status="pending",
    )
    db.add(event)
    await db.flush()
    return event


async def maybe_enqueue_tracker_for_new_finding(
    db: AsyncSession,
    finding: Finding,
    *,
    auto_sync: bool = True,
) -> bool:
    """
    Generic post-ingest hook: enqueue create_issue for a newly created finding when tracker
    is configured and severity meets threshold. Source-agnostic — called from ingest layer.
    Returns True if enqueued, False otherwise.
    """
    if not auto_sync:
        return False
    if finding.status not in (Status.Open, Status.Reopened, Status.InReview):
        return False

    from app.api.settings import (
        get_labels,
        get_tracker_issue_template,
        get_tracker_key,
        get_tracker_push_min_severity,
        get_tracker_push_mode,
        get_use_aikido_tracking,
        is_tracker_configured_for_creds,
        severity_meets_min,
    )
    from app.services.grouping import get_finding_group_key

    if await get_use_aikido_tracking(db) and _is_aikido_finding(finding):
        return False

    tracker_key = await get_tracker_key(db)
    creds = await _credential_resolver.get_tracker_credentials(db, tracker_key)
    if not is_tracker_configured_for_creds(tracker_key, creds):
        return False

    push_min_severity = await get_tracker_push_min_severity(db)
    if not severity_meets_min(
        finding.severity.value if finding.severity else "", push_min_severity
    ):
        return False

    template = await get_tracker_issue_template(db)
    labels_cfg = await get_labels(db)
    label_names = [l.get("name") for l in labels_cfg if l.get("name")]
    label_configs = labels_to_configs(labels_cfg)

    finding_dict = {
        "cveId": finding.cve_id,
        "cve_id": finding.cve_id,
        "title": finding.title,
        "severity": finding.severity.value if finding.severity else None,
        "component": finding.component,
        "image": finding.image,
        "findingType": finding.finding_type.value if finding.finding_type else None,
        "description": finding.description,
        "finding_id": finding.id,
        "file_path": finding.file_path,
        "line": finding.line,
        "source_file_url": finding.source_file_url,
        "source_issue_url": get_source_issue_url(finding),
    }
    push_mode = await get_tracker_push_mode(db)
    if push_mode == "groups":
        finding_dict["group_key"] = get_finding_group_key(finding)

    evt = await enqueue_tracker_create_issue(
        db,
        finding,
        tracker_key,
        finding_dict,
        template,
        label_names=label_names,
        label_configs=label_configs,
    )
    if evt:
        finding.sync_status = "pending_sync"
        from app.tasks.sync_tasks import trigger_sync_worker

        trigger_sync_worker(countdown=2)
        return True
    return False


async def enqueue_tracker_create_issue(
    db: AsyncSession,
    finding: Finding,
    tracker_key: str,
    finding_dict: dict,
    template: str,
    label_names: Optional[list[str]] = None,
    label_configs: Optional[list] = None,
) -> Optional[SyncEvent]:
    """Enqueue create_issue for tracker. Uses VatTrackerCreateIssueRequest."""
    request = VatTrackerCreateIssueRequest(
        finding=finding_dict,
        template=template,
        label_names=label_names,
        label_configs=label_configs,
    )
    return await enqueue_sync_event(
        db,
        finding.id,
        target="tracker",
        target_key=tracker_key,
        event_type="create_issue",
        payload=request.model_dump(),
    )


async def enqueue_tracker_post_decision(
    db: AsyncSession,
    finding: Finding,
    tracker_key: str,
    user: str,
) -> Optional[SyncEvent]:
    """Enqueue post_decision for tracker."""
    issue_id = get_tracker_issue_id(finding, tracker_key)
    if finding.status not in TRACKER_DECISION_STATUSES or not issue_id:
        return None
    status_display = finding.status.value.replace("_", " ").title()
    body_parts = [
        f"**VAT Reviewer Decision:** {status_display}",
        "",
        f"*Reviewed by {user}*",
    ]
    if finding.reviewer_note:
        body_parts.extend(["", f"**Note:** {finding.reviewer_note}"])
    if finding.justification:
        body_parts.extend(["", f"**Justification:** {finding.justification[:500]}"])
    if finding.attestation:
        att = finding.attestation
        body_parts.extend(
            [
                "",
                f"**Waiver:** {att.get('waiverRef', 'N/A')} | Expires: {att.get('expiresAt', 'N/A')}",
            ]
        )
    body = "\n".join(body_parts)
    request = VatTrackerPostDecisionRequest(
        tracker_issue_id=issue_id,
        body=body,
    )
    return await enqueue_sync_event(
        db,
        finding.id,
        target="tracker",
        target_key=tracker_key,
        event_type="post_decision",
        payload=request.model_dump(),
    )


async def enqueue_tracker_update_issue(
    db: AsyncSession,
    finding: Finding,
    tracker_key: str,
    finding_dict: dict,
    changed_fields: list[str],
    label_names: Optional[list[str]] = None,
    label_configs: Optional[list] = None,
) -> Optional[SyncEvent]:
    """Enqueue update_issue for tracker. Only when adapter supports_update_issue."""
    issue_id = get_tracker_issue_id(finding, tracker_key)
    if not issue_id:
        return None
    issue_uuid = get_tracker_issue_uuid(finding, tracker_key)
    request = VatTrackerUpdateIssueRequest(
        issue_id=issue_id,
        finding=finding_dict,
        changed_fields=changed_fields,
        label_names=label_names,
        label_configs=label_configs,
        issue_uuid=issue_uuid,
    )
    return await enqueue_sync_event(
        db,
        finding.id,
        target="tracker",
        target_key=tracker_key,
        event_type="update_issue",
        payload=request.model_dump(),
    )


async def enqueue_source_ignore(
    db: AsyncSession,
    finding: Finding,
    adapter_key: str,
    scope: str,
    *,
    source_name: Optional[str] = None,
) -> Optional[SyncEvent]:
    """Enqueue source_ignore (FP or Suppressed). scope: 'global' | 'contextual'.
    source_name: key in finding.external_links (e.g. 'Aikido'). If None, uses adapter_key."""
    lookup_key = source_name or adapter_key
    issue_id = get_source_issue_id(finding, lookup_key)
    if not issue_id:
        logger.debug(
            "No source_issue_id for %s on finding %s; skipping source ignore",
            adapter_key,
            finding.id,
        )
        return None
    request = VatSourceIgnoreRequest(issue_id=str(issue_id), scope=scope)
    return await enqueue_sync_event(
        db,
        finding.id,
        target="source",
        target_key=adapter_key,
        event_type="source_ignore",
        payload=request.model_dump(),
    )


async def enqueue_source_unignore(
    db: AsyncSession,
    finding: Finding,
    adapter_key: str,
    *,
    source_name: Optional[str] = None,
) -> Optional[SyncEvent]:
    """Enqueue source_unignore (Reopened). source_name: key in finding.external_links."""
    lookup_key = source_name or adapter_key
    issue_id = get_source_issue_id(finding, lookup_key)
    if not issue_id:
        logger.debug(
            "No source_issue_id for %s on finding %s; skipping source unignore",
            adapter_key,
            finding.id,
        )
        return None
    request = VatSourceUnignoreRequest(issue_id=str(issue_id))
    return await enqueue_sync_event(
        db,
        finding.id,
        target="source",
        target_key=adapter_key,
        event_type="source_unignore",
        payload=request.model_dump(),
    )


async def _apply_create_result(
    db: AsyncSession,
    event: "SyncEvent",
    adapter: object,
    tracker_id: str,
    tracker_uuid: Optional[str],
    *,
    linked_to_existing: bool,
) -> None:
    """Apply create_issue result to finding. Used by batch create path."""
    result = await db.execute(select(Finding).where(Finding.id == event.finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        return
    add_tracker_link(finding, event.target_key, tracker_id, issue_uuid=tracker_uuid)
    finding.sync_status = "synced"
    finding.sync_last_error = None
    finding.sync_failed_at = None
    audit = list(finding.audit or [])
    audit.append(
        {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "user": "system",
            "action": "Synced to Tracker",
            "note": tracker_id,
        }
    )
    finding.audit = audit
    req = VatTrackerCreateIssueRequest.model_validate(event.payload)
    if linked_to_existing and adapter.get_capabilities().supports_update_issue:
        from app.api.settings import get_labels, labels_to_configs

        labels_cfg = await get_labels(db)
        label_names = [l.get("name") for l in labels_cfg if l.get("name")]
        label_configs = labels_to_configs(labels_cfg)
        finding_dict = req.finding or {}
        await enqueue_tracker_update_issue(
            db,
            finding,
            event.target_key,
            finding_dict,
            ["labels"],
            label_names=label_names,
            label_configs=label_configs,
        )
    elif not linked_to_existing:
        _record_tracker_created_correctly(
            db, finding, event.target_key, req.finding or {}
        )


async def process_sync_event(
    db: AsyncSession,
    event: SyncEvent,
    adapter_factory: dict | None = None,
    *,
    adapter: object | None = None,
) -> bool:
    """
    Process a single sync event. Returns True if completed, False if failed (will retry).
    Uses VAT schemas and credential resolver. adapter_factory ignored (kept for compat).
    When adapter is provided (e.g. from batch processing), reuse it to benefit from
    per-adapter caches (e.g. label resolution) and reduce API calls.
    """
    from app.api.settings import get_tracker_push_mode

    event.status = "processing"
    event.attempts += 1
    event.updated_at = datetime.now(timezone.utc)
    await db.flush()

    try:
        if event.target == "tracker":
            adapter_cls = TRACKER_ADAPTER_REGISTRY.get(event.target_key)
            if not adapter_cls:
                raise ValueError(f"Unknown tracker adapter: {event.target_key}")

            if adapter is not None:
                pass  # Use provided adapter (batch mode)
            else:
                creds = await _credential_resolver.get_tracker_credentials(
                    db, event.target_key
                )
                adapter = adapter_cls(**creds)

            if event.event_type == "create_issue":
                if not adapter.get_capabilities().supports_create_issue:
                    raise ValueError(
                        f"Adapter {event.target_key} does not support create_issue"
                    )
                request = VatTrackerCreateIssueRequest.model_validate(event.payload)
                finding_dict = request.finding or {}
                cve_id = finding_dict.get("cve_id") or finding_dict.get("cveId")
                title = finding_dict.get("title") or ""
                group_key = finding_dict.get("group_key")
                push_mode = await get_tracker_push_mode(db)
                # groups: deduplicate by backend group_key (or CVE/title fallback). instances: one ticket per finding.
                tracker_id: Optional[str] = None
                linked_to_existing = False
                if push_mode == "groups":
                    find_group = getattr(
                        adapter, "find_existing_issue_for_group_key", None
                    )
                    if callable(find_group) and group_key:
                        existing = await find_group(group_key)
                        if existing:
                            tracker_id = existing
                            linked_to_existing = True
                            logger.info(
                                "create_issue: linking to existing %s issue %s for group_key (avoiding duplicate)",
                                event.target_key,
                                existing,
                            )
                    if tracker_id is None:
                        find_cve = getattr(adapter, "find_existing_issue_for_cve", None)
                        if callable(find_cve) and cve_id:
                            existing = await find_cve(cve_id)
                            if existing:
                                tracker_id = existing
                                linked_to_existing = True
                                logger.info(
                                    "create_issue: linking to existing %s issue %s for CVE %s (fallback)",
                                    event.target_key,
                                    existing,
                                    cve_id,
                                )
                    if tracker_id is None and title:
                        from app.core.config import get_settings

                        if get_settings().linear_link_title_fallback:
                            find_title = getattr(
                                adapter, "find_existing_issue_for_title", None
                            )
                            if callable(find_title):
                                existing = await find_title(title)
                                if existing:
                                    tracker_id = existing
                                    linked_to_existing = True
                                    logger.info(
                                        "create_issue: linking to existing %s issue %s for title (fallback)",
                                        event.target_key,
                                        existing,
                                    )
                tracker_uuid: Optional[str] = None
                if tracker_id is None:
                    create_result = await adapter.create_issue(request)
                    if isinstance(create_result, tuple):
                        tracker_id, tracker_uuid = (
                            create_result[0],
                            create_result[1] if len(create_result) > 1 else None,
                        )
                    else:
                        tracker_id = create_result
                # Update finding
                result = await db.execute(
                    select(Finding).where(Finding.id == event.finding_id)
                )
                finding = result.scalar_one_or_none()
                if finding:
                    add_tracker_link(
                        finding, event.target_key, tracker_id, issue_uuid=tracker_uuid
                    )
                    # Preserve status — tracked is shown in a separate column, not as a status
                    finding.sync_status = "synced"
                    finding.sync_last_error = None
                    finding.sync_failed_at = None
                    audit = list(finding.audit or [])
                    audit.append(
                        {
                            "ts": datetime.now(timezone.utc).strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            ),
                            "user": "system",
                            "action": "Synced to Tracker",
                            "note": tracker_id,
                        }
                    )
                    finding.audit = audit
                    # When linking to existing issue, labels and status were never applied. Enqueue update_issue.
                    if (
                        linked_to_existing
                        and adapter.get_capabilities().supports_update_issue
                    ):
                        from app.api.settings import get_labels, labels_to_configs

                        labels_cfg = await get_labels(db)
                        label_names = [
                            l.get("name") for l in labels_cfg if l.get("name")
                        ]
                        label_configs = labels_to_configs(labels_cfg)
                        finding_dict = request.finding or {}
                        finding_dict["status"] = (
                            finding.status.value if finding.status else None
                        )
                        await enqueue_tracker_update_issue(
                            db,
                            finding,
                            event.target_key,
                            finding_dict,
                            ["labels", "status"],
                            label_names=label_names,
                            label_configs=label_configs,
                        )
                    # When we created (not linked): issue was created correctly with labels. Record completed
                    # so backfill_tracker_corrections skips it (avoids redundant update_issue).
                    elif not linked_to_existing:
                        _record_tracker_created_correctly(
                            db, finding, event.target_key, request.finding or {}
                        )

            elif event.event_type == "post_decision":
                if not adapter.get_capabilities().supports_post_comment:
                    raise ValueError(
                        f"Adapter {event.target_key} does not support post_comment"
                    )
                request = VatTrackerPostDecisionRequest.model_validate(event.payload)
                await adapter.post_comment(request)

            elif event.event_type == "update_issue":
                if not adapter.get_capabilities().supports_update_issue:
                    raise ValueError(
                        f"Adapter {event.target_key} does not support update_issue"
                    )
                request = VatTrackerUpdateIssueRequest.model_validate(event.payload)
                await adapter.update_issue(request)

            else:
                raise ValueError(f"Unknown tracker event_type: {event.event_type}")

        elif event.target == "source":
            adapter_cls = SOURCE_ADAPTER_REGISTRY.get(event.target_key)
            if not adapter_cls:
                raise ValueError(f"Unknown source adapter: {event.target_key}")

            creds = await _credential_resolver.get_source_credentials(
                db, event.target_key
            )
            adapter = adapter_cls(**creds) if creds else adapter_cls()

            if event.event_type == "source_ignore":
                if not adapter.get_capabilities().supports_ignore:
                    raise ValueError(
                        f"Adapter {event.target_key} does not support ignore_issue"
                    )
                request = VatSourceIgnoreRequest.model_validate(event.payload)
                await adapter.ignore_issue(request)

            elif event.event_type == "source_unignore":
                if not adapter.get_capabilities().supports_unignore:
                    raise ValueError(
                        f"Adapter {event.target_key} does not support unignore_issue"
                    )
                request = VatSourceUnignoreRequest.model_validate(event.payload)
                await adapter.unignore_issue(request)

            else:
                raise ValueError(f"Unknown source event_type: {event.event_type}")

        event.status = "completed"
        event.completed_at = datetime.now(timezone.utc)
        event.last_error = None
        event.next_retry_at = None
        return True

    except Exception as e:
        err_detail = str(e)
        if hasattr(e, "response") and e.response is not None:
            try:
                body = getattr(e.response, "text", None) or ""
                if body:
                    err_detail = f"{err_detail} | response: {body[:500]}"
            except Exception:
                pass
        logger.warning(
            "Sync event %s failed (attempt %d): %s",
            event.id,
            event.attempts,
            err_detail,
        )
        event.last_error = err_detail[:500]
        if event.attempts >= event.max_attempts:
            event.status = "failed"
            # Update finding sync_status if create_issue
            if event.event_type == "create_issue":
                result = await db.execute(
                    select(Finding).where(Finding.id == event.finding_id)
                )
                finding = result.scalar_one_or_none()
                if finding:
                    finding.sync_status = "sync_failed"
                    finding.sync_failed_at = datetime.now(timezone.utc)
                    finding.sync_last_error = str(e)[:500]
        else:
            event.status = "pending"
            backoff = _get_backoff_seconds(event.attempts)
            event.next_retry_at = datetime.now(timezone.utc)
            from datetime import timedelta

            event.next_retry_at = event.next_retry_at + timedelta(seconds=backoff)
        return False


async def process_pending_sync_events(db: AsyncSession, limit: int = 50) -> int:
    """
    Process pending sync events. Returns count processed.
    Uses FOR UPDATE SKIP LOCKED so concurrent Celery workers claim different rows and avoid deadlocks.
    Skips tracker events when tracker is not configured (no API key/team ID).
    """
    from datetime import datetime, timezone

    from app.api.settings import get_tracker_key

    now = datetime.now(timezone.utc)
    stmt = (
        select(SyncEvent)
        .where(
            and_(
                SyncEvent.status.in_(["pending", "processing"]),
                (SyncEvent.next_retry_at.is_(None)) | (SyncEvent.next_retry_at <= now),
            )
        )
        .order_by(SyncEvent.created_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    result = await db.execute(stmt)
    events = list(result.scalars().all())
    processed = 0
    adapter_cache: dict[tuple[str, str], object] = {}
    tracker_key = await get_tracker_key(db)
    tracker_creds = await _credential_resolver.get_tracker_credentials(db, tracker_key)
    tracker_configured = bool(
        tracker_creds.get("api_key") and tracker_creds.get("team_id")
    )

    i = 0
    while i < len(events):
        event = events[i]
        if event.target == "tracker" and not tracker_configured:
            logger.debug(
                "Skipping tracker event %s: tracker not configured", event.event_type
            )
            i += 1
            continue

        cache_key = (
            (event.target, event.target_key)
            if event.target and event.target_key
            else None
        )
        adapter = adapter_cache.get(cache_key) if cache_key else None
        if adapter is None and cache_key and event.target == "tracker":
            adapter_cls = TRACKER_ADAPTER_REGISTRY.get(event.target_key)
            if adapter_cls:
                creds = await _credential_resolver.get_tracker_credentials(
                    db, event.target_key
                )
                adapter = adapter_cls(**creds)
                adapter_cache[cache_key] = adapter

        # Batch consecutive create_issue events (Linear issueBatchCreate)
        if (
            event.target == "tracker"
            and event.event_type == "create_issue"
            and adapter is not None
        ):
            from app.api.settings import get_tracker_push_mode

            push_mode = await get_tracker_push_mode(db)
            create_batch: list[SyncEvent] = []
            j = i
            while (
                j < len(events)
                and events[j].target == event.target
                and events[j].target_key == event.target_key
                and events[j].event_type == "create_issue"
            ):
                create_batch.append(events[j])
                j += 1
            if len(create_batch) >= 2 and hasattr(adapter, "create_issues_batch"):
                for ev in create_batch:
                    ev.status = "processing"
                    ev.attempts += 1
                    ev.updated_at = datetime.now(timezone.utc)
                await db.flush()
                # Classify: link vs create (find_existing per event)
                link_events: list[SyncEvent] = []
                to_create: list[tuple[SyncEvent, VatTrackerCreateIssueRequest]] = []
                for ev in create_batch:
                    req = VatTrackerCreateIssueRequest.model_validate(ev.payload)
                    fd = req.finding or {}
                    gk = fd.get("group_key")
                    cve = fd.get("cve_id") or fd.get("cveId")
                    title = fd.get("title") or ""
                    tracker_id = None
                    if push_mode == "groups":
                        fg = getattr(adapter, "find_existing_issue_for_group_key", None)
                        if callable(fg) and gk:
                            tracker_id = await fg(gk)
                        if tracker_id is None and cve:
                            fc = getattr(adapter, "find_existing_issue_for_cve", None)
                            if callable(fc):
                                tracker_id = await fc(cve)
                        if tracker_id is None and title:
                            ft = getattr(adapter, "find_existing_issue_for_title", None)
                            if callable(ft):
                                tracker_id = await ft(title)
                    if tracker_id:
                        link_events.append((ev, tracker_id))
                    else:
                        to_create.append((ev, req))
                # Process links
                for ev, tid in link_events:
                    await _apply_create_result(
                        db, ev, adapter, tid, None, linked_to_existing=True
                    )
                    ev.status = "completed"
                    ev.completed_at = datetime.now(timezone.utc)
                    ev.attempts += 1
                    ev.updated_at = datetime.now(timezone.utc)
                    ev.last_error = None
                    ev.next_retry_at = None
                    processed += 1
                # Batch create
                if to_create:
                    evs, reqs = zip(*to_create)
                    results = await adapter.create_issues_batch(list(reqs))
                    for ev, req, res in zip(evs, reqs, results):
                        if isinstance(res, Exception):
                            ev.status = "pending"
                            ev.last_error = str(res)[:500]
                            ev.next_retry_at = datetime.now(timezone.utc) + timedelta(
                                seconds=_get_backoff_seconds(ev.attempts)
                            )
                        else:
                            ident, uuid_val = res
                            await _apply_create_result(
                                db,
                                ev,
                                adapter,
                                ident,
                                uuid_val,
                                linked_to_existing=False,
                            )
                            ev.status = "completed"
                            ev.completed_at = datetime.now(timezone.utc)
                            ev.last_error = None
                            ev.next_retry_at = None
                            processed += 1
                        ev.attempts += 1
                        ev.updated_at = datetime.now(timezone.utc)
                i = j
                continue

        # Batch consecutive update_issue events (Linear supports aliased mutations)
        batch_events: list[SyncEvent] = []
        if (
            event.target == "tracker"
            and event.event_type == "update_issue"
            and adapter is not None
        ):
            j = i
            while (
                j < len(events)
                and events[j].target == event.target
                and events[j].target_key == event.target_key
                and events[j].event_type == "update_issue"
            ):
                batch_events.append(events[j])
                j += 1
            if len(batch_events) >= 2 and hasattr(adapter, "update_issues_batch"):
                # Process batch
                requests = [
                    VatTrackerUpdateIssueRequest.model_validate(ev.payload)
                    for ev in batch_events
                ]
                batch_results = await adapter.update_issues_batch(requests)
                for ev, (_, err) in zip(batch_events, batch_results):
                    ev.status = "completed" if err is None else "pending"
                    ev.attempts += 1
                    ev.updated_at = datetime.now(timezone.utc)
                    if err is None:
                        ev.completed_at = datetime.now(timezone.utc)
                        ev.last_error = None
                        ev.next_retry_at = None
                        processed += 1
                    else:
                        ev.last_error = str(err)[:500]
                        ev.next_retry_at = datetime.now(timezone.utc) + timedelta(
                            seconds=_get_backoff_seconds(ev.attempts)
                        )
                i = j
                continue

        success = await process_sync_event(db, event, {}, adapter=adapter)
        if success:
            processed += 1
        i += 1
    await db.commit()
    return processed


def compute_idempotency_key(source: str, event_type: str, *parts: str) -> str:
    """Compute idempotency key from source, event type, and identifying parts."""
    raw = f"{source}:{event_type}:" + ":".join(str(p) for p in parts if p is not None)
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


async def unlink_deleted_linear_issues(db: AsyncSession) -> int:
    """
    Remove tracker links for Linear issues that no longer exist (e.g. manually deleted).
    Uses list_issues_by_ids to verify; findings with missing issues become unlinked so
    backfill_unsynced_findings will recreate them on next sync.
    Returns count of findings unlinked.
    """
    from app.api.settings import get_tracker_key
    from app.adapters.linear import LinearAdapter

    tracker_key = await get_tracker_key(db)
    if tracker_key != "linear":
        return 0
    creds = await _credential_resolver.get_tracker_credentials(db, tracker_key)
    if not creds.get("api_key") or not creds.get("team_id"):
        return 0

    # Bounded scan — full table walks every Beat tick blew up memory once
    # the cluster crossed ~50k findings. Pages drain naturally across ticks.
    scan_limit = get_settings().linear_unlink_scan_limit
    stmt = (
        select(Finding)
        .where(Finding.archived == False)
        .order_by(Finding.id)
        .limit(scan_limit)
    )
    result = await db.execute(stmt)
    findings = list(result.scalars().all())
    # Collect (finding, issue_uuid) for findings with linear link that has issue_uuid
    to_verify: list[tuple[Finding, str]] = []
    for f in findings:
        uuid_val = get_tracker_issue_uuid(f, tracker_key)
        if uuid_val and has_tracker_link(f, tracker_key):
            to_verify.append((f, uuid_val))

    if not to_verify:
        return 0

    uuids = list({u for _, u in to_verify})
    adapter = LinearAdapter(**creds)
    try:
        nodes = await adapter.list_issues_by_ids(uuids, include_comments=False)
    except Exception as e:
        logger.warning(
            "unlink_deleted_linear_issues: Linear API error, skipping: %s", e
        )
        return 0

    existing_ids = {str(n.get("id")) for n in nodes if n.get("id")}
    unlinked = 0
    for finding, issue_uuid in to_verify:
        if issue_uuid not in existing_ids:
            if remove_tracker_link(finding, tracker_key):
                finding.status = Status.Open
                finding.sync_status = "pending_sync"
                finding.sync_last_error = None
                finding.sync_failed_at = None
                audit = list(finding.audit or [])
                audit.append(
                    {
                        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "user": "system",
                        "action": "Unlinked deleted Linear issue",
                        "note": f"issue_uuid={issue_uuid}",
                    }
                )
                finding.audit = audit
                unlinked += 1
                logger.info(
                    "Unlinked finding %s: Linear issue %s no longer exists",
                    finding.id,
                    issue_uuid,
                )
    return unlinked


def _extract_linear_identifier_from_task(task: dict) -> tuple[str | None, str | None]:
    """Extract (issue_id, url) from Aikido task. issue_id for Linear is identifier (e.g. AUT-123)."""
    import re

    identifier = task.get("identifier") or task.get("issue_id") or task.get("issueId")
    if identifier and isinstance(identifier, str) and identifier.strip():
        url = task.get("url") or task.get("link") or task.get("html_url")
        return (identifier.strip(), str(url).strip() if url else None)
    url = task.get("url") or task.get("link") or task.get("html_url")
    if url and isinstance(url, str):
        # Parse Linear-style URL: .../issue/AUT-123 or .../issue/AUT-123-Description
        m = re.search(r"/issue/([A-Za-z0-9]+-[0-9]+)(?:-|$|/)", url)
        if m:
            return (m.group(1), url.strip())
    raw_id = task.get("id")
    if raw_id is not None:
        return (str(raw_id), str(url).strip() if url else None)
    return (None, str(url).strip() if url else None)


async def sync_aikido_tracker_links(
    db: AsyncSession,
    creds: dict,
    raw_issues: list[dict],
    *,
    max_groups: int = 20,
    source_id: str | None = None,
) -> dict:
    """
    When useAikidoTracking: fetch Aikido's linked tasks per issue group, map to VAT findings
    by source_issue_group_id, and add/update tracker links. Tracking comes from Aikido's Linear integration.
    When source_id is provided, uses get_tracker_key_for_source and filters findings by aikido_source_id.
    Returns {updated: int, groups_fetched: int}.
    """
    from app.api.settings import (
        _get_trackers,
        _tracker_adapter_key,
        get_tracker_key,
        get_tracker_key_for_source,
        get_use_aikido_tracking,
    )
    from app.adapters.aikido import fetch_aikido_tasks_for_groups

    if not await get_use_aikido_tracking(db):
        return {"updated": 0, "groups_fetched": 0}

    group_ids: list[int] = []
    seen: set[int] = set()
    for issue in raw_issues or []:
        if not isinstance(issue, dict):
            continue
        gid = issue.get("group_id") or issue.get("groupId")
        if gid is not None:
            try:
                g = int(gid)
                if g not in seen:
                    seen.add(g)
                    group_ids.append(g)
            except (TypeError, ValueError):
                pass

    if not group_ids:
        return {"updated": 0, "groups_fetched": 0}

    tasks_by_group = await fetch_aikido_tasks_for_groups(
        group_ids, credentials=creds, max_groups=max_groups
    )

    if source_id:
        tracker_key = await get_tracker_key_for_source(db, source_id)
        if not tracker_key:
            return {"updated": 0, "groups_fetched": len(tasks_by_group)}
    else:
        # Legacy single-source: use first Aikido tracker
        trackers = await _get_trackers(db)
        tracker_key = None
        for t in trackers:
            if t.get("useAikidoTracking") or t.get("use_aikido_tracking"):
                tracker_key = t.get("id") or _tracker_adapter_key(t)
                break
        if not tracker_key:
            tracker_key = await get_tracker_key(db)
    group_to_task: dict[str, tuple[str, str | None]] = {}
    for gid, tasks in tasks_by_group.items():
        if not tasks or not isinstance(tasks, list):
            continue
        for t in tasks:
            if not isinstance(t, dict):
                continue
            issue_id, url = _extract_linear_identifier_from_task(t)
            if issue_id:
                group_to_task[str(gid)] = (issue_id, url)
                break

    if not group_to_task:
        return {"updated": 0, "groups_fetched": len(tasks_by_group)}

    group_ids_str = list(group_to_task.keys())
    stmt = select(Finding).where(
        Finding.archived == False,
        Finding.source_issue_group_id.in_(group_ids_str),
    )
    if source_id:
        stmt = stmt.where(Finding.aikido_source_id == source_id)
    result = await db.execute(stmt)
    findings = list(result.scalars().unique().all())
    updated = 0
    for finding in findings:
        gid = (finding.source_issue_group_id or "").strip()
        if not gid or gid not in group_to_task:
            continue
        issue_id, url = group_to_task[gid]
        add_tracker_link(finding, tracker_key, issue_id, url=url)
        updated += 1

    if updated > 0:
        await db.flush()
        logger.info(
            "Aikido tracker sync: updated %d findings with linked tasks (groups_fetched=%d)",
            updated,
            len(tasks_by_group),
        )
    return {"updated": updated, "groups_fetched": len(tasks_by_group)}


async def link_linear_issues_to_findings(
    db: AsyncSession, max_issues: int = 500
) -> dict:
    """
    Pull existing Linear issues and link them to VAT findings.
    When pushMode=groups: match by [VAT-GROUP: key] in description (backend group key), then CVE/title fallback.
    When pushMode=instances: this function is skipped (each finding gets its own issue).
    When useAikidoTracking: only Aikido findings are skipped — non-Aikido findings still get linked.
    Returns {linked: int, fetched: int}.
    """
    from app.api.settings import (
        get_tracker_key,
        get_tracker_push_min_severity,
        get_use_aikido_tracking,
        severity_meets_min,
    )
    from app.adapters.linear import LinearAdapter

    use_aikido = await get_use_aikido_tracking(db)
    from app.core.config import get_settings
    from app.services.grouping import get_finding_group_key

    tracker_key = await get_tracker_key(db)
    creds = await _credential_resolver.get_tracker_credentials(db, tracker_key)
    if not creds.get("api_key") or not creds.get("team_id"):
        return {"linked": 0, "fetched": 0}

    adapter = LinearAdapter(**creds)
    group_key_to_issue: dict[
        str, str
    ] = {}  # group_key -> identifier (from [VAT-GROUP: key])
    cve_to_issue: dict[str, str] = {}  # cve_id -> identifier (fallback)
    title_to_issue: dict[str, str] = {}  # normalized_title -> identifier (fallback)
    identifier_to_uuid: dict[
        str, Optional[str]
    ] = {}  # identifier -> Linear UUID for poll
    fetched = 0
    cursor: Optional[str] = None

    while fetched < max_issues:
        first = min(100, max_issues - fetched)
        nodes, cursor = await adapter.list_issues(
            first=first, after=cursor, include_archived=False
        )
        fetched += len(nodes)
        for node in nodes:
            identifier = node.get("identifier") or node.get("id")
            if not identifier:
                continue
            issue_uuid = node.get("id")  # Linear UUID for efficient poll filtering
            if issue_uuid:
                identifier_to_uuid[identifier] = issue_uuid
            title = node.get("title") or ""
            desc = node.get("description") or ""
            gk = LinearAdapter._extract_group_key(desc)
            if gk and gk not in group_key_to_issue:
                group_key_to_issue[gk] = identifier
            for cve in LinearAdapter.extract_cve_ids(title + " " + desc):
                if cve not in cve_to_issue:
                    cve_to_issue[cve] = identifier
            if get_settings().linear_link_title_fallback:
                norm_title = LinearAdapter._normalize_title(title)
                if norm_title and norm_title not in title_to_issue:
                    title_to_issue[norm_title] = identifier
        if not cursor:
            break

    if not group_key_to_issue and not cve_to_issue and not title_to_issue:
        return {"linked": 0, "fetched": fetched}

    # Fetch unarchived findings; match by group_key first (backend groups),
    # then CVE/title fallback. Bounded to the link scan limit so a 100k-row
    # findings table doesn't pin Beat in memory for the full tick.
    scan_limit = get_settings().linear_link_scan_limit
    stmt = (
        select(Finding)
        .where(Finding.archived == False)
        .order_by(Finding.id)
        .limit(scan_limit)
    )
    result = await db.execute(stmt)
    findings = list(result.scalars().all())
    push_min_severity = await get_tracker_push_min_severity(db)
    linked = 0
    for finding in findings:
        if use_aikido and _is_aikido_finding(finding):
            continue
        if has_tracker_link(finding, tracker_key):
            continue
        if not severity_meets_min(
            finding.severity.value if finding.severity else "", push_min_severity
        ):
            continue
        identifier = None
        gk = get_finding_group_key(finding)
        if gk:
            identifier = group_key_to_issue.get(gk)
        if not identifier and finding.cve_id:
            identifier = cve_to_issue.get(
                finding.cve_id.upper() if finding.cve_id else ""
            )
        if not identifier and finding.title:
            identifier = title_to_issue.get(
                LinearAdapter._normalize_title(finding.title)
            )
        if not identifier:
            continue
        issue_uuid = identifier_to_uuid.get(identifier) if identifier else None
        add_tracker_link(finding, tracker_key, identifier, issue_uuid=issue_uuid)
        # Preserve status — tracked is shown in a separate column, not as a status
        finding.sync_status = "synced"
        finding.sync_last_error = None
        finding.sync_failed_at = None
        audit = list(finding.audit or [])
        audit.append(
            {
                "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "user": "system",
                "action": "Linked to existing Linear issue",
                "note": identifier,
            }
        )
        finding.audit = audit
        # Enqueue update_issue to add labels and sync status (linked issues need VAT state applied)
        adapter_cls = TRACKER_ADAPTER_REGISTRY.get(tracker_key)
        if adapter_cls and adapter_cls().get_capabilities().supports_update_issue:
            from app.api.settings import get_labels, labels_to_configs

            labels_cfg = await get_labels(db)
            label_names = [l.get("name") for l in labels_cfg if l.get("name")]
            label_configs = labels_to_configs(labels_cfg)
            finding_dict = {
                "cveId": finding.cve_id,
                "cve_id": finding.cve_id,
                "title": finding.title,
                "severity": finding.severity.value if finding.severity else None,
                "status": finding.status.value if finding.status else None,
            }
            await enqueue_tracker_update_issue(
                db,
                finding,
                tracker_key,
                finding_dict,
                ["labels", "status"],
                label_names=label_names,
                label_configs=label_configs,
            )
        linked += 1

    if linked > 0:
        await db.commit()
        logger.info(
            "Linear link: linked %d findings to existing issues (fetched %d)",
            linked,
            fetched,
        )
    return {"linked": linked, "fetched": fetched}


async def backfill_tracker_corrections(db: AsyncSession, limit: int = 50) -> int:
    """
    Enqueue update_issue for linked findings to correct Linear issues to match VAT state.
    Pushes labels, title, severity so issues created before defaults (e.g. security-bug) get corrected.
    Skips findings that already have a pending update_issue. Returns count enqueued.
    When useAikidoTracking: Aikido findings are skipped — non-Aikido findings still get corrections.
    """
    from sqlalchemy import exists
    from app.api.settings import get_labels, get_tracker_key, get_use_aikido_tracking

    use_aikido = await get_use_aikido_tracking(db)
    tracker_key = await get_tracker_key(db)
    creds = await _credential_resolver.get_tracker_credentials(db, tracker_key)
    if not creds or not creds.get("api_key") or not creds.get("team_id"):
        return 0

    adapter_cls = TRACKER_ADAPTER_REGISTRY.get(tracker_key)
    if not adapter_cls or not adapter_cls().get_capabilities().supports_update_issue:
        return 0

    labels_cfg = await get_labels(db)
    label_names = [l.get("name") for l in labels_cfg if l.get("name")]
    label_configs = labels_to_configs(labels_cfg)

    # Skip if pending/processing OR ever completed (avoids re-enqueueing every run).
    # Re-correction only happens when the finding changes in VAT → normal update flow enqueues.
    pending_or_done = exists(
        select(1).where(
            SyncEvent.finding_id == Finding.id,
            SyncEvent.target == "tracker",
            SyncEvent.target_key == tracker_key,
            SyncEvent.event_type == "update_issue",
            or_(
                SyncEvent.status.in_(["pending", "processing"]),
                SyncEvent.status == "completed",
            ),
        )
    )
    needle = [{"kind": "tracker", "adapter_key": tracker_key}]
    base_conds = [
        Finding.external_links.op("@>")(type_coerce(needle, JSONB)),
        ~pending_or_done,
        Finding.archived == False,
    ]
    if use_aikido:
        base_conds.append(or_(Finding.source.is_(None), Finding.source != "Aikido"))
    stmt = (
        select(Finding)
        .where(and_(*base_conds))
        .order_by(Finding.updated_at.desc().nullslast())
        .limit(limit)
    )
    result = await db.execute(stmt)
    findings = list(result.scalars().all())
    if not findings:
        from sqlalchemy import func

        count_stmt = (
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.external_links.op("@>")(type_coerce(needle, JSONB)),
                Finding.archived == False,
            )
        )
        total_linked = (await db.execute(count_stmt)).scalar() or 0
        logger.debug(
            "Backfill corrections: 0 enqueued (total linked=%d; all have pending or completed update_issue)",
            total_linked,
        )
    enqueued = 0
    for finding in findings:
        finding_dict = {
            "cveId": finding.cve_id,
            "cve_id": finding.cve_id,
            "title": finding.title,
            "severity": finding.severity.value if finding.severity else None,
            "status": finding.status.value if finding.status else None,
        }
        changed = ["labels", "title", "severity", "status"]
        evt = await enqueue_tracker_update_issue(
            db,
            finding,
            tracker_key,
            finding_dict,
            changed,
            label_names=label_names,
            label_configs=label_configs,
        )
        if evt:
            enqueued += 1
    if enqueued > 0:
        await db.commit()
        logger.info(
            "Backfill corrections: enqueued update_issue for %d linked findings",
            enqueued,
        )
    return enqueued


async def get_sync_status(db: AsyncSession) -> dict:
    """
    Diagnostic counts for sync status. Use to understand how many groups/findings
    should be synced and what's pending.
    """
    from app.api.settings import (
        get_tracker_key,
        get_tracker_push_min_severity,
        get_tracker_push_mode,
        severity_meets_min,
    )
    from app.services.grouping import get_finding_group_key

    tracker_key = await get_tracker_key(db)
    creds = await _credential_resolver.get_tracker_credentials(db, tracker_key)
    tracker_configured = bool(creds.get("api_key") and creds.get("team_id"))

    open_statuses = [
        Status.Open,
        Status.SyncedToTracker,
        Status.InReview,
        Status.Rejected,
        Status.Mitigated,
        Status.Reopened,
    ]
    total_open = (
        await db.execute(
            select(func.count(Finding.id)).where(
                Finding.status.in_(open_statuses),
                Finding.archived == False,
            )
        )
    ).scalar() or 0

    push_min_severity = await get_tracker_push_min_severity(db)
    push_mode = await get_tracker_push_mode(db)

    # Unlinked findings (no tracker link)
    from sqlalchemy import bindparam, text

    open_status_values = tuple(s.value for s in open_statuses)
    unlinked_stmt = text("""
        SELECT f.id FROM findings f
        WHERE f.status IN :open_statuses AND f.archived = false
          AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(COALESCE(f.external_links, '[]'::jsonb)) AS elem
            WHERE elem->>'kind' = 'tracker' AND elem->>'adapter_key' = :tk
          )
    """).bindparams(bindparam("open_statuses", expanding=True))
    unlinked_result = await db.execute(
        unlinked_stmt,
        {"tk": tracker_key, "open_statuses": open_status_values},
    )
    unlinked_ids = [r[0] for r in unlinked_result.fetchall()]

    unlinked_meeting_severity = 0
    unique_groups = set()
    if unlinked_ids:
        result = await db.execute(select(Finding).where(Finding.id.in_(unlinked_ids)))
        findings = list(result.scalars().unique().all())
        for f in findings:
            if severity_meets_min(
                f.severity.value if f.severity else "", push_min_severity
            ):
                unlinked_meeting_severity += 1
                if push_mode == "groups":
                    unique_groups.add(get_finding_group_key(f))

    # Pending create_issue events
    pending_create = (
        await db.execute(
            select(func.count(SyncEvent.id)).where(
                SyncEvent.target == "tracker",
                SyncEvent.event_type == "create_issue",
                SyncEvent.status.in_(["pending", "processing"]),
            )
        )
    ).scalar() or 0

    return {
        "tracker_configured": tracker_configured,
        "push_mode": push_mode,
        "push_min_severity": push_min_severity or "all",
        "total_open": total_open,
        "unlinked": len(unlinked_ids),
        "unlinked_meeting_severity": unlinked_meeting_severity,
        "unique_groups_to_create": len(unique_groups)
        if push_mode == "groups"
        else unlinked_meeting_severity,
        "pending_create_issue": pending_create,
    }


async def backfill_unsynced_findings(db: AsyncSession, limit: int = 20) -> int:
    """
    Enqueue create_issue for findings that have no tracker link (e.g. bootstrap before tracker setup).
    First links findings to existing Linear issues (pull from Linear). Only creates new issues for
    findings that remain unlinked. Skips findings that already have a pending create_issue.
    Returns count of findings enqueued.
    """
    from sqlalchemy import text
    from app.api.settings import (
        get_labels,
        get_tracker_issue_template,
        get_tracker_key,
        get_tracker_push_min_severity,
        get_tracker_push_mode,
        get_use_aikido_tracking,
        severity_meets_min,
    )
    from app.services.grouping import get_finding_group_key

    use_aikido = await get_use_aikido_tracking(db)
    tracker_key = await get_tracker_key(db)
    creds = await _credential_resolver.get_tracker_credentials(db, tracker_key)
    if not creds.get("api_key") or not creds.get("team_id"):
        logger.debug("Backfill skipped: tracker not configured")
        return 0

    # Link findings to existing Linear issues only when pushMode=groups and we have unlinked findings
    push_mode = await get_tracker_push_mode(db)
    aikido_filter = (
        "\n          AND (f.source IS NULL OR f.source != 'Aikido')"
        if use_aikido
        else ""
    )
    if push_mode == "groups":
        unlinked_check = await db.execute(
            text(
                """
                SELECT 1 FROM findings f
                WHERE f.status IN ('Open', 'Reopened', 'InReview') AND f.archived = false
                  AND NOT EXISTS (
                    SELECT 1 FROM jsonb_array_elements(COALESCE(f.external_links, '[]'::jsonb)) AS elem
                    WHERE elem->>'kind' = 'tracker' AND elem->>'adapter_key' = :tk
                  )
                  """
                + aikido_filter
                + """
                LIMIT 1
            """
            ),
            {"tk": tracker_key},
        )
        if unlinked_check.scalar():
            await link_linear_issues_to_findings(db, max_issues=500)
    template = await get_tracker_issue_template(db)
    labels_cfg = await get_labels(db)
    label_names = [l.get("name") for l in labels_cfg if l.get("name")]
    label_configs = labels_to_configs(labels_cfg)

    # Find Open/Reopened/InReview findings with no tracker link and no pending create_issue.
    # Must filter by unlinked in SQL so we use the limit on actual candidates (not findings that
    # already have links).
    unlinked_stmt = text(
        """
        SELECT f.id FROM findings f
        WHERE f.status IN ('Open', 'Reopened', 'InReview') AND f.archived = false
          AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(COALESCE(f.external_links, '[]'::jsonb)) AS elem
            WHERE elem->>'kind' = 'tracker' AND elem->>'adapter_key' = :tk
          )
          AND NOT EXISTS (
            SELECT 1 FROM sync_events e
            WHERE e.finding_id = f.id AND e.target = 'tracker'
              AND e.event_type = 'create_issue' AND e.status IN ('pending', 'processing')
          )
          """
        + aikido_filter
        + """
        ORDER BY f.created_at
        LIMIT :lim
    """
    )
    ids_result = await db.execute(unlinked_stmt, {"tk": tracker_key, "lim": limit})
    ids = [r[0] for r in ids_result.fetchall()]
    if not ids:
        logger.debug(
            "Backfill: 0 enqueued (all unlinked findings have pending create_issue; queue draining)"
        )
        return 0
    result = await db.execute(select(Finding).where(Finding.id.in_(ids)))
    findings = list(result.scalars().unique().all())
    findings.sort(
        key=lambda f: f.created_at or datetime(1970, 1, 1, tzinfo=timezone.utc)
    )
    push_min_severity = await get_tracker_push_min_severity(db)
    enqueued = 0
    for finding in findings:
        if has_tracker_link(finding, tracker_key):
            continue
        if not severity_meets_min(
            finding.severity.value if finding.severity else "", push_min_severity
        ):
            continue
        finding_dict = {
            "cveId": finding.cve_id,
            "cve_id": finding.cve_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "component": finding.component,
            "image": finding.image,
            "findingType": finding.finding_type.value,
            "description": finding.description,
            "finding_id": finding.id,
            "file_path": finding.file_path,
            "line": finding.line,
            "source_file_url": finding.source_file_url,
            "source_issue_url": get_source_issue_url(finding),
        }
        if push_mode == "groups":
            finding_dict["group_key"] = get_finding_group_key(finding)
        await enqueue_tracker_create_issue(
            db,
            finding,
            tracker_key,
            finding_dict,
            template,
            label_names=label_names,
            label_configs=label_configs,
        )
        finding.sync_status = "pending_sync"
        enqueued += 1
    if enqueued > 0:
        await db.commit()
        logger.info(
            "Backfill: enqueued create_issue for %d unsynced findings", enqueued
        )
    return enqueued


async def sync_single_finding_to_tracker(db: AsyncSession, finding_id: str) -> dict:
    """
    Enqueue create_issue or update_issue for a single finding.
    When already linked: enqueues update_issue to push VAT state (labels, title, severity) to tracker
    — idempotent so tracker reflects VAT regardless of edits in tracker or closed status.
    Returns {enqueued: bool, message: str}.
    """
    from app.api.settings import (
        get_labels,
        get_tracker_issue_template,
        get_tracker_key,
        get_tracker_push_min_severity,
        get_tracker_push_mode,
        get_use_aikido_tracking,
        labels_to_configs,
        severity_meets_min,
    )
    from app.services.grouping import get_finding_group_key

    tracker_key = await get_tracker_key(db)
    creds = await _credential_resolver.get_tracker_credentials(db, tracker_key)
    if not creds.get("api_key") or not creds.get("team_id"):
        return {
            "enqueued": False,
            "message": "Linear not configured (API key and Team ID required)",
        }

    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        return {"enqueued": False, "message": "Finding not found"}
    if finding.archived:
        return {"enqueued": False, "message": "Finding is archived"}
    if await get_use_aikido_tracking(db) and _is_aikido_finding(finding):
        return {
            "enqueued": False,
            "message": "Aikido findings use Aikido's Linear integration; sync from Aikido instead",
        }

    adapter_cls = TRACKER_ADAPTER_REGISTRY.get(tracker_key)
    supports_update = (
        adapter_cls and adapter_cls().get_capabilities().supports_update_issue
    )

    if has_tracker_link(finding, tracker_key):
        # Already linked: enqueue update_issue to push VAT state (idempotent sync)
        if not supports_update:
            issue_id = get_tracker_issue_id(finding, tracker_key)
            return {
                "enqueued": False,
                "message": f"Finding already synced to {issue_id} (adapter does not support update)",
            }

        pending = await db.execute(
            select(1).where(
                SyncEvent.finding_id == finding_id,
                SyncEvent.target == "tracker",
                SyncEvent.event_type == "update_issue",
                SyncEvent.status.in_(["pending", "processing"]),
            )
        )
        if pending.scalar_one_or_none():
            return {
                "enqueued": False,
                "message": "Update already pending for this finding",
            }

        labels_cfg = await get_labels(db)
        label_names = [l.get("name") for l in labels_cfg if l.get("name")]
        label_configs = labels_to_configs(labels_cfg)
        finding_dict = {
            "cveId": finding.cve_id,
            "cve_id": finding.cve_id,
            "title": finding.title,
            "severity": finding.severity.value if finding.severity else None,
            "status": finding.status.value if finding.status else None,
        }
        evt = await enqueue_tracker_update_issue(
            db,
            finding,
            tracker_key,
            finding_dict,
            ["labels", "title", "severity"],
            label_names=label_names,
            label_configs=label_configs,
        )
        if evt:
            await db.commit()
            trigger_sync_worker(countdown=1)
            logger.info(
                "Single sync: enqueued update_issue for finding %s (already linked)",
                finding_id,
            )
            return {
                "enqueued": True,
                "message": f"Enqueued update to push VAT state to tracker for {finding.cve_id}.",
            }
        return {"enqueued": False, "message": "Could not enqueue update"}

    # Not linked: create new issue (only for Open/Reopened)
    if finding.status not in (Status.Open, Status.Reopened):
        return {
            "enqueued": False,
            "message": f"Finding status must be Open or Reopened to create tracker issue (current: {finding.status.value})",
        }

    push_min_severity = await get_tracker_push_min_severity(db)
    if not severity_meets_min(
        finding.severity.value if finding.severity else "", push_min_severity
    ):
        return {
            "enqueued": False,
            "message": f"Finding severity {finding.severity.value} is below push threshold (push Min Severity in Linear settings)",
        }

    pending = await db.execute(
        select(1).where(
            SyncEvent.finding_id == finding_id,
            SyncEvent.target == "tracker",
            SyncEvent.event_type == "create_issue",
            SyncEvent.status.in_(["pending", "processing"]),
        )
    )
    if pending.scalar_one_or_none():
        return {"enqueued": False, "message": "Sync already pending for this finding"}

    template = await get_tracker_issue_template(db)
    labels_cfg = await get_labels(db)
    label_names = [l.get("name") for l in labels_cfg if l.get("name")]
    label_configs = labels_to_configs(labels_cfg)

    finding_dict = {
        "cveId": finding.cve_id,
        "cve_id": finding.cve_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "component": finding.component,
        "image": finding.image,
        "findingType": finding.finding_type.value,
        "description": finding.description,
        "finding_id": finding.id,
        "file_path": finding.file_path,
        "line": finding.line,
        "source_file_url": finding.source_file_url,
        "source_issue_url": get_source_issue_url(finding),
    }
    push_mode = await get_tracker_push_mode(db)
    if push_mode == "groups":
        finding_dict["group_key"] = get_finding_group_key(finding)
    await enqueue_tracker_create_issue(
        db,
        finding,
        tracker_key,
        finding_dict,
        template,
        label_names=label_names,
        label_configs=label_configs,
    )
    finding.sync_status = "pending_sync"
    await db.commit()
    logger.info("Single sync: enqueued create_issue for finding %s", finding_id)
    return {
        "enqueued": True,
        "message": f"Enqueued. Linear issue will be created for {finding.cve_id}.",
    }
