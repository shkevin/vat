"""Shared logic for applying parsed [VAT] blocks from Linear (webhook + API polling)."""

import logging
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.linear import LinearAdapter

logger = logging.getLogger(__name__)
from app.core.config import get_settings
from app.models.finding import Finding
from app.services.external_links_service import find_finding_by_linear_issue_id_or_uuid
from app.services.webhook_idempotency import record_webhook_processed


async def apply_vat_parsed_update(
    db: AsyncSession,
    parsed: dict,
    issue_id: str,
    issue_uuid: str,
    idempotency_key: str,
    event_name: str,
    data: dict | None = None,
) -> dict:
    """
    Find linked finding and apply VAT status update.
    Returns {"received": True, "event": ..., "parsed": True, "finding_id": ...} or {"finding": None}.
    data: optional payload for idempotency record (webhook payload or synthetic for polling).
    """
    data = data or {}
    cve_id = parsed["cve_id"]
    finding = await find_finding_by_linear_issue_id_or_uuid(
        db, issue_id or "", issue_uuid or None
    )
    if not finding:
        r = await db.execute(select(Finding).where(Finding.cve_id == cve_id).limit(1))
        finding = r.scalar_one_or_none()
    if not finding and cve_id and len(cve_id) <= 32:
        # Support [VAT] finding_id (e.g. f-trivy-1, SAST-2024-012) for unambiguous lookup
        r = await db.execute(select(Finding).where(Finding.id == cve_id).limit(1))
        finding = r.scalar_one_or_none()
    if not finding:
        logger.warning(
            "Linear→VAT: no finding found for %s (issue_id=%s, issue_uuid=%s, cve_id=%s)",
            event_name,
            issue_id,
            issue_uuid,
            cve_id,
        )
        await record_webhook_processed(db, idempotency_key, "linear", event_name, data)
        return {"received": True, "event": event_name, "parsed": True, "finding": None}

    from app.adapters.registry import TRACKER_ADAPTER_REGISTRY
    from app.services.findings_service import update_finding

    adapter_cls = TRACKER_ADAPTER_REGISTRY.get("linear")
    if not adapter_cls or not adapter_cls().get_capabilities().supports_inbound_sync:
        await record_webhook_processed(db, idempotency_key, "linear", event_name, data)
        return {
            "received": True,
            "event": event_name,
            "parsed": True,
            "skipped": "adapter does not support inbound sync",
        }

    await update_finding(
        db,
        finding.id,
        {
            "status": parsed["status"],
            "justification": parsed["justification"],
            "compensating_controls": parsed.get("compensating_controls") or "",
        },
    )
    await record_webhook_processed(
        db, idempotency_key, "linear", event_name, data, {"finding_id": finding.id}
    )
    return {
        "received": True,
        "event": event_name,
        "parsed": True,
        "finding_id": finding.id,
    }


async def post_canonical_if_enabled(
    adapter: LinearAdapter,
    issue_id: str,
    parsed: dict,
) -> None:
    """Post canonical [VAT] format to Linear when config enabled."""
    if not get_settings().linear_post_canonical_on_parse:
        return
    try:
        block = adapter.format_canonical_block(
            parsed["cve_id"],
            parsed["status"],
            parsed["justification"],
            parsed.get("compensating_controls") or "",
        )
        body = f"**VAT parsed your response.** Canonical format:\n\n{block}"
        from app.schemas.vat import VatTrackerPostDecisionRequest

        await adapter.post_comment(
            VatTrackerPostDecisionRequest(tracker_issue_id=issue_id, body=body)
        )
    except Exception:
        pass  # Non-fatal
