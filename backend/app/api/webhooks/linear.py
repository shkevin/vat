"""Linear webhook handler. PRD §5.9, §8.4. Comment.create for [VAT] blocks; Issue.update for watched label inject, description parse, and template re-injection."""

import json
from typing import Optional

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.linear import LinearAdapter
from app.api.settings import get_linear_credentials
from app.api.webhooks.common import verify_hmac, verify_replay_timestamp
from app.core.database import async_session, get_db
from app.services.linear_parsed_service import (
    apply_vat_parsed_update,
    post_canonical_if_enabled,
)
from app.services.tracker_issue_closed import handle_tracker_issue_closed_without_vat
from app.services.watched_label_inject import (
    handle_issue_label_update,
    handle_template_reinject,
)
from app.services.webhook_idempotency import (
    compute_idempotency_key,
    is_duplicate_webhook,
    record_webhook_processed,
)

router = APIRouter()

# Linear sends Linear-Signature; X-VAT-Signature supported for legacy
SIGNATURE_HEADERS = ["Linear-Signature", "linear-signature", "X-VAT-Signature"]


def _configured(api_key: Optional[str], team_id: Optional[str]) -> bool:
    """True if Linear integration is configured."""
    return bool(api_key and team_id)


@router.post("")
async def linear_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    """Receive Linear webhooks: Comment.create for [VAT] blocks; Issue.update for watched label inject and description parse."""
    api_key, team_id, webhook_secret = await get_linear_credentials(db)
    if not _configured(api_key, team_id):
        return Response(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content="Linear not configured",
        )
    body = await request.body()
    sig = None
    for h in SIGNATURE_HEADERS:
        sig = request.headers.get(h)
        if sig:
            break
    if webhook_secret and not verify_hmac(webhook_secret, body, sig):
        return Response(
            status_code=status.HTTP_401_UNAUTHORIZED, content="Invalid signature"
        )
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return Response(status_code=status.HTTP_400_BAD_REQUEST, content="Invalid JSON")
    # Replay protection: reject webhooks older than 5 min (Linear guide recommends 60s–5min)
    if not verify_replay_timestamp(request, data, max_age_sec=300):
        return Response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content="Replay: timestamp too old or invalid",
        )

    action = data.get("action") or data.get("type") or ""
    event_type = data.get("type") or ""
    data_body = data.get("data", data)
    updated_from = data.get("updatedFrom") or {}

    # Issue.update — watched label inject (PRD §5.9.4) and description parse (resilience to body edits)
    is_issue_update = event_type == "Issue" and action == "update"
    if is_issue_update:
        issue_obj = data_body.get("issue") or data_body
        issue_id = str(
            issue_obj.get("identifier")
            or issue_obj.get("id")
            or data_body.get("issueId")
            or ""
        )
        ts = data.get("createdAt", "") or data.get("webhookTimestamp", "")

        # 1. Watched label inject
        label_result = None
        if "labelIds" in updated_from or "labels" in updated_from:
            idempotency_key = compute_idempotency_key(
                "linear", "Issue.update.label", issue_id, ts
            )
            if not await is_duplicate_webhook(db, idempotency_key):
                async with async_session() as session:
                    label_result = await handle_issue_label_update(
                        session, data_body, updated_from
                    )
                    if label_result is not None:
                        await record_webhook_processed(
                            session,
                            idempotency_key,
                            "linear",
                            "Issue.update",
                            data,
                            label_result,
                        )

        # 2. Description parse — when issue body is edited with [VAT] block (e.g. AI/developer updates)
        desc_result = None
        reinject_result = None
        if "description" in updated_from:
            new_desc = str(issue_obj.get("description") or "")
            parsed = LinearAdapter.parse_vat_block_from_text(new_desc)
            if parsed:
                idempotency_key = compute_idempotency_key(
                    "linear", "Issue.update.description", issue_id, new_desc[:200] + ts
                )
                if not await is_duplicate_webhook(db, idempotency_key):
                    adapter = LinearAdapter(api_key=api_key, team_id=team_id)
                    async with async_session() as session:
                        desc_result = await apply_vat_parsed_update(
                            session,
                            parsed,
                            issue_id,
                            str(issue_obj.get("id") or ""),
                            idempotency_key,
                            "Issue.update.description",
                            data,
                        )
                    if desc_result.get("finding_id"):
                        await post_canonical_if_enabled(adapter, issue_id, parsed)
            else:
                # 3. Template re-injection — when template was removed or altered
                idempotency_key = compute_idempotency_key(
                    "linear", "Issue.update.reinject", issue_id, new_desc[:100] + ts
                )
                if not await is_duplicate_webhook(db, idempotency_key):
                    adapter = LinearAdapter(api_key=api_key, team_id=team_id)
                    async with async_session() as session:
                        reinject_result = await handle_template_reinject(
                            session, adapter, issue_obj, issue_id, new_desc
                        )
                        if reinject_result:
                            await record_webhook_processed(
                                session,
                                idempotency_key,
                                "linear",
                                "Issue.update.reinject",
                                data,
                                reinject_result,
                            )

        # 4. State change to closed/canceled — reopen if VAT finding not yet handled (prevent drift)
        reopen_result = None
        if "stateId" in updated_from or "state" in updated_from:
            state_obj = issue_obj.get("state") or {}
            new_state_id = issue_obj.get("stateId") or state_obj.get("id")
            if new_state_id:
                idempotency_key = compute_idempotency_key(
                    "linear", "Issue.update.state", issue_id, str(new_state_id) + ts
                )
                if not await is_duplicate_webhook(db, idempotency_key):
                    adapter = LinearAdapter(api_key=api_key, team_id=team_id)
                    async with async_session() as session:
                        reopen_result = await handle_tracker_issue_closed_without_vat(
                            session,
                            adapter,
                            issue_id,
                            str(issue_obj.get("id") or ""),
                            new_state_id,
                            api_key,
                            team_id,
                        )
                        await record_webhook_processed(
                            session,
                            idempotency_key,
                            "linear",
                            "Issue.update.state",
                            data,
                            {
                                "reopened": reopen_result.get("reopened"),
                                "finding_id": reopen_result.get("finding_id"),
                            },
                        )

        return {
            "received": True,
            "event": "Issue.update",
            "label_inject": label_result,
            "description_parsed": desc_result.get("parsed") if desc_result else None,
            "finding_id": desc_result.get("finding_id") if desc_result else None,
            "template_reinjected": reinject_result.get("reinjected")
            if reinject_result
            else None,
            "reopened": reopen_result.get("reopened") if reopen_result else None,
        }

    # Comment.create — parse [VAT] block and update finding
    action = action or "Comment.create"
    adapter = LinearAdapter(api_key=api_key, team_id=team_id)
    data_body = data.get("data", data)
    issue_obj = data_body.get("issue") or {}
    issue_body_hint = (
        str(issue_obj.get("description") or "")
        + " "
        + str(issue_obj.get("title") or "")
    )
    comment_update = adapter.to_vat_comment_update(
        data, issue_body_hint=issue_body_hint or None
    )
    if not comment_update:
        return {"received": True, "event": action, "parsed": False}

    cve_id = comment_update.cve_id
    issue_id = comment_update.tracker_issue_id
    issue_uuid = str(data_body.get("issueId") or issue_obj.get("id") or "")
    comment_id = comment_update.tracker_comment_id or ""
    comment_ts = data_body.get("createdAt") or data_body.get("created_at") or ""

    idempotency_key = compute_idempotency_key(
        "linear", action, comment_id or issue_id, comment_ts or issue_uuid
    )
    if await is_duplicate_webhook(db, idempotency_key):
        return {"received": True, "event": action, "parsed": True, "duplicate": True}

    parsed = {
        "cve_id": cve_id,
        "status": comment_update.status,
        "justification": comment_update.justification,
        "compensating_controls": comment_update.compensating_controls or "",
    }
    async with async_session() as session:
        result = await apply_vat_parsed_update(
            session, parsed, issue_id, issue_uuid, idempotency_key, action, data
        )
    if result.get("finding_id"):
        await post_canonical_if_enabled(adapter, issue_id, parsed)
    return result
