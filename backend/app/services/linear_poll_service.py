"""Linear API polling — use when webhooks aren't configured. Uses same credentials as Linear integration settings."""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.linear import LinearAdapter
from app.api.settings import get_linear_credentials
from app.core.config import get_settings
from app.services.external_links_service import get_all_linear_tracker_issue_ids
from app.services.linear_parsed_service import (
    apply_vat_parsed_update,
    post_canonical_if_enabled,
)
from app.services.webhook_idempotency import (
    compute_idempotency_key,
    is_duplicate_webhook,
)

logger = logging.getLogger(__name__)


async def poll_linear_for_updates(db: AsyncSession, *, force: bool = False) -> dict:
    """
    Poll Linear API for issue/comment updates and apply [VAT] parsed blocks.
    Only fetches issues that are linked to VAT findings (tracked in VAT).
    Uses same idempotency as webhooks so webhook + poll don't double-apply.
    Returns {issues_fetched, comments_processed, descriptions_processed, errors}.
    When force=True (e.g. manual sync), runs regardless of VAT_LINEAR_POLL_ENABLED.
    """
    settings = get_settings()
    # Same credentials as Linear integration settings (API key, team ID, webhook secret)
    api_key, team_id, webhook_secret = await get_linear_credentials(db)

    # When webhooks configured: don't poll unless force (manual sync or reconciliation)
    if not force and webhook_secret:
        logger.debug(
            "Linear poll skipped: webhook configured (use reconciliation for safety net)"
        )
        return {
            "issues_fetched": 0,
            "comments_processed": 0,
            "descriptions_processed": 0,
            "errors": [],
        }
    if not force and not settings.linear_poll_enabled:
        return {
            "issues_fetched": 0,
            "comments_processed": 0,
            "descriptions_processed": 0,
            "errors": [],
        }
    if not api_key or not team_id:
        logger.debug("Linear poll skipped: not configured")
        return {
            "issues_fetched": 0,
            "comments_processed": 0,
            "descriptions_processed": 0,
            "errors": [],
        }

    # Only poll issues that VAT tracks — no fetching of unrelated team issues
    tracked = await get_all_linear_tracker_issue_ids(db)
    if not tracked:
        logger.debug("Linear poll skipped: no VAT-tracked Linear issues")
        return {
            "issues_fetched": 0,
            "comments_processed": 0,
            "descriptions_processed": 0,
            "errors": [],
        }

    adapter = LinearAdapter(api_key=api_key, team_id=team_id)
    comments_processed = 0
    descriptions_processed = 0
    fetched = 0
    errors: list[str] = []

    # Prefer UUIDs for efficient batch fetch (id: { in: [...] })
    uuids = [uuid for _, uuid in tracked if uuid]
    identifiers_without_uuid = [issue_id for issue_id, uuid in tracked if not uuid]

    try:
        nodes: list[dict] = []
        if uuids:
            nodes = await adapter.list_issues_by_ids(
                uuids,
                include_comments=True,
                comments_per_issue=50,
            )
        # Fallback: fetch by identifier for legacy links without stored UUID (one query per issue)
        for issue_id in identifiers_without_uuid:
            issue_data = await adapter.get_issue_with_comments(issue_id, first=50)
            if issue_data:
                nodes.append(issue_data)

        fetched = len(nodes)

        for issue in nodes:
            issue_id = str(issue.get("identifier") or issue.get("id") or "")
            issue_uuid = str(issue.get("id") or "")
            title = issue.get("title") or ""
            description = str(issue.get("description") or "")
            issue_body_hint = f"{title} {description}"

            # 1. Parse issue description
            parsed_desc = LinearAdapter.parse_vat_block_from_text(
                description, cve_id_hint=None
            )
            if parsed_desc:
                idempotency_key = compute_idempotency_key(
                    "linear", "Issue.update.description", issue_id, description[:200]
                )
                if not await is_duplicate_webhook(db, idempotency_key):
                    data = {
                        "source": "poll",
                        "issue_id": issue_id,
                        "type": "description",
                    }
                    result = await apply_vat_parsed_update(
                        db,
                        parsed_desc,
                        issue_id,
                        issue_uuid,
                        idempotency_key,
                        "Issue.update.description",
                        data,
                    )
                    if result.get("finding_id"):
                        descriptions_processed += 1
                        await post_canonical_if_enabled(adapter, issue_id, parsed_desc)
                await db.commit()

            # 2. Parse each comment
            comments_data = issue.get("comments") or {}
            comment_nodes = comments_data.get("nodes") or []
            for comment in comment_nodes:
                comment_id = str(comment.get("id") or "")
                body = str(comment.get("body") or "")
                created_at = str(comment.get("createdAt") or "")

                payload = {
                    "data": {
                        "body": body,
                        "id": comment_id,
                        "createdAt": created_at,
                        "issue": {
                            "identifier": issue_id,
                            "id": issue_uuid,
                            "title": title,
                            "description": description,
                        },
                    }
                }
                comment_update = adapter.to_vat_comment_update(
                    payload, issue_body_hint=issue_body_hint
                )
                if not comment_update:
                    continue

                idempotency_key = compute_idempotency_key(
                    "linear",
                    "Comment.create",
                    comment_id or issue_id,
                    created_at or issue_uuid,
                )
                if await is_duplicate_webhook(db, idempotency_key):
                    continue

                parsed = {
                    "cve_id": comment_update.cve_id,
                    "status": comment_update.status,
                    "justification": comment_update.justification,
                    "compensating_controls": comment_update.compensating_controls or "",
                }
                data = {
                    "source": "poll",
                    "issue_id": issue_id,
                    "comment_id": comment_id,
                }
                result = await apply_vat_parsed_update(
                    db,
                    parsed,
                    issue_id,
                    issue_uuid,
                    idempotency_key,
                    "Comment.create",
                    data,
                )
                if result.get("finding_id"):
                    comments_processed += 1
                    await post_canonical_if_enabled(adapter, issue_id, parsed)
                await db.commit()

        logger.info(
            "Linear poll: fetched %d issues, processed %d comments, %d descriptions",
            fetched,
            comments_processed,
            descriptions_processed,
        )
    except Exception as e:
        logger.exception("Linear poll failed: %s", e)
        errors.append(str(e))

    return {
        "issues_fetched": fetched,
        "comments_processed": comments_processed,
        "descriptions_processed": descriptions_processed,
        "errors": errors,
    }
