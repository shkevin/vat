"""Tracker notification — post reviewer decisions to Linear. PRD §5.9.2 step 5."""

import logging

from app.adapters.linear import LinearAdapter
from app.core.config import get_settings
from app.core.retry import retry_async
from app.models.finding import Finding, Status

logger = logging.getLogger(__name__)

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


async def notify_tracker_decision(
    finding: Finding,
    user: str = "security@co.com",
    *,
    db=None,
) -> bool:
    """
    Post reviewer decision to Linear issue when status is terminal.
    Returns True if posted, False if skipped or failed.
    db: AsyncSession for get_tracker_key. If None, uses 'linear' as default tracker.
    """
    if finding.status not in TRACKER_DECISION_STATUSES:
        return False
    from app.services.external_links_service import get_tracker_issue_id

    tracker_key = "linear"  # default
    if db is not None:
        from app.api.settings import get_tracker_key

        tracker_key = await get_tracker_key(db)
    issue_id = get_tracker_issue_id(finding, tracker_key)
    if not issue_id:
        return False
    if not get_settings().linear_api_key:
        return False

    status_display = finding.status.value.replace("_", " ").title()
    body_parts = [
        f"**VAT Reviewer Decision:** {status_display}",
        "",
        f"*Reviewed by {user}*",
    ]
    if finding.reviewer_note:
        body_parts.append("")
        body_parts.append(f"**Note:** {finding.reviewer_note}")
    if finding.justification:
        body_parts.append("")
        body_parts.append(f"**Justification:** {finding.justification[:500]}")
    if finding.attestation:
        att = finding.attestation
        body_parts.append("")
        body_parts.append(
            f"**Waiver:** {att.get('waiverRef', 'N/A')} | Expires: {att.get('expiresAt', 'N/A')}"
        )

    body = "\n".join(body_parts)

    try:
        linear = LinearAdapter()

        async def _post():
            await linear.post_comment(issue_id, body)

        await retry_async(_post, max_attempts=3, base_delay=1.0)
        logger.info("Posted decision to Linear %s for finding %s", issue_id, finding.id)
        return True
    except Exception as e:
        logger.warning("Failed to post decision to Linear after retries: %s", e)
        return False
