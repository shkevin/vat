"""Handle tracker issue closed/canceled without proper [VAT] handling — reopen to prevent drift.

When a Linear issue is closed or canceled without a [VAT] block, the finding in VAT
remains open. We detect this and reopen the tracker issue so VAT stays source of truth.
"""

import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.linear import LinearAdapter
from app.models.finding import Finding, Status
from app.services.external_links_service import find_finding_by_external_id

logger = logging.getLogger(__name__)

# VAT statuses that mean the finding is "handled" — we allow tracker to stay closed
FINDING_TERMINAL_STATUSES = {
    Status.Approved,
    Status.Rejected,
    Status.RiskAccepted,
    Status.FalsePositive,
    Status.Suppressed,
    Status.NotApplicable,
    Status.Mitigated,
    Status.Duplicate,
    Status.Resolved,
}


async def handle_tracker_issue_closed_without_vat(
    db: AsyncSession,
    adapter: LinearAdapter,
    issue_id: str,
    issue_uuid: str,
    state_id: str,
    api_key: str,
    team_id: str,
) -> dict:
    """
    If a Linear issue was closed/canceled but the linked VAT finding is not terminal,
    reopen the Linear issue to prevent drift.

    Returns {"reopened": bool, "finding_id": str|None, "reason": str}.
    """
    if not await adapter.is_state_closed(state_id):
        return {"reopened": False, "finding_id": None, "reason": "state not closed"}

    finding = await find_finding_by_external_id(db, "linear", issue_id)
    if not finding:
        finding = await find_finding_by_external_id(db, "linear", issue_uuid)
    if not finding:
        return {"reopened": False, "finding_id": None, "reason": "no linked finding"}

    if finding.status in FINDING_TERMINAL_STATUSES:
        return {
            "reopened": False,
            "finding_id": finding.id,
            "reason": "finding already terminal",
        }

    reopened = await adapter.reopen_issue(issue_id, team_uuid=None)
    if reopened:
        return {
            "reopened": True,
            "finding_id": finding.id,
            "reason": "reopened to prevent drift",
        }
    return {
        "reopened": False,
        "finding_id": finding.id,
        "reason": "reopen failed",
    }
