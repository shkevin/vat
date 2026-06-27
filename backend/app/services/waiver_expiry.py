"""Waiver expiry enforcement — ledger-first with finding fallback."""

from datetime import datetime, timezone

from sqlalchemy import select

from app.core.config import get_settings
from app.core.database import async_session
from app.models.finding import Finding, Status
from app.services.decision_ledger import _is_waiver_expired, expire_decision_waivers


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _enforce_waiver_expiry_on_findings(db) -> int:
    """Fallback for Risk Accepted findings not yet represented in the ledger."""
    result = await db.execute(
        select(Finding).where(
            Finding.status == Status.RiskAccepted,
            Finding.attestation.isnot(None),
        )
    )
    findings = list(result.scalars().all())
    today = datetime.now(timezone.utc).date().isoformat()
    count = 0

    for f in findings:
        expires_at = (f.attestation or {}).get("expiresAt")
        if not _is_waiver_expired(expires_at, today=today):
            continue
        f.status = Status.Open
        audit = list(f.audit or [])
        waiver_ref = (f.attestation or {}).get("waiverRef", "")
        audit.append(
            {
                "ts": _now(),
                "user": "system",
                "action": "Waiver expired — auto-reopened",
                "note": f"Waiver {waiver_ref} expired {expires_at}",
            }
        )
        f.audit = audit
        count += 1

    if count > 0:
        await db.commit()
    return count


async def enforce_waiver_expiry() -> int:
    """
    Expire waivers from the durable decision ledger first, then scan findings
    as a fallback for unmigrated rows.
    """
    count = 0
    async with async_session() as db:
        if get_settings().decision_ledger_enabled:
            count += await expire_decision_waivers(db)
        count += await _enforce_waiver_expiry_on_findings(db)
    return count
