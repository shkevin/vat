"""Waiver expiry enforcement — auto-reopen Risk Accepted findings when attestation expires.
Per PRD §5.5.2: On application load, VAT must scan all Risk Accepted findings and
auto-reopen any where attestation.expiresAt is in the past."""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session
from app.models.finding import Finding, Status


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def enforce_waiver_expiry() -> int:
    """
    Scan Risk Accepted findings with expired attestation.expiresAt,
    set status to Open, add audit entry. Returns count reopened.
    """
    count = 0
    async with async_session() as db:
        result = await db.execute(
            select(Finding).where(
                Finding.status == Status.RiskAccepted,
                Finding.attestation.isnot(None),
            )
        )
        findings = list(result.scalars().all())
        today = datetime.now(timezone.utc).date().isoformat()

        for f in findings:
            expires_at = (f.attestation or {}).get("expiresAt")
            if not expires_at:
                continue
            # expiresAt can be "2025-06-01" or "2025-06-01T00:00:00Z"
            exp_date = expires_at[:10] if isinstance(expires_at, str) else str(expires_at)[:10]
            if exp_date < today:
                f.status = Status.Open
                audit = list(f.audit or [])
                waiver_ref = (f.attestation or {}).get("waiverRef", "")
                audit.append({
                    "ts": _now(),
                    "user": "system",
                    "action": "Waiver expired — auto-reopened",
                    "note": f"Waiver {waiver_ref} expired {expires_at}",
                })
                f.audit = audit
                count += 1

        if count > 0:
            await db.commit()
    return count
