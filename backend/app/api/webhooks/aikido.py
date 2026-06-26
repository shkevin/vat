"""Aikido webhook handler. PRD §8.4."""

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.aikido import AikidoAdapter
from app.api.settings import get_aikido_credentials
from app.api.webhooks.common import verify_hmac, verify_replay_timestamp
from app.core.database import async_session, get_db
from app.models.finding import Finding, Status
from app.services.external_links_service import find_finding_by_external_id
from app.schemas.vat import VatFindingSchema
from app.services.aikido_full_sync import aikido_issue_trace_id
from app.core.tenancy import normalize_tenant_id
from app.services.ingest import ingest_finding
from app.services.webhook_idempotency import (
    compute_idempotency_key,
    claim_webhook,
    is_duplicate_webhook,
    record_webhook_processed,
)

router = APIRouter()
logger = logging.getLogger(__name__)

SIGNATURE_HEADER = "X-Aikido-Webhook-Signature"


def _get_nested(obj: dict, *keys: str, default=None):
    for k in keys:
        if isinstance(obj, dict) and k in obj:
            obj = obj[k]
        else:
            return default
    return obj


def _fallback_to_vat(data: dict) -> VatFindingSchema | None:
    """Build VatFindingSchema from raw Aikido webhook when adapter fails."""
    try:
        issue = data.get("issue") or data.get("payload", {}).get("issue") or data
        cve_id = str(
            _get_nested(issue, "cveId")
            or _get_nested(issue, "cve_id")
            or _get_nested(issue, "id")
            or "unknown"
        )
        comp = str(
            _get_nested(issue, "component")
            or _get_nested(issue, "package")
            or _get_nested(issue, "component_base")
            or ""
        )
        if comp and _get_nested(issue, "version"):
            comp = f"{comp} {_get_nested(issue, 'version')}"
        sev = str(
            _get_nested(issue, "severity")
            or _get_nested(issue, "criticality")
            or "medium"
        ).lower()
        raw_id = _get_nested(issue, "id") or _get_nested(issue, "issue_id")
        return VatFindingSchema(
            cve_id=cve_id,
            severity=sev,
            description=str(_get_nested(issue, "description") or ""),
            component=comp or None,
            title=str(
                _get_nested(issue, "title") or _get_nested(issue, "name") or cve_id
            ),
            source_issue_id=str(raw_id) if raw_id is not None else None,
        )
    except Exception:
        return None


def _configured(creds: dict) -> bool:
    """True if Aikido integration is configured (OAuth credentials present)."""
    return bool(creds.get("client_id") and creds.get("client_secret"))


@router.post("/{source_id}")
async def aikido_webhook_per_source(
    source_id: str, request: Request, db: AsyncSession = Depends(get_db)
):
    """Receive Aikido issue.created/.updated/.closed for ``source_id``.

    strict=True: refuses to fall back to global creds. A webhook signed
    by source Y's secret can no longer be HMAC-validated against source
    X's just because X has no per-source webhook_secret configured.
    Returns 503 (Aikido not configured) when per-source creds are
    missing — operator must configure the source explicitly first.
    """
    creds = await get_aikido_credentials(db, source_id, strict=True)
    return await _handle_aikido_webhook(request, db, creds, aikido_source_id=source_id)


@router.post("")
async def aikido_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    """Receive Aikido issue.created, issue.updated, issue.closed events. Legacy: uses global credentials."""
    creds = await get_aikido_credentials(db, None)
    return await _handle_aikido_webhook(request, db, creds, aikido_source_id=None)


async def _handle_aikido_webhook(
    request: Request,
    db: AsyncSession,
    creds: dict,
    *,
    aikido_source_id: str | None = None,
) -> Response | dict:
    if not _configured(creds):
        return Response(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content="Aikido not configured",
        )
    body = await request.body()
    sig = request.headers.get(SIGNATURE_HEADER)
    webhook_secret = creds.get("webhook_secret")
    if not webhook_secret:
        # Fail closed: configured Aikido source must have a webhook secret before
        # inbound deliveries can be trusted. Returning 503 (not 401) makes the
        # missing-config state visible to ops without leaking that "no secret"
        # would have been accepted before.
        logger.warning(
            "Aikido webhook rejected: webhook_secret not configured for source"
        )
        return Response(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content="Aikido webhook secret not configured",
        )
    if not verify_hmac(webhook_secret, body, sig):
        return Response(
            status_code=status.HTTP_401_UNAUTHORIZED, content="Invalid signature"
        )
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return Response(status_code=status.HTTP_400_BAD_REQUEST, content="Invalid JSON")
    if not verify_replay_timestamp(request, data, max_age_sec=30):
        return Response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content="Replay: timestamp too old or invalid",
        )
    event = data.get("event") or data.get("event_type") or "unknown"
    issue = data.get("issue") or data.get("payload", {}).get("issue") or data
    issue_id = str(_get_nested(issue, "id") or _get_nested(issue, "issue_id") or "")
    ts = (
        data.get("dispatched_at")
        or data.get("created_at")
        or data.get("timestamp")
        or ""
    )
    idempotency_key = compute_idempotency_key("aikido", event, issue_id, str(ts))
    # Fast-path duplicate filter; the authoritative claim happens inside the
    # side-effect session below so a rollback releases it.
    if await is_duplicate_webhook(db, idempotency_key):
        return {"received": True, "event": event, "duplicate": True}
    if not AikidoAdapter().get_capabilities().supports_inbound_sync:
        # No side effect; record completion best-effort (idempotent).
        await record_webhook_processed(db, idempotency_key, "aikido", event, data)
        await db.commit()
        return {
            "received": True,
            "event": event,
            "skipped": "adapter does not support inbound sync",
        }
    if event in ("issue.closed",):
        adapter = AikidoAdapter(credentials=creds)
        try:
            payload = await adapter.to_vat_finding(data)
            cve_id = payload.cve_id
            component = payload.component or payload.component_base or ""
            image = payload.image or ""
            branch = getattr(payload, "branch", None) or ""
            tag = getattr(payload, "tag", None) or ""
            source_issue_id = str(
                getattr(payload, "source_issue_id", None) or ""
            ).strip()
        except Exception as e:
            logger.warning("Aikido adapter ingest failed for issue.closed: %s", e)
            issue = data.get("issue") or data.get("payload", {}).get("issue") or data
            cve_id = str(
                issue.get("cveId")
                or issue.get("cve_id")
                or issue.get("id")
                or "unknown"
            )
            component = str(
                issue.get("component")
                or issue.get("package")
                or issue.get("component_base")
                or ""
            )
            image = ""
            branch = ""
            tag = ""
            source_issue_id = str(
                issue.get("id") or issue.get("issue_id") or ""
            ).strip()
        async with async_session() as session:
            # Atomic claim — if another delivery beat us between the fast-path
            # check above and now, this returns False and we abort without
            # double-applying the side effect.
            if not await claim_webhook(
                session, idempotency_key, "aikido", event, data
            ):
                await session.rollback()
                return {"received": True, "event": event, "duplicate": True}

            from app.services.dedup import make_fingerprint

            existing = None
            if source_issue_id:
                existing = await find_finding_by_external_id(
                    session, "Aikido", source_issue_id
                )
            if not existing:
                fp = make_fingerprint(
                    cve_id, component, image=image, branch=branch, tag=tag
                )
                result = await session.execute(
                    select(Finding).where(Finding.fingerprint_id == fp)
                )
                existing = result.scalar_one_or_none()
            if existing:
                existing.status = Status.Resolved
                if aikido_source_id and not existing.aikido_source_id:
                    existing.aikido_source_id = aikido_source_id
                audit = list(existing.audit or [])
                audit.append(
                    {
                        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "user": "system",
                        "action": "Closed via Aikido issue.closed",
                        "note": f"Aikido reported issue closed for {cve_id}",
                    }
                )
                existing.audit = audit
                await session.commit()
                return {
                    "received": True,
                    "event": event,
                    "finding_id": existing.id,
                    "status": "Resolved",
                }
            await session.commit()
            return {"received": True, "event": event, "finding_id": None}

    adapter = AikidoAdapter(credentials=creds)
    try:
        payload = await adapter.to_vat_finding(data)
    except Exception as e:
        logger.warning("Aikido adapter to_vat_finding failed: %s", e)
        payload = _fallback_to_vat(data)
        if not payload:
            raise

    issue_for_trace = data.get("issue") if isinstance(data.get("issue"), dict) else data
    trace_id = aikido_issue_trace_id(aikido_source_id, issue_for_trace or data)

    # M16: stamp tenant_id from per-source creds; always default to t-default
    # so ingested findings stay visible in the single-tenant deployment.
    creds_tenant_id = normalize_tenant_id(
        creds.get("tenant_id") if isinstance(creds, dict) else None
    )

    async with async_session() as session:
        if not await claim_webhook(
            session, idempotency_key, "aikido", event, data
        ):
            await session.rollback()
            return {"received": True, "event": event, "duplicate": True}
        finding, created = await ingest_finding(
            session,
            payload,
            source_name="Aikido",
            tenant_id=creds_tenant_id,
            aikido_source_id=aikido_source_id,
            trace_id=trace_id,
            parser_id="aikido",
        )
        await session.refresh(finding)
        await session.commit()

    return {
        "received": True,
        "event": event,
        "finding_id": finding.id,
        "created": created,
    }
