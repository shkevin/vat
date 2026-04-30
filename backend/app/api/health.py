"""Health check endpoints.

- ``GET /health`` (legacy + ``/health/live``): cheap process-liveness ping.
  Returns 200 unless the ASGI app itself is broken.
- ``GET /health/ready``: kubernetes readiness gate. Hits Postgres
  (``SELECT 1``) and the Celery broker (Redis/Valkey ``PING``). Returns 503
  with a per-component breakdown when any dependency is down so a node can
  be drained from the LB.

The k8s liveness probe should target ``/health/live``; readiness should
target ``/health/ready``. Keeping the legacy unprefixed handler returning
200 avoids breaking any deploy manifests that already point at it.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app.core.config import get_settings
from app.core.database import async_session

logger = logging.getLogger(__name__)
router = APIRouter()

# Dependency probes are short — readiness should fail fast rather than block
# the probe past the kubelet timeout.
PROBE_TIMEOUT_SECONDS = 2.0


@router.get("")
async def health() -> dict[str, str]:
    """Process-liveness — succeeds whenever the ASGI app is up."""
    return {"status": "ok", "service": "vat"}


@router.get("/live")
async def health_live() -> dict[str, str]:
    """Explicit liveness probe target. Same semantics as the legacy /health."""
    return {"status": "ok", "service": "vat"}


async def _check_db() -> tuple[bool, str | None]:
    try:
        async with async_session() as session:
            await asyncio.wait_for(
                session.execute(text("SELECT 1")), timeout=PROBE_TIMEOUT_SECONDS
            )
        return True, None
    except Exception as e:
        logger.warning("readiness: db check failed: %s", e)
        return False, type(e).__name__


async def _check_broker() -> tuple[bool, str | None]:
    """Ping the Celery broker (redis/valkey). Skipped when the broker URL is
    not redis-compatible (e.g. amqp://) — the Kombu probe is heavier and we
    don't want to add a dependency just for the health endpoint."""
    url = get_settings().celery_broker_url or ""
    if not url.startswith(("redis://", "rediss://")):
        return True, "skipped"
    try:
        # redis-py is already a transitive dep via celery; import lazily so
        # the probe doesn't pay the cost on every /health/live hit.
        import redis.asyncio as aioredis  # type: ignore[import-not-found]

        client = aioredis.from_url(url, socket_timeout=PROBE_TIMEOUT_SECONDS)
        try:
            await asyncio.wait_for(client.ping(), timeout=PROBE_TIMEOUT_SECONDS)
        finally:
            await client.aclose()
        return True, None
    except Exception as e:
        logger.warning("readiness: broker check failed: %s", e)
        return False, type(e).__name__


@router.get("/ready")
async def health_ready(response: Response) -> dict[str, Any]:
    """Readiness gate. 503 when any required dependency is unreachable."""
    db_ok, db_err = await _check_db()
    broker_ok, broker_err = await _check_broker()
    overall = db_ok and broker_ok
    if not overall:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ok" if overall else "degraded",
        "checks": {
            "db": {"ok": db_ok, "error": db_err},
            "broker": {"ok": broker_ok, "error": broker_err},
        },
    }
