"""Lightweight Redis-backed lockout counters for auth endpoints.

Used to throttle brute-force attempts on credential-exchange surfaces
(currently /api/auth/oauth/token; future: /api/auth/login). Backing
store is the Celery broker — already deployed, already redis-compatible,
and Beat workers already share it. Falls back to no-op when the broker
is unreachable or not redis (production with rabbitmq, local stubs in
tests) so an outage in the rate-limit store can never block a legitimate
sign-in.

Algorithm: sliding-fixed-window counter via INCR + EXPIRE. After the
configured ``threshold`` failures within ``window_seconds``, the key is
considered locked until the window expires. ``record_failure`` returns
the current count so the caller can decide between "still failing" and
"now locked".
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT_SECONDS = 1.0


async def _client() -> Optional[object]:
    """Return a redis.asyncio client when the broker is redis, else None.

    Lazy-imported and lazy-connected so the rest of the app never pays
    the cost when this module isn't used. Errors are swallowed and the
    caller treats it as "no rate limit available".
    """
    url = get_settings().celery_broker_url or ""
    if not url.startswith(("redis://", "rediss://")):
        return None
    try:
        import redis.asyncio as aioredis  # type: ignore[import-not-found]

        return aioredis.from_url(url, socket_timeout=_PROBE_TIMEOUT_SECONDS)
    except Exception as e:
        logger.debug("rate_limit: redis client init failed: %s", e)
        return None


async def is_locked(key: str, threshold: int) -> bool:
    """True when the failure counter for ``key`` is already at/above
    ``threshold``. Returns False on store failure (fail-open by design —
    a Redis outage cannot block legitimate auth)."""
    client = await _client()
    if client is None:
        return False
    try:
        val = await asyncio.wait_for(client.get(key), timeout=_PROBE_TIMEOUT_SECONDS)
        if val is None:
            return False
        try:
            return int(val) >= threshold
        except (TypeError, ValueError):
            return False
    except Exception as e:
        logger.debug("rate_limit: is_locked failed: %s", e)
        return False
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


async def record_failure(key: str, window_seconds: int) -> int:
    """Increment the failure counter for ``key``; set TTL on first hit so
    the lock auto-clears after ``window_seconds``. Returns the post-
    increment count, or 0 on store failure."""
    client = await _client()
    if client is None:
        return 0
    try:
        async with asyncio.timeout(_PROBE_TIMEOUT_SECONDS):
            count = await client.incr(key)
            if count == 1:
                await client.expire(key, window_seconds)
        return int(count)
    except Exception as e:
        logger.debug("rate_limit: record_failure failed: %s", e)
        return 0
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


async def reset(key: str) -> None:
    """Clear a key on success so a legitimate sign-in after some failures
    doesn't leave the bucket primed for the next user."""
    client = await _client()
    if client is None:
        return
    try:
        await asyncio.wait_for(client.delete(key), timeout=_PROBE_TIMEOUT_SECONDS)
    except Exception:
        pass
    finally:
        try:
            await client.aclose()
        except Exception:
            pass
