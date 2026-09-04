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
import time
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


# --- Cross-process request pacing -------------------------------------------
#
# The Aikido adapter paced itself with a module-global timestamp, which is
# per-process. Two backend replicas plus the celery workers each kept their own,
# so the real request rate against Aikido was several times the configured gap
# and the workspace sat in 429 — on /teams, and then on /issues/export during a
# sync. These give every process one shared schedule.

_GAP_TTL_MS = 300_000  # a stale key must not wedge the schedule forever
_MAX_WAIT_SECONDS = 120.0

# Atomic claim-the-next-slot. Returns ms to wait before the caller may proceed.
_GAP_LUA = """
local nxt = tonumber(redis.call('GET', KEYS[1]) or '0')
local now = tonumber(ARGV[1])
local gap = tonumber(ARGV[2])
local ttl = ARGV[3]
if now >= nxt then
  redis.call('PSETEX', KEYS[1], ttl, now + gap)
  return 0
end
redis.call('PSETEX', KEYS[1], ttl, nxt + gap)
return nxt - now
"""


async def acquire_gap_slot(key: str, gap_ms: int) -> Optional[float]:
    """Reserve the next slot on a shared schedule; return seconds to wait.

    Returns None when there is no Redis, so the caller can fall back to its own
    in-process pacing rather than losing rate limiting altogether.
    """
    client = await _client()
    if client is None:
        return None
    try:
        now_ms = time.time() * 1000.0
        wait_ms = await client.eval(
            _GAP_LUA, 1, f"ratelimit:gap:{key}", now_ms, gap_ms, _GAP_TTL_MS
        )
        return min(max(float(wait_ms) / 1000.0, 0.0), _MAX_WAIT_SECONDS)
    except Exception as e:
        logger.debug("rate_limit: gap slot failed for %s: %s", key, e)
        return None


async def note_upstream_backoff(key: str, retry_after_seconds: float) -> None:
    """Push the shared schedule out after a 429.

    Without this only the process that saw the 429 backs off while its siblings
    keep calling, so the limit never clears.
    """
    client = await _client()
    if client is None:
        return
    try:
        until_ms = (time.time() + max(retry_after_seconds, 0.0)) * 1000.0
        await client.eval(
            "local nxt = tonumber(redis.call('GET', KEYS[1]) or '0')\n"
            "if tonumber(ARGV[1]) > nxt then\n"
            "  redis.call('PSETEX', KEYS[1], ARGV[2], ARGV[1])\n"
            "end\n"
            "return 1",
            1,
            f"ratelimit:gap:{key}",
            until_ms,
            _GAP_TTL_MS,
        )
    except Exception as e:
        logger.debug("rate_limit: backoff note failed for %s: %s", key, e)
