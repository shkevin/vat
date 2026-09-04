"""Cached async clients must not outlive their event loop.

Celery runs every task under its own asyncio.run(), so a client cached across
tasks hands the next one sockets belonging to a closed loop. The sync failed
with:

    Task ... got Future <Future pending> attached to a different loop

which is that, from the module-level Aikido httpx client. The Redis client in
core.rate_limit had the mirror problem: a fresh client per call, leaking a
connection pool on every Aikido request once pacing started using it.
"""

import asyncio

from app.adapters import aikido as aikido_mod
from app.core import rate_limit as rl


def test_http_client_is_rebuilt_for_a_new_loop():
    seen = []

    async def task():
        seen.append(aikido_mod._aikido_client())

    # Two Celery tasks in the same worker process.
    asyncio.run(task())
    asyncio.run(task())

    assert len(seen) == 2
    assert seen[0] is not seen[1], (
        "same client reused across loops — its sockets belong to a dead loop"
    )


def test_http_client_is_reused_within_one_loop():
    async def task():
        return aikido_mod._aikido_client(), aikido_mod._aikido_client()

    a, b = asyncio.run(task())
    assert a is b, "rebuilding per call would drop connection pooling"


def test_redis_client_is_reused_within_one_loop(monkeypatch):
    """A fresh client per call leaked a pool on every paced request."""
    class _Fake:
        def __init__(self, url):
            self.url = url

    monkeypatch.setattr(
        rl, "get_settings", lambda: type("S", (), {"celery_broker_url": "redis://x:6379/0"})()
    )

    import sys
    import types

    fake = types.ModuleType("redis.asyncio")
    fake.from_url = lambda url, **kw: _Fake(url)
    monkeypatch.setitem(sys.modules, "redis.asyncio", fake)
    rl._redis_client = None
    rl._redis_loop = None

    async def task():
        return await rl._client(), await rl._client(), await rl._client()

    a, b, c = asyncio.run(task())
    # Identity is the guarantee; counting constructions is order-dependent
    # because other suites touch this module's cache.
    assert a is b is c, "a fresh client per call leaks a pool on every request"


def test_redis_client_is_rebuilt_for_a_new_loop(monkeypatch):
    """Across loops the cache must not be reused, or the pool is bound to a dead one."""

    class _Fake:
        def __init__(self, url):
            self.url = url

    monkeypatch.setattr(
        rl, "get_settings", lambda: type("S", (), {"celery_broker_url": "redis://x:6379/0"})()
    )

    import sys
    import types

    fake = types.ModuleType("redis.asyncio")
    fake.from_url = lambda url, **kw: _Fake(url)
    monkeypatch.setitem(sys.modules, "redis.asyncio", fake)

    async def task():
        c = await rl._client()
        return c, rl._redis_loop

    rl._redis_client = None
    rl._redis_loop = None
    c1, loop1 = asyncio.run(task())
    c2, loop2 = asyncio.run(task())

    assert c1 is not None and c2 is not None
    assert loop1 is not loop2, "cache key did not follow the loop"
    assert c1 is not c2, "client from a closed loop was reused"
