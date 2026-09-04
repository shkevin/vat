"""Database session and engine configuration.

The engine is created per event loop rather than once at import.

A Celery worker runs every task under its own ``asyncio.run()``, so a module
level engine hands the second task asyncpg connections belonging to the first
task's now-closed loop, and the request fails with::

    Task ... got Future <Future pending cb=[BaseProtocol._on_waiter_completed()]>
    attached to a different loop

which is how the Aikido full sync failed. ``aikido_tasks`` already built its own
engine for that reason, but ``run_full_sync`` uses ``async_session`` directly, so
the global pool was still in play.

Under uvicorn the loop never changes, so the key never changes and this is the
old single-engine behaviour.
"""

import asyncio
from typing import Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings
from app.models.base import Base

settings = get_settings()

_engine: Optional[AsyncEngine] = None
_engine_loop: Optional[asyncio.AbstractEventLoop] = None
_session_factory: Optional[async_sessionmaker] = None


def _running_loop() -> Optional[asyncio.AbstractEventLoop]:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def get_engine() -> AsyncEngine:
    """Engine bound to the running loop, rebuilt when that loop changes."""
    global _engine, _engine_loop, _session_factory
    loop = _running_loop()
    if _engine is None or _engine_loop is not loop:
        # The previous engine is dropped, not disposed. dispose() is async and
        # needs the loop its connections belong to, which by definition has
        # gone; sync_engine.dispose() reaches the same asyncpg teardown and
        # raises MissingGreenlet. Those sockets died with their loop, so
        # releasing the reference and letting GC finish is the honest option.
        _engine = create_async_engine(
            settings.database_url,
            echo="debug"
            if settings.database_url.startswith("postgresql+asyncpg://vat:vat@localhost")
            else False,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_timeout=settings.db_pool_timeout_sec,
            pool_recycle=settings.db_pool_recycle_sec,
            pool_pre_ping=settings.db_pool_pre_ping,
        )
        _session_factory = async_sessionmaker(
            _engine, class_=AsyncSession, expire_on_commit=False
        )
        _engine_loop = loop
    return _engine


def async_session(**kwargs) -> AsyncSession:
    """Open a session on the running loop's engine.

    A callable rather than an ``async_sessionmaker`` instance so the 26 existing
    ``async_session()`` call sites keep working while the factory underneath can
    be swapped when the loop changes.
    """
    get_engine()
    assert _session_factory is not None
    return _session_factory(**kwargs)


async def init_db() -> None:
    """Create tables. Use Alembic for migrations in production."""
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session
