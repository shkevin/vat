"""Database session and engine configuration."""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.models.base import Base

settings = get_settings()
engine = create_async_engine(
    settings.database_url,
    echo="debug"
    if settings.database_url.startswith("postgresql+asyncpg://vat:vat@localhost")
    else False,
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    """Create tables. Use Alembic for migrations in production."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session
