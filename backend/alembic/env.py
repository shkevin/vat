"""Alembic environment — uses sync engine for migrations."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.models.base import Base
from app.models.finding import Finding  # noqa: F401
from app.models.openscap_scan_result import OpenSCAPScanResult  # noqa: F401
from app.models.sbom import SbomPackage  # noqa: F401
from app.models.sync_event import SyncEvent  # noqa: F401
from app.models.user import Tenant, User  # noqa: F401
from app.models.webhook_event import WebhookEvent  # noqa: F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata
settings = get_settings()
# Use sync URL for migrations (psycopg2)
db_url = settings.database_url.replace("+asyncpg", "").replace("postgresql+asyncpg", "postgresql")
config.set_main_option("sqlalchemy.url", db_url)


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(
        config.get_main_option("sqlalchemy.url"),
        poolclass=NullPool,
    )
    with connectable.connect() as connection:
        do_run_migrations(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
