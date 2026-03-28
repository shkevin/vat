"""
Integration test harness: migrated schema + clean tables.

Reproducible runs require PostgreSQL and ``VAT_DATABASE_URL`` (same as backend).
Run migrations once per session: ``uv run alembic upgrade head`` from ``backend/``.

Example (empty local stack):

.. code-block:: bash

   docker compose up -d postgres
   cd backend && VAT_DATABASE_URL=postgresql+asyncpg://vat:vat@localhost:5432/vat uv run alembic upgrade head
   uv run pytest tests/integration -v -m integration_db
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from sqlalchemy import text

# backend/tests/integration/conftest.py -> parents[2] = backend repo root for alembic
BACKEND_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def _session_alembic_upgrade() -> None:
    """Apply Alembic migrations once so integration tests match production schema."""
    env = {**os.environ}
    r = subprocess.run(
        ["uv", "run", "alembic", "upgrade", "head"],
        cwd=str(BACKEND_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if r.returncode != 0:
        pytest.skip(
            "alembic upgrade head failed — start Postgres and set VAT_DATABASE_URL. "
            f"stderr={r.stderr!r} stdout={r.stdout!r}"
        )


@pytest.fixture
async def integration_db(db, _session_alembic_upgrade):
    """Async session against DB at migration head with correlation columns."""
    try:
        await db.execute(
            text("SELECT correlation_key, correlated_to FROM findings LIMIT 0")
        )
    except Exception as exc:
        pytest.skip(f"Schema missing correlation columns: {exc}")
    yield db


@pytest.fixture
async def clean_integration_tables(integration_db):
    """Truncate audit + findings for isolated E2E (repeatable on empty DB)."""
    await integration_db.execute(
        text(
            "TRUNCATE TABLE "
            "audit_events, "
            "audit_ledger_checkpoints, "
            "correlation_edges, "
            "crosswalk_runs, "
            "crosswalk_entries, "
            "finding_identifiers "
            "RESTART IDENTITY CASCADE"
        )
    )
    await integration_db.execute(
        text("TRUNCATE TABLE findings RESTART IDENTITY CASCADE")
    )
    await integration_db.commit()
    yield integration_db
    await integration_db.execute(
        text(
            "TRUNCATE TABLE "
            "audit_events, "
            "audit_ledger_checkpoints, "
            "correlation_edges, "
            "crosswalk_runs, "
            "crosswalk_entries, "
            "finding_identifiers "
            "RESTART IDENTITY CASCADE"
        )
    )
    await integration_db.execute(
        text("TRUNCATE TABLE findings RESTART IDENTITY CASCADE")
    )
    await integration_db.commit()
