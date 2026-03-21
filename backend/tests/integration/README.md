# Integration tests (PostgreSQL)

These tests hit a **real database** with the **Alembic migration head** applied. They are marked `integration_db`.

## Reproducible local run (empty or fresh DB)

1. Start PostgreSQL (e.g. Docker Compose from repo root):

   ```bash
   docker compose up -d postgres
   ```

2. Point the backend at the DB and migrate (from `backend/`):

   ```bash
   export VAT_DATABASE_URL=postgresql+asyncpg://vat:vat@localhost:5432/vat
   uv run alembic upgrade head
   ```

3. Run integration tests:

   ```bash
   uv run pytest tests/integration tests/test_correlation_golden_keys.py -v -m integration_db
   ```

The session fixture runs `alembic upgrade head` once; each test using `clean_integration_tables` truncates `findings` and audit tables so runs are repeatable on an “empty” database.

## Correlation E2E

- **Golden keys** (no DB): `tests/test_correlation_golden_keys.py` — Trivy vs Grype fixtures under `fixtures/correlation/` must yield the same typed `correlation_key`.
- **Full ingest path**: `test_correlation_ingest_e2e.py` — uses source names aligned with vat-local-scanner: `vat-local-trivy`, `vat-local-grype`, `vat-local-gitleaks`.

## Correlation toggles

Cross-source linking runs on every ingest when `VAT_CORRELATION_LINKING_ENABLED` is true (default). See `Settings.correlation_linking_enabled` in `app/core/config.py`.
