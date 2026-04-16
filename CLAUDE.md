# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VAT (Vulnerability Assessment Tracker) is a security findings management platform that bridges vulnerability scanners (Aikido, Trivy, Grype, Semgrep, Gitleaks, etc.) and task trackers (Linear) with structured triage, risk acceptance, and remediation tracking. See `docs/VAT-PRD.md` for full product requirements.

## Commands

### Docker (full stack)

```bash
docker compose up -d                                    # postgres, valkey, backend, frontend, celery
docker compose --profile observability up -d            # adds prometheus, loki, tempo, grafana
docker compose --profile scanner run scanner scan /workspace  # run local scanner
```

### Backend (from `backend/`)

```bash
uv sync                                    # install dependencies
uv run uvicorn app.main:app --reload --port 8000  # start API server
make worker                                # celery worker (vat-sync queue)
make beat                                  # celery beat scheduler
make worker-beat                           # combined worker+beat (dev only)
```

### Backend tests

```bash
cd backend
pytest                          # all tests with coverage
pytest -k test_name             # single test by name
pytest -m e2e_linear            # E2E tests (requires VAT_LINEAR_E2E_* env vars)
pytest -m integration_db        # tests requiring PostgreSQL with migrations
make verify-correlation         # correlation reversibility quality gate
```

### Frontend (from `frontend/`)

```bash
npm install && npm run dev      # dev server on :3000
npm run test                    # vitest (run once)
npm run test:watch              # vitest watch mode
npm run lint                    # eslint via next lint
npm run build                   # production build
```

## Architecture

### Backend

- **FastAPI** app at `backend/app/main.py` with SQLAlchemy 2.x async (asyncpg) on **PostgreSQL 16**
- **Celery** workers with Redis/Valkey broker; three queues: `vat-sync`, `vat-feeds`, `vat-maintenance`
- Beat schedule runs Linear sync polling (5min), sync queue processing (2min), vuln feed refresh (hourly), audit checkpoints (daily)
- All env vars use `VAT_` prefix; config in `backend/app/core/config.py` via pydantic-settings
- Alembic migrations in `backend/alembic/versions/`

### Backend layout

- `app/api/` — FastAPI route handlers (findings, assets, ingest, audit, export, sbom, vuln-feeds, settings, auth, oauth)
- `app/adapters/` — External system adapters (Aikido scanner, Linear tracker)
- `app/parsers/` — Scanner output parsers (Trivy, Grype, Semgrep, Gitleaks, npm audit, pip-audit, CycloneDX, SARIF, OpenSCAP)
- `app/services/` — Business logic (ingest, correlation/dedup, SLA, sync, audit events, finding identifiers)
- `app/models/` — SQLAlchemy models (Finding, Asset, CorrelationEdge, AuditEvent, Waiver, VulnFeedRecord, SBOMRecord, etc.)
- `app/schemas/` — Pydantic request/response schemas
- `app/tasks/` — Celery task modules (sync, audit, vuln feeds)

### Frontend

- **Next.js 15** (App Router) with React 18, Tailwind CSS, TanStack React Query
- Proxies `/api/*` and `/webhook/*` to backend via `API_UPSTREAM_URL` (default `http://localhost:8000`) in `next.config.js`
- API client in `frontend/lib/api.ts` — all backend calls go through this module
- State management via React Query + URL search params (nuqs)

### Key design concepts

- **Correlation/dedup**: Deterministic cross-source deduplication via fingerprints and correlation edges. See `docs/correlation-linking-architecture.md`
- **Ingest pipeline**: Push-based scanner ingestion normalizes findings from multiple parser formats into unified Finding model
- **Audit ledger**: All state changes produce AuditEvent records for compliance evidence (PRD section 7)
- **Waivers**: Risk acceptance with named attestation and expiry enforcement

### Observability

Docker profile `observability` provides Prometheus, Loki, Tempo, OTEL Collector, and Grafana (port 3001). Backend emits OpenTelemetry traces.

## Key documentation

- `docs/VAT-PRD.md` — Full product requirements
- `docs/correlation-linking-architecture.md` — Correlation and dedup design
- `docs/correlation-reversibility-test-gate.md` — QA gate for correlation changes
- `docs/scanner-correlation-readiness.md` — Per-scanner readiness tracker
