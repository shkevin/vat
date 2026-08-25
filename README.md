# VAT — Vulnerability Assessment Tracker

Authoritative source of record for vulnerability and security findings. Bridges Aikido scanner and Linear task tracker with structured triage, risk acceptance, and remediation tracking.

See [docs/VAT-PRD.md](./docs/VAT-PRD.md) for full product requirements.

## Architecture

- **Backend:** Python 3.11+, FastAPI, SQLAlchemy 2.x, PostgreSQL
- **Frontend:** React 18+, Next.js 14+ (App Router)

## Quick Start

### Everything at once (Docker)

```bash
docker compose up -d
```

Brings up PostgreSQL, Valkey, the backend, the frontend, and the Celery worker
and beat. The backend runs migrations on start, so the generated admin password
is in its logs:

```bash
docker compose logs backend | grep -A3 'bootstrap admin'
```

Then open http://localhost:3000 and see **First login** below.

### Running from source

Prerequisites: Python 3.11+, Node.js 18+, and PostgreSQL (or `docker compose up -d postgres`).

```bash
# backend
cd backend
uv sync
cp .env.example .env      # edit as needed
uv run alembic upgrade head
uv run uvicorn app.main:app --reload --port 8000
```

```bash
# frontend
cd frontend
npm install
npm run dev
```

Open http://localhost:3000.

### First login

The first migration run creates an `admin` account and prints a **randomly
generated** password once:

```
================================================================
  VAT bootstrap admin created
    username: admin   (or admin@vat.local)
    password: <generated>
================================================================
```

Save it — it is not stored anywhere else and is not shown again. To choose the
password yourself, set `VAT_ADMIN_BOOTSTRAP_PASSWORD` before running migrations:

```bash
VAT_ADMIN_BOOTSTRAP_PASSWORD='...' uv run alembic upgrade head
```

Re-running migrations never resets a password you have since changed.

### Correlation Reversibility Gate

For repeatable validation of correlation remove/restore/audit behavior:

```bash
cd backend
make verify-correlation
```

Details: [`docs/correlation-reversibility-test-gate.md`](./docs/correlation-reversibility-test-gate.md)

### Correlation And Linking Design

For end-to-end documentation of how deterministic correlation, linking, asset merge review requirements, and crosswalk mapping work:

[`docs/correlation-linking-architecture.md`](./docs/correlation-linking-architecture.md)

### Scanner Correlation Readiness Tracker

For scanner-by-scanner readiness, testing coverage, and adaptation backlog:

[`docs/scanner-correlation-readiness.md`](./docs/scanner-correlation-readiness.md)

## Project Structure

```
vat/
├── backend/                 # FastAPI API
│   ├── app/
│   │   ├── api/             # Route handlers
│   │   ├── adapters/        # Source (Aikido) & tracker (Linear) adapters
│   │   ├── core/            # Config, database
│   │   ├── models/          # SQLAlchemy models
│   │   ├── schemas/         # Pydantic schemas
│   │   └── services/        # Ingest, dedup, SLA
│   └── requirements.txt
├── frontend/                # Next.js App Router
│   ├── app/                 # Pages, layout
│   ├── components/
│   └── lib/
├── docs/
├── VAT-PRD.md
└── README.md
```

## Roadmap

| Phase   | Status   | Deliverables                                      |
|---------|----------|---------------------------------------------------|
| v0.1–0.3 | Complete | Frontend prototype, data model, triage workflow  |
| v1.0   | Planned  | FastAPI backend, PostgreSQL, Aikido + Linear     |
| v1.1   | Planned  | Additional adapters, PDF export, Slack escalation |
