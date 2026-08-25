# VAT — Vulnerability Assessment Tracker

Authoritative source of record for vulnerability and security findings. Bridges Aikido scanner and Linear task tracker with structured triage, risk acceptance, and remediation tracking.

See [docs/VAT-PRD.md](./docs/VAT-PRD.md) for full product requirements.

## Architecture

- **Backend:** Python 3.11+, FastAPI, SQLAlchemy 2.x, PostgreSQL
- **Frontend:** React 18+, Next.js 14+ (App Router)

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL (or Docker)

### Backend

```bash
cd backend
uv sync
cp .env.example .env      # edit as needed
uv run uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000

### Database (Docker)

```bash
docker compose up -d postgres
```

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
