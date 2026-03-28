# Audit evidence handoff runbook

This runbook supports compliance and security reviews that need to **reconstruct ingest and mapping decisions** and **verify ledger integrity** using VAT APIs and exports. Pair it with [PRD-audit-asset-mapping-dedup.md](./PRD-audit-asset-mapping-dedup.md).

## Scope

- **Replay deduplication** — fingerprint-based; see `dedup.replay.new` / `dedup.replay.merged`.
- **Cross-source correlation** — typed `correlation_key`; link-only policy sets `correlated_to` to the oldest finding in the cluster; see `dedup.correlation.linked` / `dedup.correlation.skipped`.
- **Audit ledger** — append-only `audit_events` with hash chaining; **daily checkpoints** in `audit_ledger_checkpoints`.

## Prerequisites

- Admin API access (audit export and checkpoint endpoints require admin auth).
- Base URL of the VAT API (e.g. `https://vat.example.com`).
- Optional: `curl`, `jq`, `unzip`.

## 1. Export an audit bundle (ZIP)

**Endpoint:** `GET /api/audit/export` (admin)

**Query parameters (all optional):**

| Parameter    | Description                                      |
|-------------|---------------------------------------------------|
| `trace_id`  | Narrow to a single request/trace                 |
| `source_id` | Ingest source / integration id                   |
| `parser_id` | Parser identifier                                |
| `asset_id`  | Resolved asset id                                |
| `finding_id`| VAT finding id                                   |
| `event_type`| e.g. `dedup.correlation.linked`, `asset.mapping.resolved` |
| `date_from` | ISO datetime (start, inclusive)                  |
| `date_to`   | ISO datetime (end, inclusive)                    |
| `limit`     | Max rows (1–20000, default 5000)                 |

**Example — by trace:**

```bash
curl -sS -H "Authorization: Bearer <admin_jwt>" \
  "https://vat.example.com/api/audit/export?trace_id=<hex>&limit=20000" \
  -o audit-bundle.zip
```

**Contents:**

- `manifest.json` — schema version, generation time, filter summary, row count.
- `audit-events.json` — ordered audit rows with `record_hash`, `prev_record_hash`, and decision fields.

A follow-up export emits `export.audit_bundle.generated` for the export action itself (when at least one row matches).

## 2. Daily ledger checkpoint (anchor hash)

**Automated:** Celery Beat runs `app.tasks.audit_tasks.run_daily_audit_checkpoint` at **00:30 UTC** and anchors the **previous UTC calendar day** for retention class `operational` (configurable). Disable with `VAT_AUDIT_DAILY_CHECKPOINT_ENABLED=false`.

**Manual:** `POST /api/audit/checkpoints/daily?checkpoint_date=YYYY-MM-DD&retention_class=operational` (admin)

Use checkpoints to prove **daily anchor hashes** over the event stream for a given date and retention class.

## 3. Correlation link evidence

For a finding `F`:

1. Read `correlation_key`, `correlation_confidence`, and `correlated_to` from the finding record or API.
2. In the audit export, filter `event_type` ∈ `dedup.correlation.linked`, `dedup.correlation.skipped` and `finding_id=F`.
3. **Linked** rows include `data.canonical_finding_id` and `data.correlation_key`. **Skipped** rows include `decision_reason_code` such as `no_peer`, `cluster_root`, `confidence_below_policy`, or `no_correlation_key`.

## 4. Suggested evidence checklist

| Artifact | How to obtain |
|----------|----------------|
| Ingest trace for a batch | Response `traceId` from `POST /api/ingest` or `X-Trace-Id` / middleware trace |
| Full decision trail for that trace | Export with `trace_id=<id>` |
| Cross-source link decision | Export `event_type=dedup.correlation.linked` or `skipped` for the finding |
| Daily integrity anchor | Query `audit_ledger_checkpoints` or re-run `POST .../checkpoints/daily` for a date and compare `anchor_hash` |

## 5. Operational dashboards

See Grafana provisioning under `observability/grafana/provisioning/dashboards/json/` (e.g. `vat-asset-mapping-dedup-validation.json`, `vat-platform-health.json`) for live validation of audit log patterns and pipeline health.

## 6. Regression tests (correlation linking)

Automated coverage lives under `backend/tests/`:

- `test_correlation_linking.py` — mocked DB, policy branches, multi-node repair, tenant-scoped SQL, `cluster_membership_mismatch`.
- `test_correlation_linking_contract.py` — compiled SQL: `tenant_id IS NULL` vs equality bind, `ORDER BY created_at, id`.
- `test_correlation_golden_keys.py` — **no DB**: committed Trivy/Grype JSON under `tests/integration/fixtures/correlation/` must produce the **same** `correlation_key` (reproducible cross-scanner contract).
- `tests/integration/` — marked `integration_db`; session runs `alembic upgrade head`; `clean_integration_tables` truncates findings + audit for repeatable runs on an empty DB. Includes E2E ingest via `_ingest_from_parser` with `vat-local-trivy` / `vat-local-grype` / `vat-local-gitleaks` source names.

**Correlation linking** runs on every successful ingest when `VAT_CORRELATION_LINKING_ENABLED` is true (default). There is no per-request flag.

Run from `backend/`:

```bash
export VAT_DATABASE_URL=postgresql+asyncpg://vat:vat@localhost:5432/vat
uv run alembic upgrade head
uv run pytest tests/test_correlation_linking.py tests/test_correlation_linking_contract.py tests/test_correlation_golden_keys.py tests/integration -v -m integration_db
```

CI should run the integration slice against PostgreSQL with migrations so cross-tenant isolation and parser-level linking are exercised, not only mocks.
