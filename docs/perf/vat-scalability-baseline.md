# VAT Scalability Baseline

This runbook captures a repeatable baseline before/after scalability changes.

## 1) API Baseline

Run from `backend/` with API reachable:

```bash
API_BASE="http://localhost:8000/api" \
AUTH_TOKEN="<jwt>" \
uv run python scripts/benchmark_api_endpoints.py
```

Outputs:
- p50/p95 latency for `vat-data`, `findings`, `findings/groups`
- response payload sizes (bytes)
- summary JSON for trend comparison

## 2) Browser Heap Baseline

In Chrome DevTools:
1. Open VAT dashboard with a large dataset.
2. Record heap snapshot at T0.
3. Perform 20 interactions (asset open, filter, sort, finding open).
4. Wait 15 minutes with normal usage.
5. Record heap snapshot at T15.

Pass criteria:
- No monotonic heap growth greater than 15%.

## 3) Click Latency Baseline

Measure P95 manually with DevTools Performance:
- Asset page open-to-interactive.
- Asset/finding table filter/sort/apply.
- Finding open detail panel.

Record values in this format:

```text
asset_open_p95_ms=
table_action_p95_ms=
finding_open_p95_ms=
```

## 4) Queue/Worker Baseline

Record:
- Celery queue depth
- Worker throughput (tasks/min)
- Task lag for sync and feed refresh tasks

Use these values for canary verification after rollout.
