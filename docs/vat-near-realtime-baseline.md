# VAT Near-Real-Time Baseline

Date: 2026-03-21

## Baseline Before Refactor

- Frontend first load used one monolithic `refetch()` in `frontend/hooks/useVATData.ts`.
- Initial fetch path requested:
  - `GET /api/vat-data?limit=0`
  - `GET /api/settings`
  - `GET /api/sbom/packages?limit=5000`
- `loading` stayed true until all three requests completed.
- Backend `/api/vat-data` fetched unbounded findings when `limit=0` and always loaded all assets to include zero-finding rows.

## Baseline Signals To Track

- `vat_http_request_latency_seconds_*` for `/api/vat-data`
- `vat_http_response_bytes_total` for `/api/vat-data`
- Frontend UX:
  - time-to-first-shell (interactive layout)
  - time-to-first-findings-render
  - background refresh completion after focus

## Target SLOs

- Warm shell interactive p95: `< 1.0s`
- First findings render p95: `< 2.5s`
- Background refresh p95: `< 1.5s`

## Verification Commands

```bash
# API latency/bytes metrics
curl -s http://localhost:8000/metrics | rg "vat_http_request_latency_seconds|vat_http_response_bytes_total|vat_ingest_latency_seconds"

# Spot-check vat-data response shape/meta
curl -s "http://localhost:8000/api/vat-data?page=1&page_size=100&include_assets=true&include_zero_assets=false" \
  -H "Authorization: Bearer <token>" | jq '.meta'
```

## Authenticated p95 benchmark script

Use the local script to run a curl loop plus before/after Prometheus diff:

```bash
# token auth
VAT_TOKEN="<your-token>" \
VAT_REQUESTS=60 \
./scripts/measure_vat_data_p95.sh

# or legacy header auth
VAT_USER_EMAIL="you@company.com" \
VAT_REQUESTS=60 \
./scripts/measure_vat_data_p95.sh
```

Output:
- markdown report in `artifacts/vat-data-p95-report-<timestamp>.md`
- client latency percentiles (p50/p90/p95/p99)
- `/metrics` deltas for `vat_http_*` series on `/api/vat-data`
