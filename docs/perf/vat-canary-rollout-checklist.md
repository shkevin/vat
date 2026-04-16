# VAT Canary Rollout Checklist

Use this checklist before promoting scalability changes to all tenants.

## Canary Scope

- Select one representative tenant/workspace with high finding volume.
- Route canary traffic to the new backend/frontend deployment.
- Keep rollback target ready (previous image tags + compose file revision).

## Verify SLOs

- `asset open p95` < 900ms (large dataset canary target)
- `table action p95` < 700ms
- `finding navigation p95` < 800ms
- `api list p95` < 500ms
- Browser heap growth over 15 minutes < 15%
- Worker queue lag < 30s

## API/Payload Validation

- Run endpoint baseline utility and compare with previous baseline:
  - `vat_data` payload reduced materially (target >= 60%)
  - no 5xx spikes after pagination/cap changes

## Worker/Queue Validation

- `vat-sync` queue drains steadily under normal load.
- `vat-feeds` queue remains independent; feed refresh does not starve sync traffic.
- Beat scheduler runs once and enqueues scheduled jobs as expected.

## Database/Pooling Validation

- PgBouncer accepts connections and backend uses pooled endpoint.
- DB CPU/connection counts remain stable under canary load.
- No connection timeout spikes from app pool + PgBouncer combo.

## Rollback Conditions

Immediately rollback canary if any of the following persist for > 10 minutes:
- p95 latencies exceed targets by > 30%
- queue lag exceeds 2 minutes
- sustained API error rate > 1%
- monotonic browser heap growth > 25%

## Rollout Progression

1. Canary tenant (25% of target traffic)
2. Expanded cohort (50%)
3. Full rollout only after 24h stable metrics window
