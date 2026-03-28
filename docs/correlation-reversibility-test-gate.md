# Correlation Reversibility Test Gate

This gate locks in repeatable verification for the non-destructive correlation lifecycle and minimal Phase 2 P0 features:

- remove correlation edge
- restore correlation edge
- per-finding correlation history
- operation-id correlation history lookup
- deterministic medium-confidence auto-link behavior
- dynamic crosswalk ingestion and resolution

## When to run

Run this gate before merging any future changes that touch:

- `backend/app/api/findings.py` correlation endpoints
- `backend/app/services/correlation_edges.py`
- `backend/app/services/correlation_linking.py`
- related correlation tests

## Single command

From `backend/`:

```bash
make verify-correlation
```

Equivalent direct command:

```bash
uv run python scripts/verify_correlation_reversibility.py
```

## What the gate does

1. Applies schema updates to the local DB:
   - `uv run alembic upgrade head`
2. Runs targeted correlation test suites:
   - `tests/test_correlation_edges_service.py`
   - `tests/test_crosswalks_service.py`
   - `tests/test_correlation_scoring.py`
   - `tests/test_findings_correlation_edges_api.py`
   - `tests/test_findings_correlation_handlers_unit.py`
   - `tests/test_correlation_linking.py`
   - `tests/test_correlation_linking_contract.py`
3. Enforces coverage thresholds:
   - `app/services/correlation_edges.py` >= 90%
   - correlation handler block in `app/api/findings.py` >= 90%

The script writes a coverage artifact to `backend/coverage-correlation.json` for inspection.

## Pass/Fail contract

- Exit code `0`: gate passes, safe to continue correlation enhancements
- Non-zero exit: gate fails, fix tests/coverage before proceeding

## Notes

- This gate is scoped to the correlation reversibility slice.
- It does not replace broader regression runs for unrelated subsystems.
