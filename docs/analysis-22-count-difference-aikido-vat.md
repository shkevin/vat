# Analysis: 22-Count Difference Between Aikido and VAT Open Issues

**Observed:** Aikido shows 1,413 current open issues; VAT shows 1,391 open. Difference: 22.

## Data Flow Summary

| Stage | Source | Count |
|-------|--------|-------|
| Aikido dashboard | `GET /issues/counts` | 1,413 open |
| VAT DB (findings) | `status = 'Open'` | 1,391 open |
| VAT total (non-archived) | All findings from Aikido | 2,789 |

## Root Cause Hypotheses (Ranked by Likelihood)

### 1. **Sync timing (most likely)**

22 new open issues were created in Aikido after the last VAT bootstrap/full sync. VAT only ingests from `GET /issues/export` during bootstrap or full sync; it does not continuously poll. Webhooks handle updates for *existing* findings, but new issues that appear in Aikido after the last sync are not ingested until the next sync.

**How to verify:** Run a fresh bootstrap and compare open counts. If they align, timing is the cause.

### 2. **Ingest failures during bootstrap**

The full sync iterates over `raw_issues` and calls `ingest_finding()` for each. On exception, it logs a warning and continues:

```python
# aikido_full_sync.py:136-147
for raw in raw_issues:
    try:
        transformed = await adapter.to_vat_finding(...)
        finding, is_new = await ingest_finding(...)
    except Exception as e:
        await session.rollback()
        logger.warning("Full sync bootstrap failed for issue %s: %s", raw.get("id", "?"), ...)
```

If 22 issues fail transform or ingest (e.g. missing required fields, DB constraint), they never appear in VAT.

**How to verify:** Re-run full sync and inspect logs for `"Full sync bootstrap failed for issue"`. Compare `result["pull"]["fetched"]` vs `created + merged`.

### 3. **Export API limit / pagination** — Not applicable

Per Aikido docs, `GET /issues/export` returns all issues in one response (no pagination). Query params are optional filters (`format`, `filter_status`, `filter_team_id`, etc.), not pagination.

### 4. **Status mapping mismatch**

VAT maps Aikido status as follows:

| Aikido | VAT |
|--------|-----|
| `ignored`, `suppressed`, `auto_ignored` or `ignored_at` set | Suppressed |
| `closed`, `resolved` or `closed_at` set | Resolved |
| else | Open |

If Aikido has a status that they count as "open" but we map to Resolved/Suppressed, we would undercount. For example:

- **Snoozed:** Aikido has `snooze_until`; we do not use it. Snoozed issues would fall through to `else` → Open, so we would count them. No undercount from snooze.
- **Mitigated:** We do not map `mitigated`; it falls to Open. We would count it. No undercount.
- **Reopened:** If Aikido has `closed_at` set from a prior close but status "open" after reopen, we would map to Resolved because of `closed_at_raw`. That could undercount if Aikido clears `closed_at` on reopen but we received stale data.

**How to verify:** Run `diagnose_aikido_counts.py` and inspect the status breakdown. Look for statuses we map to closed that Aikido might count as open.

### 5. **Groups vs instances**

Aikido groups similar issues; each group can have multiple instances. VAT uses `source_issue_id` for 1:1 mapping, so each VAT finding = one Aikido instance. If Aikido’s "1,413 open" were group count and VAT’s 1,391 were instance count, we would expect VAT ≥ Aikido (instances ≥ groups). Since Aikido > VAT, this does not explain the gap. Aikido’s count is almost certainly instance-based (or at least not group-only).

## Recommended Next Steps

1. **Run the diagnostic script** (with Aikido credentials configured):

   ```bash
   docker compose exec backend uv run python scripts/diagnose_aikido_counts.py
   ```

   This will show:
   - Raw export count vs Aikido counts
   - Open count computed from export (VAT logic)
   - Status breakdown
   - Direct comparison: `Aikido /issues/counts open` vs `VAT computed current open`

2. **Run a fresh full sync** and compare:
   - `result["pull"]["fetched"]` vs `created + merged`
   - Any ingest failure warnings in logs

3. **Add diagnostic logging** to full sync:
   - Log count of ingest failures
   - Optionally persist failed issue IDs for later analysis

## Relevant Code Paths

- **Status mapping:** `backend/app/adapters/aikido.py` lines 790–801
- **Ingest:** `backend/app/services/ingest.py` (fingerprint, merge, status sync)
- **Full sync:** `backend/app/services/aikido_full_sync.py` lines 122–156
- **Export fetch:** `backend/app/adapters/aikido.py` `fetch_aikido_issues()`
- **Diagnostic:** `backend/scripts/diagnose_aikido_counts.py`
