# Decision Ledger Design

**Date:** 2026-06-26  
**Status:** Implemented (phases 1–2)  
**Problem:** Triage decisions live on `findings` rows and are hard-deleted with asset cleanup.

---

## Summary

Human triage outcomes (status, justification, attestation, waiver metadata) are stored in a **durable decision ledger** keyed by **Decision Subject Keys (DSKs)**. Findings remain ephemeral scanner projections; ingest re-links decisions idempotently when the same risk reappears.

---

## Decision Subject Key (DSK) — highest-risk component

Implemented in `backend/app/services/decision_subject_key.py`.

| Property | DSK | `correlation_key` |
|----------|-----|-------------------|
| Tenant scoped | Yes | No |
| Image digest | Never | Optional |
| Prefix | `decision:v1:{tenant}:` | `v1:` |
| Source-issue alias | Yes | No |
| OpenSCAP branch | Yes | Partial |

Candidates (first match wins):

1. **primary** — typed risk identity (SCA, SAST, license, OpenSCAP, …)
2. **openscap** — when `stable_rule_key` present but primary used another type
3. **source_issue** — `source:{adapter}:{issue_id}:{asset_scope}` alias

Callers must pass **canonical asset** (via `correlation_asset_image_for_ingest` / `resolve_canonical_asset_id`).

---

## Schema

| Table | Role |
|-------|------|
| `triage_decisions` | Authoritative decision per `(tenant_id, subject_key)` |
| `triage_decision_revisions` | Append-only history |
| `decision_subject_aliases` | Alternate keys → canonical subject |
| `decision_finding_links` | Materialized finding attachment (soft-unlink on delete) |

Migration: `048_decision_ledger.py`

---

## Service

`backend/app/services/decision_ledger.py`

- `record_decision_from_finding` — dual-write on reviewer update / bulk triage
- `resolve_and_apply_decision` — ingest hook; idempotent re-link
- `soft_unlink_findings` — asset delete preserves decisions
- `register_subject_alias` — fingerprint override / asset merge (future)

Config: `VAT_DECISION_LEDGER_ENABLED` (default `true`)

---

## Integration points

| Location | Behavior |
|----------|----------|
| `ingest.py` | After correlation, `resolve_and_apply_decision` |
| `findings_service.py` | `record_decision_from_finding` on update/bulk |
| `assets.py` `_delete_asset_owned_data` | `soft_unlink_findings` before finding delete |

---

## Idempotency

- `UNIQUE(tenant_id, subject_key)` on decisions
- `UNIQUE(decision_id, finding_id)` on links
- `should_apply_decision()` skips re-apply when finding already reflects terminal status
- Second `resolve_and_apply_decision` call on same finding → `applied=False`

---

## Phase 2 (complete)

- Waiver expiry reads `triage_decisions` first (`expire_decision_waivers`), finding scan fallback
- Celery beat: `enforce-waiver-expiry` daily at 01:00 UTC (`maintenance_tasks.py`)
- `GET /api/decisions/waivers` — durable waiver list (includes unlinked)
- `POST /api/decisions/backfill` — admin backfill from existing findings
- Export bundle + auditor workbook use `build_waiver_export_records`
- `identity_snapshot` on decisions for display when finding is gone (migration 049)
- Frontend Waivers tab + badge use `/api/decisions/waivers`

---

## Tests

- `tests/test_decision_subject_key.py` — golden DSK stability (no DB)
- `tests/test_decision_ledger.py` — survive delete + idempotent re-link (`integration_db`)
- `tests/test_decision_ledger_phase2.py` — export + expiry helpers (no DB)
