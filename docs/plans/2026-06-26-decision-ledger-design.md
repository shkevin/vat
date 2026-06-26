# Decision Ledger Design

**Date:** 2026-06-26  
**Status:** Implemented (phase 1)  
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

## Phase 2 (not in this PR)

- Waiver expiry Celery job reads ledger first
- Waivers tab queries ledger + active links
- Backfill job for existing findings with decisions
- Export/auditor workbook reads from ledger
- Asset-merge auto-alias registration

---

## Tests

- `tests/test_decision_subject_key.py` — golden DSK stability (no DB)
- `tests/test_decision_ledger.py` — survive delete + idempotent re-link (`integration_db`)
