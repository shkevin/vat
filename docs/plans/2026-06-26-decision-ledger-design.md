# Decision Ledger Design

**Date:** 2026-06-26 (finalized 2026-06-27)  
**Status:** Implemented (phases 0–3). Deferred: physical DB split (phase 4) and the
optional `decision_identifiers` fuzzy-match table — both explicitly optional in the
original design.  
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
- `resolve_and_apply_decision` — ingest hook; idempotent re-link with conflict policy
- `soft_unlink_findings` — asset delete preserves decisions
- `register_subject_alias` / `register_decision_aliases_for_asset_merge` — asset-merge
  identity migration (wired into `upsert_asset_alias`)
- `reconcile_decision_links` — nightly drift repair across findings
- `decision_provenance` — finding-detail read overlay (ledger linkage + conflict flag)

Fingerprint override needs no alias: the DSK excludes `fingerprint_id` by design, so a
decision survives override automatically.

Tables live in a dedicated `decisions` Postgres schema (migration 051) — the design's
service/storage boundary. They are FK-free and ORM-only, so a later physical DB split
(phase 4) is just a connection-string change.

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
- `identity_snapshot` on decisions for display when finding is gone (migration 050)
- Frontend Waivers tab + badge use `/api/decisions/waivers`

---

## Phase 3 / finalization (complete)

- **Conflict policy** (`decision_apply_action`): terminal compliance states
  (RiskAccepted/FalsePositive/Suppressed/NotApplicable/Mitigated/Duplicate) auto-apply;
  **Approved/Rejected are never auto-applied**; a decision is **not** projected onto a
  finding a human edited after the decision — both emit `decision.relink.conflict`.
- **Asset-merge identity migration**: `upsert_asset_alias` re-keys the merged asset
  segment of affected DSKs and registers `decision_subject_aliases`, so a prior
  Risk Accepted follows an AssetAlias-based merge. (Container *digest* merges recompute
  the DSK at ingest via `correlation_asset_image_for_ingest` — a separate path.)
- **Reconciliation**: `reconcile_decision_links` Celery beat (02:30 UTC, `vat-maintenance`)
  re-runs re-linking across findings to repair drift; idempotent.
- **Read-path overlay**: finding detail returns `decisionId`, `subjectKey`,
  `decisionVersion`, `decisionLinkMethod`, `decisionRelinked`, `decisionConflict`
  (annotates, never clobbers the projection cache).
- **Schema separation**: tables moved to the `decisions` schema (migration 051).

### Deferred (optional in the original design)

- **Phase 4 physical DB split** — boundary is ready (FK-free, ORM-only, own schema);
  only the connection string changes.
- **`decision_identifiers`** fuzzy re-link table — for medium/low DSK-confidence matches.
- **Container digest-merge → decision** bridging beyond ingest-time recomputation.

---

## Tests

- `tests/test_decision_subject_key.py` — golden DSK stability (no DB)
- `tests/test_decision_ledger.py` — survive delete + idempotent re-link (`integration_db`)
- `tests/test_decision_ledger_phase2.py` — export + expiry helpers (no DB)
