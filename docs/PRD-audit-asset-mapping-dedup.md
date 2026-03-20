# PRD: Enterprise Auditability and Deterministic Asset Mapping/Deduplication

## 1. Document Purpose

This PRD defines the production pattern for:

- Enterprise-grade auditability and decision traceability
- Deterministic mapping of findings to assets across scanner types
- Separation of replay deduplication, cross-source correlation, and grouping
- Operational observability required to validate behavior end-to-end

This document is intended to be the canonical reference for implementation, validation, and audit evidence preparation.

## 2. Problem Statement

VAT ingests findings from multiple scanners and integration paths (Aikido, local scanner, webhook/push sources). Without deterministic identity rules and audit evidence:

- Findings may map inconsistently to assets across sources
- Deduplication decisions are difficult to explain and verify
- Grouping can be conflated with deduplication
- Compliance teams cannot reliably reconstruct "what happened, why, and by whom/system"

We need deterministic behavior with a complete decision trail.

## 3. Product Goals

1. **Deterministic Asset Mapping**
   - Every ingested finding maps to an asset via explicit precedence and reason codes.
2. **Audit-First Architecture**
   - Every key ingest/mapping/dedup decision emits immutable audit events.
3. **Correct Concept Separation**
   - Replay deduplication, cross-source correlation, and grouping are distinct systems.
4. **Operational Verifiability**
   - Dashboards and telemetry must prove system behavior using live metrics/logs/traces.

## 4. Non-Goals

- Do not merge unrelated findings solely for UI convenience.
- Do not use grouping keys as dedup keys.
- Do not hide mapping failures without auditable rejection events.

## 5. Scope

### In Scope

- Deterministic asset resolver contract and precedence
- Parser identity policy contract
- Immutable audit ledger with hash-chain behavior and daily checkpoint support
- Ingest-path decision event emission
- Local scanner single vs multi asset mode behavior
- Typed correlation key generation
- Observability stack and validation dashboards

### Out of Scope (Current State)

- Automatic correlation linking engine that sets `correlated_to` for matched findings
- Correlation-driven merge policy (link-only policy is the intended next step)

## 6. Deterministic Asset Mapping Model

### 6.1 Resolver Contract

For each finding, resolver output includes:

- `asset_id`
- `asset_kind`
- `asset_display_name`
- `confidence`
- `reason`
- `resolution_inputs`

### 6.2 Precedence

1. Explicit ingest override (`X-VAT-Asset`)
2. Strong scanner-provided asset identity (e.g., image/repo/component fields)
3. Derived identity from parser-specific strong fields
4. Strict-mode rejection when required identity is absent

### 6.3 Strict Mode

When strict mode is enabled and required identity is missing, ingest must reject and emit policy rejection audit events.

## 7. Parser Identity Contract

Each parser declares:

- `requires_explicit_asset`
- `supports_deterministic_derived_asset`
- `strong_fields`

This policy is the machine-readable source of truth for deterministic mapping behavior by parser.

## 8. Deduplication, Correlation, and Grouping

### 8.1 Replay Deduplication (Implemented)

- Purpose: prevent duplicate rows from repeated ingestion of the same finding identity
- Implemented via fingerprint-based matching in ingest
- Emits `dedup.replay.new` or `dedup.replay.merged`

### 8.2 Cross-Source Correlation (Partially Implemented)

- Typed correlation keys are computed and stored:
  - `correlation_key`
  - `correlation_confidence`
- Current gap: no automatic linking engine yet sets `correlated_to`

### 8.3 Grouping (Separate Concern)

- Grouping is presentation/triage aggregation logic
- Grouping keys and behavior are distinct from dedup keys
- Must remain independent to avoid data integrity issues

## 9. Enterprise Auditability Requirements

### 9.1 Audit Ledger

- Append-only `audit_events` table
- Event-level hash chaining (`prev_record_hash` -> `record_hash`)
- Event metadata includes trace/source/parser/asset/finding/decision fields

### 9.2 Checkpointing

- Daily anchor checkpoints in `audit_ledger_checkpoints`
- API endpoint supports checkpoint generation

### 9.3 Event Coverage

Critical events include:

- Auth validated/rejected
- Parser resolution/failure
- Asset mapping resolved/rejected
- Replay dedup new/merged
- Ingest failure
- Asset lifecycle (created)

### 9.4 Traceability

- `trace_id` propagated in middleware and response headers
- Trace IDs included in audit log messages and OTEL spans

## 10. Observability and Operational Validation

### 10.1 Stack

- Prometheus (metrics)
- Loki + Promtail (logs)
- Tempo (traces)
- OTEL Collector (telemetry pipeline)
- Grafana (dashboards/provisioning)

### 10.2 Dashboard Suite (Consolidated)

- `VAT Operational Overview`
- `VAT Audit and Asset Forensics`
- `VAT Observability Pipeline`
- `VAT Platform Health`

### 10.3 Validation Outcomes

Expected live signals:

- Non-zero `asset.mapping.resolved`
- Non-zero `dedup.replay.new|merged`
- Non-zero `asset.lifecycle.created` when assets are discovered
- `vat_audit_otel_mirror_failures_total == 0` (healthy path)
- Tempo/Loki ingestion rates above zero

## 11. Acceptance Criteria

1. Deterministic mapping path is auditable for all supported parsers.
2. Every mapping decision is explainable with `asset_id`, `reason`, `decision`, and `result`.
3. Replay dedup behavior is visible in both metrics and logs.
4. Audit ledger evidence can be exported and traced end-to-end by `trace_id`.
5. Dashboard suite provides operational confidence without redundant views.

## 12. Implementation Status Snapshot

### Completed

- Audit ledger + checkpoint schema and services
- Deterministic resolver integration in ingest path
- Parser identity policy contract
- Replay dedup decision event emission
- Local scanner `asset_mode` single/multi behavior
- Typed correlation key generation + schema fields
- Observability stack + consolidated dashboard suite
- Aikido full sync mapping/dedup and asset lifecycle event emission

### Remaining (High Priority)

1. Implement correlation linking engine (link-only policy):
   - set `correlated_to` when correlation confidence/policy allows
   - emit `dedup.correlation.linked|skipped` events
2. Add scheduled daily checkpoint automation (if required operationally)
3. Produce formal evidence runbook/export template for audit handoff

## 13. Risks and Controls

- **Risk:** Over-merging due to weak identity fields  
  **Control:** strict mode + parser identity contract + reason-coded events

- **Risk:** Hidden ingestion path differences  
  **Control:** enforce audit event parity across all ingest paths

- **Risk:** Operator confusion between dedup and grouping  
  **Control:** explicit separate metrics/panels and separate code paths

## 14. Reference Files

- `backend/app/services/asset_resolver.py`
- `backend/app/parsers/__init__.py`
- `backend/app/services/ingest.py`
- `backend/app/services/correlation.py`
- `backend/app/services/audit_events.py`
- `backend/app/services/aikido_full_sync.py`
- `backend/app/api/audit.py`
- `backend/app/models/audit_event.py`
- `backend/app/models/audit_ledger_checkpoint.py`
- `observability/grafana/provisioning/dashboards/json/vat-operational-overview.json`
- `observability/grafana/provisioning/dashboards/json/vat-asset-mapping-dedup-validation.json`
- `observability/grafana/provisioning/dashboards/json/vat-observability-pipeline.json`
- `observability/grafana/provisioning/dashboards/json/vat-platform-health.json`

