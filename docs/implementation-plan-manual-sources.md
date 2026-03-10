# Implementation Plan: Additional Manual Integration Sources

**Version:** 1.2  
**Date:** March 2026  
**Status:** Complete (Phases 1–8)

---

## 1. Overview

Extend VAT's Manual source to support multiple push-based scanner integrations (Trivy, Snyk, Semgrep, Gitleaks, etc.) via tool-specific parsers. Each parser converts native tool output to `VatFindingSchema`; no external dependencies. Findings are ingested through the existing `ingest_finding` flow with source attribution and fingerprint deduplication.

**Key design decisions:**
- **1:1 mapping:** Each push source (Trivy, Snyk, etc.) is a distinct Manual integration. No "add another push source" — each new source requires a full manual integration setup.
- **Dedicated parsers only:** No universal/configurable parser. Each supported tool has its own parser (Trivy, Snyk, Semgrep, Gitleaks, SARIF).
- **Parser selection in settings:** Manual integration source has a dropdown/search for parser. VAT uses the configured parser for the payload — no auto-detect, no format in API input.
- **Single ingest endpoint:** One endpoint for all manual ingest (JSON body or file upload).
- **Per-source auth:** Each source has its own credentials (API token and/or OAuth client), rotatable and deletable independently.

---

## 2. Goals

- Add Trivy, Snyk, Semgrep, and Gitleaks as first-wave manual sources
- 1:1 mapping: each push source = distinct Manual integration; full setup per source; no "add another push source"
- Dedicated parsers only — no universal/configurable parser
- Parser configured per Manual source in Settings (dropdown/search)
- Single ingest endpoint; VAT uses source's configured parser for payload
- Per-source auth: API token + OAuth support, each source independently rotatable/deletable
- Establish a parser registry pattern for easy addition of future tools
- Preserve deduplication, SLA
- Document CI integration examples for each supported tool

---

## 3. Architecture

### 3.1 Parser Pattern

```
[Payload] → Auth → source_id → lookup source config → parser → Parser.parse(raw) → list[VatFindingSchema] → ingest_finding()
```

- Each parser implements `IngestParser` (format_name, parse).
- Parsers live in `backend/app/parsers/`.
- Parser is configured per Manual source in Settings; no auto-detect.

### 3.2 Endpoint Strategy — Single Endpoint

| Endpoint | Behavior |
|----------|----------|
| `POST /api/ingest` | Single endpoint. Accepts JSON body or file upload. Auth validates key → source_id. Lookup source config → parser. Use configured parser to parse payload. |

**Flow:**
1. Request arrives with `Authorization: Bearer <key>` or `X-VAT-API-Key`
2. Validate key → resolve source_id (e.g. `trivy-ci`)
3. Lookup source in settings → get `parser` (e.g. `trivy`)
4. Get parser from registry (TrivyParser)
5. Parse payload with that parser → list[VatFindingSchema]
6. Ingest each finding with source=source_id

**Source attribution:** From API key's source_id. Parser from source config.

### 3.3 Manual Source Config — 1:1 Mapping

**Each push source is a distinct Manual integration.** Adding Trivy, Snyk, Semgrep, etc. creates a new source entry with full setup — not "add another" under a generic Manual bucket.

| Field | Description |
|-------|-------------|
| name | Display name (e.g. "Trivy CI", "Snyk Prod") |
| adapter | `manual` |
| parser | Dropdown/search: Trivy, Snyk, Semgrep, Gitleaks, SARIF, Canonical |
| ... | credentials, color, etc. |

**Add flow:** "Add source" → pick Trivy/Snyk/Semgrep/etc. → full manual integration setup (name, parser, create API key). Each source is independent.

**Parser options (first wave):**
- **Trivy** — Trivy JSON (vulns, secrets, licenses, misconfig)
- **Snyk** — Snyk JSON
- **Semgrep** — Semgrep JSON
- **Gitleaks** — Gitleaks JSON
- **SARIF** — SARIF 2.1.0
- **Canonical** — Direct VAT format `{ findings: [...] }` (validates, passes through)

**Source config lookup:** API key → source_id. Sources list (settings) → find source by id → get parser. Use parser to parse payload.

### 3.4 Finding Type Inference

| Tool | Default finding_type |
|------|----------------------|
| Trivy (vuln) | CVE |
| Trivy (secret) | Secret |
| Trivy (license) | License |
| Trivy (misconfig) | IaC |
| Snyk | CVE |
| Semgrep | SAST |
| Gitleaks | Secret |

---

## 4. Auth Model — Per-Source Credentials

### 4.1 Requirements

- Each source (trivy, snyk, semgrep, gitleaks, etc.) has its own credentials.
- Support **API token** and **OAuth** (client credentials) for programmatic ingest.
- Credentials are rotatable and deletable independently per source.

### 4.2 Data Model

**Option A: Extend SettingsKV (current)**  
Store per-source credentials in `source_credentials`:

```json
{
  "trivy-ci": {
    "authType": "api_token",
    "keyHash": "...",
    "keyPrefix": "vat_",
    "createdAt": "...",
    "rotatedAt": null
  },
  "snyk-prod": {
    "authType": "oauth",
    "clientId": "...",
    "clientSecretHash": "...",
    "createdAt": "...",
    "rotatedAt": null
  }
}
```

**Option B: Separate table (recommended for audit)**  
`source_credential` table:

| Column | Type | Description |
|--------|------|-------------|
| id | uuid | PK |
| source_id | str | Unique (trivy, snyk, etc.) |
| auth_type | enum | "api_token" \| "oauth" |
| key_hash | str | For API token (nullable) |
| key_prefix | str | Display prefix |
| client_id | str | For OAuth (nullable) |
| client_secret_hash | str | For OAuth (nullable) |
| created_at | datetime | |
| rotated_at | datetime | Last rotation |
| revoked_at | datetime | Soft delete |

### 4.3 Auth Flows

**API Token (existing, extended):**
- Header: `Authorization: Bearer <token>` or `X-VAT-API-Key: <token>`
- Validate: hash lookup → resolve source_id
- Return source_id for ingest attribution

**OAuth Client Credentials (new):**
- VAT exposes `POST /oauth/token` (or `/api/oauth/token`)
- Grant type: `client_credentials`
- Request: `client_id`, `client_secret`, `grant_type=client_credentials`
- Response: `access_token`, `expires_in`, `token_type=Bearer`
- Token encodes source_id (JWT or opaque with DB lookup)
- Ingest: `Authorization: Bearer <access_token>` — validate token, resolve source_id

### 4.4 Per-Source Operations

| Operation | API token | OAuth |
|-----------|-----------|-------|
| Create | Generate key, store hash, return once | Create client_id, client_secret; store hash; return once |
| Rotate | Regenerate key; invalidate old | Regenerate client_secret; invalidate old tokens |
| Revoke | Delete credential | Delete credential; invalidate tokens |
| List | List source_id (no secrets) | Same |

### 4.5 Settings UI

- **Manual source config:** Parser dropdown/search (Trivy, Snyk, Semgrep, Gitleaks, SARIF, Canonical)
- **Per-source credentials:** "Create API key" | "Create OAuth client" | "Rotate" | "Revoke"
- Display: source_id, parser, auth_type, last rotated, prefix/client_id (no secrets)

---

## 5. Phases

### Phase 1: Parser Registry & Single Ingest Endpoint

**Scope:** Parser registry, source config with parser field, unified ingest endpoint.

| Task | Description | Files |
|------|-------------|-------|
| 1.1 | Create parser registry: `get_parser(parser_id: str) -> IngestParser`; include CanonicalParser for `{ findings: [...] }` | `app/parsers/__init__.py` |
| 1.2 | Add `parser` field to Manual source config schema | `app/schemas/`, `app/api/settings.py` |
| 1.3 | Add `_ingest_from_parser(db, raw, parser, source)` helper | `app/api/ingest.py` |
| 1.4 | Refactor `POST /api/ingest` to single endpoint: accept JSON body or file upload; require auth; lookup source → parser; parse and ingest | `app/api/ingest.py` |

**Deliverable:** Single `POST /api/ingest`; parser from source config; source from auth.

---

### Phase 2: Per-Source Auth Model

**Scope:** Each source gets its own credentials; support API token and OAuth; rotatable/deletable.

| Task | Description | Files |
|------|-------------|-------|
| 2.1 | Design `source_credential` model (or extend SettingsKV schema) | `app/models/` |
| 2.2 | Migrate existing ingest keys to per-source credential model | migration |
| 2.3 | Extend `validate_key` to return source_id; require auth for ingest (no anonymous) | `app/core/ingest_auth.py` |
| 2.4 | Add OAuth client credentials: `POST /oauth/token`, token validation | `app/api/oauth.py`, `app/core/oauth.py` |
| 2.5 | Per-source: create API key, create OAuth client, rotate, revoke | `app/api/settings.py` |
| 2.6 | Settings UI: per-source credential management (create/rotate/revoke) | `frontend/` |

**OAuth scope:** Client credentials grant only. Token encodes source_id. Ingest validates token and uses source_id for attribution.

---

### Phase 3: Trivy Parser ✅

**Scope:** First tool parser; establishes patterns for others.

| Task | Description | Files |
|------|-------------|-------|
| 3.1 | Implement `TrivyParser` | `app/parsers/trivy.py` |
| 3.2 | Handle Trivy JSON schema (Results[].Vulnerabilities, Misconfigurations, Secrets, Licenses) | `app/parsers/trivy.py` |
| 3.3 | Map severity: CRITICAL→Critical, HIGH→High, etc. | `app/parsers/trivy.py` |
| 3.4 | Register Trivy in parser registry | `app/parsers/__init__.py` |
| 3.5 | Unit tests with sample Trivy JSON | `tests/test_trivy_parser.py` |

**Trivy JSON structure (reference):**
- `Results[]` with `Target`, `Class`, `Type`
- `Vulnerabilities[]`: VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, Title, Description
- `Misconfigurations[]`: ID, Title, Severity, Message
- `Secrets[]`: RuleID, Category, Severity, Match
- `Licenses[]`: PkgName, Severity, Category

---

### Phase 4: Snyk Parser ✅

**Scope:** Snyk JSON format (single-project and all-projects).

| Task | Description | Files |
|------|-------------|-------|
| 4.1 | Implement `SnykParser` | `app/parsers/snyk.py` |
| 4.2 | Support `vulnerabilities[]` and `vulnerabilities` (nested) | `app/parsers/snyk.py` |
| 4.3 | Map package, version, id, title, severity, cvssScore | `app/parsers/snyk.py` |
| 4.4 | Register Snyk in parser registry | `app/parsers/__init__.py` |
| 4.5 | Unit tests | `tests/test_snyk_parser.py` |

---

### Phase 5: Semgrep Parser ✅

**Scope:** Semgrep JSON output (`semgrep scan --json`).

| Task | Description | Files |
|------|-------------|-------|
| 5.1 | Implement `SemgrepParser` | `app/parsers/semgrep.py` |
| 5.2 | Parse `results[]`: check_id, path, start.line, extra.message, extra.severity | `app/parsers/semgrep.py` |
| 5.3 | Set finding_type=SAST | `app/parsers/semgrep.py` |
| 5.4 | Register Semgrep in parser registry | `app/parsers/__init__.py` |
| 5.5 | Unit tests | `tests/test_semgrep_parser.py` |

---

### Phase 6: Gitleaks Parser ✅

**Scope:** Gitleaks JSON report (secrets).

| Task | Description | Files |
|------|-------------|-------|
| 6.1 | Implement `GitleaksParser` | `app/parsers/gitleaks.py` |
| 6.2 | Parse findings: RuleID, Description, Secret, File, StartLine, Entropy | `app/parsers/gitleaks.py` |
| 6.3 | Set finding_type=Secret, severity from rule metadata or default High | `app/parsers/gitleaks.py` |
| 6.4 | Register Gitleaks in parser registry | `app/parsers/__init__.py` |
| 6.5 | Unit tests | `tests/test_gitleaks_parser.py` |

---

### Phase 7: Settings & Frontend ✅

**Scope:** 1:1 source model; Manual source config with parser dropdown; per-source credentials.

| Task | Description | Files |
|------|-------------|-------|
| 7.1 | **1:1 mapping:** Remove "add another push source". Each new source = full manual integration setup. Add source → pick Trivy/Snyk/etc. → creates distinct source entry | `frontend/components/settings/PushSourcesSettings.tsx`, `IntegrationCanvas.tsx` |
| 7.2 | Add parser dropdown/search to Manual source config UI | `frontend/` |
| 7.3 | Parser options: Trivy, Snyk, Semgrep, Gitleaks, SARIF, Canonical (from API or constant) | `frontend/lib/constants.ts` or API |
| 7.4 | Per-source credential cards — Create API key | Create OAuth client | Rotate | Revoke | `frontend/` |
| 7.5 | Document: add source → pick parser → full setup → use in CI | docs |

---

### Phase 8: Documentation ✅

**Scope:** User-facing docs for CI integration.

| Task | Description | Files |
|------|-------------|-------|
| 8.1 | Add `docs/manual-sources.md`: overview, auth (API key + OAuth), single endpoint, CI examples | `docs/manual-sources.md` |
| 8.2 | Per-tool: command to generate report, curl to `POST /api/ingest` (body or file) | `docs/manual-sources.md` |
| 8.3 | Update VAT-PRD or design doc | `docs/VAT-PRD.md` |

**Example CI snippet (Trivy):**
```bash
trivy image --format json -o trivy.json myimage:latest
curl -X POST "https://vat.example.com/api/ingest" \
  -H "X-VAT-API-Key: $VAT_TRIVY_KEY" \
  -F "file=@trivy.json"
# Source (trivy-ci) configured with parser=Trivy in Settings; VAT uses TrivyParser
```

---

## 6. File Summary

| Path | Action |
|------|--------|
| `backend/app/parsers/base.py` | No change (existing) |
| `backend/app/parsers/trivy.py` | Create |
| `backend/app/parsers/snyk.py` | Create |
| `backend/app/parsers/semgrep.py` | Create |
| `backend/app/parsers/gitleaks.py` | Create |
| `backend/app/parsers/__init__.py` | Update: export parsers, registry |
| `backend/app/api/ingest.py` | Update: single endpoint, parser from source config, `_ingest_from_parser` |
| `backend/app/core/ingest_auth.py` | Update: require auth for ingest; source from key |
| `backend/app/core/oauth.py` | Create — token issuance, validation |
| `backend/app/api/oauth.py` | Create — `POST /oauth/token` |
| `backend/app/models/source_credential.py` | Create (optional; or extend SettingsKV) |
| `backend/app/schemas/vat.py` | No change |
| `backend/tests/parsers/test_trivy.py` | Create |
| `backend/tests/parsers/test_snyk.py` | Create |
| `backend/tests/parsers/test_semgrep.py` | Create |
| `backend/tests/parsers/test_gitleaks.py` | Create |
| `frontend/lib/constants.ts` | MANUAL_SOURCES |
| `frontend/` (Settings) | Per-source credential UI |
| `docs/manual-sources.md` | Create |

---

## 7. Dependencies

- No new Python packages for parsers
- OAuth: `python-jose`, `passlib`, or `authlib` (if not already present)
- Existing: FastAPI, Pydantic, SQLAlchemy, ingest service

---

## 8. Risks & Mitigations

| Risk | Mitigation |
|------|-------------|
| Wrong parser for source | Parser configured explicitly in Settings; user selects when creating source |
| Tool JSON schema changes | Defensive parsing; unit tests with real samples |
| Large file uploads | Existing file size limits; consider streaming |
| OAuth complexity | Phase OAuth after API token; API token sufficient for v1 |

---

## 9. Success Criteria

- [x] Single `POST /api/ingest`; accepts JSON body or file upload
- [x] Parser from Manual source config (dropdown in Settings); VAT uses configured parser
- [x] 1:1 mapping: each new source requires full manual integration setup; no "add another push source"
- [x] Per-source auth: API token per source, rotatable, deletable
- [x] OAuth client credentials supported
- [x] Findings appear with correct source attribution from auth
- [x] Deduplication works across re-imports and sources
- [x] CI examples documented (`docs/manual-sources.md`)
- [x] Unit tests for each parser

---

## 10. Future Extensions

- **Phase 9+:** Add dedicated parsers for Checkov, Tfsec, Bandit
- **Bulk file:** Accept zip of multiple reports, route by filename or content detection

---

## 11. Binary Package Scanners (Added)

**Parsers added for binary/package ecosystem scanners:**

| Parser | Tool | Format | Asset type |
|--------|------|--------|------------|
| **npm_audit** | npm audit | `npm audit --json` (v6 advisories, v7+ vulnerabilities) | package |
| **pip_audit** | pip-audit | `pip-audit --format json` (legacy array or dependencies) | package |
| **grype** | Grype | `grype -o json` (deb, rpm, apk, npm, pypi, etc.) | package |
| **cyclonedx** | CycloneDX SBOM | JSON with vulnerabilities (spec 1.4+) | package |

**CI examples:**
```bash
# npm
npm audit --json | curl -X POST "$VAT_URL/api/ingest" -H "X-VAT-API-Key: $KEY" -H "Content-Type: application/json" -d @-

# pip
pip-audit --format json | curl -X POST "$VAT_URL/api/ingest" -H "X-VAT-API-Key: $KEY" -H "Content-Type: application/json" -d @-

# grype (container, fs, sbom)
grype image:myimage:tag -o json | curl -X POST "$VAT_URL/api/ingest" -H "X-VAT-API-Key: $KEY" -H "Content-Type: application/json" -d @-

# cyclonedx (from Trivy, Syft, or other SBOM generators)
trivy image --format cyclonedx -o sbom.json myimage:tag
curl -X POST "$VAT_URL/api/ingest" -H "X-VAT-API-Key: $KEY" -F "file=@sbom.json"
```
