# Manual Sources — Push-Based Scanner Integration

VAT supports push-based ingestion from security scanners via a single API endpoint. Each Manual source is a distinct integration with its own parser and credentials. This document describes how to configure sources and integrate them into CI/CD pipelines.

---

## Overview

- **Single endpoint:** `POST /api/ingest` — accepts JSON body or file upload
- **Parser per source:** Each Manual source is configured with a parser (Trivy, Snyk, Semgrep, etc.). VAT uses the configured parser to convert tool output to findings.
- **1:1 mapping:** Each push source (e.g. Trivy CI, Snyk Prod) is a separate Manual integration with full setup — name, parser, credentials.
- **Auth required:** API key or OAuth client credentials. No anonymous ingest.

---

## Authentication

### API Token

Use `Authorization: Bearer <token>` or `X-VAT-API-Key: <token>`.

1. In VAT Settings → Integrations → Manual, add a source and select the parser.
2. Save the source (set Source ID).
3. Create an API key for that source.
4. Store the key securely (e.g. CI secret). The key is shown only once.

### OAuth Client Credentials

For programmatic ingest with OAuth:

1. Create an OAuth client for the source in Settings.
2. Exchange `client_id` and `client_secret` for an access token:

```bash
curl -X POST "$VAT_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET"
```

3. Use the returned `access_token` in `Authorization: Bearer <token>` for ingest.

---

## Endpoint

| Method | Endpoint | Auth | Body |
|--------|----------|------|------|
| POST | `/api/ingest` | Bearer token or X-VAT-API-Key | JSON body or `multipart/form-data` with `file` field |

**Response:** `{ "created": N, "merged": M, "source": "<source_id>", "message": "..." }`

---

## Supported Parsers

| Parser | Tool | Input format | Finding types |
|--------|------|--------------|---------------|
| **trivy** | Trivy | JSON (vulns, secrets, licenses, misconfig) | CVE, Secret, License, IaC |
| **snyk** | Snyk | JSON | CVE |
| **semgrep** | Semgrep | `semgrep scan --json` | SAST |
| **gitleaks** | Gitleaks | JSON | Secret |
| **npm_audit** | npm audit | `npm audit --json` (v6 or v7+) | CVE |
| **pip_audit** | pip-audit | `pip-audit --format json` | CVE |
| **grype** | Grype | `grype -o json` | CVE |
| **cyclonedx** | CycloneDX SBOM | JSON with vulnerabilities (1.4+) | CVE |
| **sarif** | SARIF 2.1.0 | SARIF JSON | varies |
| **canonical** | Direct VAT | `{ "findings": [...] }` | varies |

---

## CI Integration Examples

Replace `$VAT_URL` with your VAT instance URL (e.g. `https://vat.example.com`) and `$KEY` with your API key or Bearer token.

### Trivy (container, filesystem, SBOM)

```bash
trivy image --format json -o trivy.json myimage:latest
curl -X POST "$VAT_URL/api/ingest" \
  -H "X-VAT-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d @trivy.json
```

Or with file upload:

```bash
trivy image --format json -o trivy.json myimage:latest
curl -X POST "$VAT_URL/api/ingest" \
  -H "X-VAT-API-Key: $KEY" \
  -F "file=@trivy.json"
```

### Snyk

```bash
snyk test --json > snyk.json 2>/dev/null || true
curl -X POST "$VAT_URL/api/ingest" \
  -H "X-VAT-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d @snyk.json
```

### Semgrep

```bash
semgrep scan --json -o semgrep.json .
curl -X POST "$VAT_URL/api/ingest" \
  -H "X-VAT-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d @semgrep.json
```

### Gitleaks

```bash
gitleaks detect --no-git --report-format json --report-path gitleaks.json 2>/dev/null || true
curl -X POST "$VAT_URL/api/ingest" \
  -H "X-VAT-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d @gitleaks.json
```

### npm audit

```bash
npm audit --json > npm-audit.json 2>/dev/null || true
curl -X POST "$VAT_URL/api/ingest" \
  -H "X-VAT-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d @npm-audit.json
```

### pip-audit

```bash
pip-audit --format json > pip-audit.json 2>/dev/null || true
curl -X POST "$VAT_URL/api/ingest" \
  -H "X-VAT-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d @pip-audit.json
```

### Grype (container, filesystem, SBOM)

```bash
grype image:myimage:tag -o json > grype.json
curl -X POST "$VAT_URL/api/ingest" \
  -H "X-VAT-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d @grype.json
```

### CycloneDX

```bash
trivy image --format cyclonedx -o sbom.json myimage:tag
curl -X POST "$VAT_URL/api/ingest" \
  -H "X-VAT-API-Key: $KEY" \
  -F "file=@sbom.json"
```

Or with Syft:

```bash
syft image:myimage:tag -o cyclonedx-json > sbom.json
curl -X POST "$VAT_URL/api/ingest" \
  -H "X-VAT-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d @sbom.json
```

---

## Setup Checklist

1. **Add source:** Settings → Integrations → Add source → Manual
2. **Configure:** Name (e.g. "Trivy CI"), set Source ID, select parser (e.g. Trivy)
3. **Create credentials:** Create API key or OAuth client for the source
4. **Use in CI:** Store the key as a secret; use the curl examples above in your pipeline

---

## Deduplication

Findings are deduplicated by fingerprint (CVE + component). Re-importing the same report merges into existing findings and appends the source attribution. No duplicate findings are created.
