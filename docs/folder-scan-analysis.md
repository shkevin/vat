# VAT Folder Scan & Push — Analysis

## Executive Summary

VAT has **parsers** for scanner output (Trivy, Grype, Semgrep, Gitleaks, etc.) but **no built-in scanners**. The ingest flow expects JSON reports from external tools. This document analyzes your existing setup and outlines what is needed for a script that scans a folder and pushes findings to VAT as a single asset.

---

## 1. Existing VAT Scanners (Parsers)

VAT does not run scanners; it **parses** JSON output from tools. Your parser registry:

| Parser | Tool | Input | Finding Types | Best For |
|--------|------|-------|---------------|----------|
| **trivy** | Trivy | `trivy fs/image/sbom ... -o json` | SCA, Secret, IaC, License | Filesystem, container, SBOM |
| **grype** | Grype | `grype dir:/path -o json` | SCA | RPM, deb, apk, npm, pypi |
| **semgrep** | Semgrep | `semgrep scan --json` | SAST | Code (JS, Python, etc.) |
| **gitleaks** | Gitleaks | `gitleaks detect --report-format json` | Secret | Repos, secrets |
| **npm_audit** | npm | `npm audit --json` | SCA | Node.js |
| **pip_audit** | pip-audit | `pip-audit --format json` | SCA | Python |
| **cyclonedx** | CycloneDX | SBOM JSON | SCA | SBOM with vulns |
| **sarif** | SARIF 2.1.0 | SARIF JSON | varies | Any SARIF tool |
| **canonical** | Direct | `{ "findings": [...] }` | varies | Custom payloads |

---

## 2. Test Artifacts Review

From `test/artifacts/2026-03-08_0429/`:

| File | Type | Scanner Coverage |
|------|------|------------------|
| `release_origination.md` | Markdown | Trivy (secrets), Gitleaks (secrets) |
| `kamiwaza-tools-rpm.private.gpg` | GPG key | Trivy (secrets) |
| `kamiwaza-tools-rpm.pub.gpg` | GPG pub key | Trivy (secrets) |
| `kamiwaza-helm.asc` | ASCII armor | Trivy (secrets) |
| `kamiwaza-helm.sha256` | Checksum | Trivy (secrets) |

**Note:** `release_origination.md` references `kamiwaza-prod-0.0.19b5a22-1.el9.x86_64.rpm` but the RPM is not in this folder. If you add RPMs, Grype/Trivy can scan them.

---

## 3. File Type → Scanner Mapping

| File Type | Recommended Scanner | Parser | Notes |
|-----------|---------------------|--------|-------|
| **.rpm** | Grype `dir:/path` | grype | Best RPM support |
| **.rpm** | Trivy fs (experimental) | trivy | `TRIVY_EXPERIMENTAL_RPM_ARCHIVE=true` |
| **.html** | Trivy fs | trivy | Secrets only; no HTML vuln scanner |
| **.txt, .md** | Trivy fs, Gitleaks | trivy, gitleaks | Secrets |
| **.py, .js, .ts, .go** | Semgrep | semgrep | SAST |
| **.sh, .bash, .zsh** | Trivy fs, Gitleaks, Semgrep | trivy, gitleaks, semgrep | Secrets (Trivy/Gitleaks); SAST (Semgrep bash rules) |
| **package.json, requirements.txt** | npm/pip audit | npm_audit, pip_audit | Lockfile-based |
| **GPG, .asc, .sha256** | Trivy fs | trivy | Secrets (keys, tokens) |

---

## 4. Gaps & Recommendations

### 4.1 What You Have

- **Parsers:** Trivy, Grype, Semgrep, Gitleaks, npm_audit, pip_audit, CycloneDX, SARIF, canonical
- **Ingest API:** `POST /api/ingest` with Bearer token or `X-VAT-API-Key`
- **Asset model:** Findings grouped by `image` or `component`; assets derived from findings
- **Source config:** Parser per Manual source; API key per source

### 4.2 What You Need for Folder Scan

1. **CLI script** that:
   - Accepts folder path
   - Runs appropriate scanners (Trivy, Grype, etc.)
   - Normalizes asset name (single asset per folder)
   - Uploads JSON to VAT via `POST /api/ingest`

2. **Asset normalization:** Trivy uses `Target` (path) as asset; Grype uses `source.target`. For a single asset per folder, the script should rewrite these to a consistent name (e.g. folder basename) before upload.

3. **Manual source setup:** Create a Manual source in VAT Settings with parser `trivy` (or `grype`) and an API key.

### 4.3 HTML / Text Files

- **No HTML vulnerability scanner** in VAT parsers. HTML is typically not scanned for XSS by Trivy/Grype.
- **Secrets:** Trivy and Gitleaks can scan HTML/text for hardcoded secrets.
- **SAST:** Semgrep can scan embedded JS in HTML if configured.
- **Shell scripts (.sh, .bash, .zsh):** Trivy and Gitleaks scan for secrets. Semgrep has bash/shell rules for unsafe patterns (e.g. `curl | bash`, variable splitting).

### 4.4 Asset Creation & Type

- **No public API** to create `Asset` records. Assets are created by integrations (e.g. Aikido) or derived from findings.
- **For folder scan:** Findings create a derived asset. Set **Asset type** to **Package** in the Manual source config (Settings → Integrations → your source) so VAT infers `package` instead of `container`.
- **Asset type options:** Auto (infer), Package (folder/bundle), Container, Repo. Use Package for folder scans.

---

## 5. Script Design

### 5.1 Flow

```
[Folder] → Run Trivy fs (vuln, secret, license, misconfig) — covers .sh, .html, .txt, .md, etc.
         → Run Grype dir (if .rpm present)
         → Optionally run Gitleaks (secrets), Semgrep (SAST for .sh, .py, .js, etc.)
         → Normalize asset name in JSON (jq)
         → POST /api/ingest (Trivy report)
         → POST /api/ingest (Grype report, if any)
```

### 5.2 Asset Override

Use `jq` to replace `Target` (Trivy) or `source.target` (Grype) with a normalized asset name (e.g. `folder-basename` or `custom-name`).

### 5.3 Prerequisites

- `trivy` installed
- `grype` installed (optional, for RPM)
- `jq` for JSON transform
- `curl` for HTTP
- VAT Manual source with API key and parser configured

---

## 6. Script Usage

### VAT Local Scanner (recommended — decoupled)

The **VAT Local Scanner** (`vat-local-scanner/`) is a standalone CLI that replaces/enhances the legacy script. It is decoupled from the VAT backend/frontend:

```bash
pip install -e vat-local-scanner/
vat-scan scan <folder> [--asset NAME] [--dry-run] [--scan-types code,dependencies,secrets,iac,license,container]
```

See `vat-local-scanner/README.md` and `docs/PRD-vat-local-scanner.md`.

### Python script (legacy)

The Python script auto-creates Manual source integrations per parser if they don't exist:

```bash
python scripts/scan_folder_and_push.py <folder> [--asset NAME] [--dry-run] [--reset-keys]
```

**Env:** `VAT_URL`, `VAT_ADMIN_TOKEN` (admin JWT from login, or admin API key from Settings → Access → Admin API keys)

**Flow:**
1. Scans folder with Trivy (and Grype if RPMs present)
2. Calls `POST /api/settings/sources/manual/ensure` for each parser needed
3. Caches API keys in `~/.config/vat/scanner-keys.json`
4. Pushes reports to VAT (one source per parser: folder-scan-trivy, folder-scan-grype)

**Examples:**

```bash
# Dry run (scan only)
python scripts/scan_folder_and_push.py test/artifacts/2026-03-08_0429 --dry-run

# Scan and push (auto-creates sources + keys on first run)
export VAT_URL=https://vat.example.com
export VAT_ADMIN_TOKEN=<admin JWT or admin API key from Settings>
python scripts/scan_folder_and_push.py test/artifacts/2026-03-08_0429 --asset kamiwaza-release

# Regenerate API keys (e.g. after key was revoked)
python scripts/scan_folder_and_push.py /path/to/folder --reset-keys

# Docker (scanner image has trivy, grype, npm, pip-audit)
# Start VAT first: docker compose up -d
docker compose --profile scanner run -v $(pwd)/my-folder:/scan -e VAT_ADMIN_TOKEN=xxx scanner /scan --asset my-asset
```

### Bash script (legacy)

```bash
./scripts/scan-folder-and-push.sh <folder> [--asset NAME] [--dry-run]
```

Requires manual source setup and `VAT_API_KEY` (and `VAT_GRYPE_API_KEY` for RPM).

---

## 7. API: Ensure Manual Source

`POST /api/settings/sources/manual/ensure` (admin only)

Creates a Manual source for a parser if it doesn't exist. 1:1 mapping: one source per parser.

**Body:** `{ "parser": "trivy", "sourceIdPrefix": "folder-scan", "assetType": "package", "createKey": true, "regenerateKey": false }`

**Response:** `{ "sourceId": "folder-scan-trivy", "created": true, "key": "vat_..." }` — key only when creating or regenerating.

---

## 8. Checklist Before Running

**Python script (recommended):**
- [ ] Install `trivy` (and `grype` for RPM scanning)
- [ ] Set `VAT_URL` and `VAT_ADMIN_TOKEN` (admin JWT or admin API key from Settings → Access)
- [ ] First run auto-creates sources and caches keys

**Bash script (manual setup):**
- [ ] Create Manual source(s) in VAT Settings
- [ ] Set parser and Asset type to Package
- [ ] Create API key(s)
- [ ] Set `VAT_URL`, `VAT_API_KEY` (and `VAT_GRYPE_API_KEY` for RPM)
