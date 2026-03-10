# VAT Local Scanner — Product Requirements Document

| | |
|---|---|
| **Version** | 1.0 — Draft |
| **Date** | March 2026 |
| **Status** | Draft |
| **Classification** | Internal |

---

## 1. Executive Summary

### Problem Statement

Organizations with strict data residency (DFARS, FISMA, FedRAMP, HIPAA) cannot send source code to cloud-based scanners. VAT today ingests findings from external tools, but teams must manually run Trivy, Grype, Semgrep, etc., and stitch results together. There is no single, decoupled local scanner that runs entirely on-prem and pushes only findings to VAT.

### Proposed Solution

**VAT Local Scanner** — a standalone CLI tool that runs security scans locally (code, dependencies, secrets, IaC, containers) and pushes only findings to VAT. No source code leaves the customer environment. Modeled after [Aikido's Local Scanner](https://aikido.dev/features/local-scanner): same coverage, same output format, fully decoupled from VAT backend.

### Success Criteria

| KPI | Target |
|-----|--------|
| Scan coverage parity | SAST, SCA, secrets, IaC, license, container — all supported |
| Data residency | Zero source code sent to VAT; only finding metadata |
| CI integration | Works in GitHub Actions, GitLab CI, Jenkins, Azure DevOps |
| Time to first scan | < 5 minutes from install to first push |
| Gating reliability | Exit code and JSON output for PR/release gating |

---

## 2. User Experience & Functionality

### 2.1 User Personas

| Persona | Goal | Pain Point |
|---------|------|-------------|
| **Security Engineer** | Run scans locally for compliance; push to VAT for triage | No unified local tool; manual scanner orchestration |
| **DevOps / Platform** | Integrate scanning into CI; gate PRs on severity | Scattered scanner configs; no single CLI |
| **Compliance / GRC** | Evidence that code never left premises | Cloud scanners violate data residency |

### 2.2 User Stories

**US-1: Local folder scan**
> As a security engineer, I want to run `vat-scan scan /path/to/repo` so that I can scan a folder locally and push findings to VAT without sending code.

- **AC:** Scans run locally; only JSON findings sent to VAT; supports `--dry-run` (no push)
- **AC:** Asset name configurable via `--asset` or derived from folder/repo name

**US-2: CI/CD integration**
> As a DevOps engineer, I want to add the scanner to my GitHub Action so that every PR is scanned and findings appear in VAT.

- **AC:** Works in GitHub Actions, GitLab CI, Jenkins, Azure DevOps
- **AC:** Configurable via env vars (`VAT_URL`, `VAT_API_KEY`, `VAT_ADMIN_TOKEN` for source creation)
- **AC:** Exit code 1 on configurable severity threshold for gating

**US-3: Gating mode**
> As a platform engineer, I want to run the scanner in gating mode so that I can fail the build when critical/high findings are introduced.

- **AC:** `--gating-mode release|pr` with `--fail-on low|medium|high|critical`
- **AC:** PR mode: `--base-commit-id` and `--head-commit-id` for diff-aware gating
- **AC:** `--gating-result-output <file>` writes JSON issues for downstream tooling

**US-4: Scan type selection**
> As a security engineer, I want to enable only specific scan types so that I can reduce noise and scan time.

- **AC:** `--scan-types code,dependencies,secrets,iac,license,container` (comma-separated)
- **AC:** Default: all applicable types based on content detection
- **AC:** `--disable-artifact-scanning` to skip Trivy rootfs for speed

**US-5: Exclusions**
> As a developer, I want to exclude paths from scanning so that third-party or generated code is not scanned.

- **AC:** `--exclude` (repeatable) for glob or path patterns
- **AC:** Respects `.vatignore` or `.vat-scanner-ignore` in repo root
- **AC:** Default excludes: `node_modules`, `.git`, `__pycache__`, `dist`, `build`, `.venv`

**US-6: Config file**
> As a team lead, I want to configure the scanner via a YAML/TOML file so that CI and local runs share the same settings.

- **AC:** `vat-scan scan` reads `vat-scanner.yaml` (or `.vat-scanner.yaml`) from repo root or `--config`
- **AC:** Config: `vat_url`, `asset`, `scan_types`, `exclude`, `fail_on`, `timeout`
- **AC:** CLI flags override config

**US-7: Container image scanning**
> As a platform engineer, I want to scan container images (including tarballs) so that image vulnerabilities appear in VAT.

- **AC:** `vat-scan scan /path` detects `*.tar` and runs Trivy image scan
- **AC:** `vat-scan scan-image <image-ref>` for direct image scanning (e.g. `myregistry/app:v1`)

**US-8: Self-contained distribution**
> As an operator, I want to run the scanner via Docker or a single binary so that I don't need to install Trivy, Grype, etc. manually.

- **AC:** Docker image with all scanner deps (Trivy, Grype, Semgrep, etc.)
- **AC:** Optional: standalone binary (e.g. Go/Rust) that bundles or downloads scanner binaries

### 2.3 Non-Goals (v1)

- **Cloud scanning:** Scanner is local-only; no VAT-hosted scanning
- **Reachability analysis:** No code flow analysis; out of scope for v1
- **Auto-remediation:** No automatic fix suggestions or PR generation
- **Real-time sync:** Push-only; no webhook or streaming from scanner to VAT
- **Multi-tenant scanner:** Single VAT instance per run; no org/project switching in CLI

---

## 3. Technical Specifications

### 3.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Customer Environment                          │
│  ┌─────────────┐    ┌──────────────────┐    ┌─────────────────┐ │
│  │  Repo/Folder│───▶│  VAT Local       │───▶│  HTTPS (443)    │ │
│  │  (no egress)│    │  Scanner (CLI)    │    │  VAT Ingest API │ │
│  └─────────────┘    │  - Trivy         │    └────────┬────────┘ │
│                     │  - Grype         │             │          │
│                     │  - Semgrep       │             │          │
│                     │  - Gitleaks      │             │          │
│                     │  - npm/pip audit │             │          │
│                     └──────────────────┘             │          │
└──────────────────────────────────────────────────────│──────────┘
                                                       │
                                                       ▼
                                            ┌─────────────────────┐
                                            │  VAT Backend        │
                                            │  (ingest only)      │
                                            │  - Parse JSON       │
                                            │  - Dedupe           │
                                            │  - Store findings   │
                                            └─────────────────────┘
```

**Data flow:**
1. User runs `vat-scan scan <path>` (or via CI)
2. Scanner runs Trivy, Grype, Semgrep, etc. locally; outputs JSON
3. Scanner normalizes output to VAT parser formats (Trivy, Grype, etc.)
4. Scanner POSTs to `VAT_URL/api/ingest` with `Authorization: Bearer <key>`
5. VAT parses, deduplicates, stores; no source code received

### 3.2 Scan Types & Parser Mapping

| Scan Type | Tool(s) | VAT Parser | Trigger Condition |
|-----------|---------|------------|-------------------|
| **code** | Semgrep | semgrep | `.py`, `.js`, `.ts`, `.go`, `.java`, `.rb`, etc. |
| **dependencies** | Grype, npm audit, pip-audit | grype, npm_audit, pip_audit | `package.json`, `requirements.txt`, lockfiles, `*.rpm` |
| **secrets** | Trivy, Gitleaks | trivy, gitleaks | All files (Trivy fs); git repo (Gitleaks) |
| **iac** | Trivy | trivy | `.tf`, `.yaml`, `.yml`, CloudFormation, etc. |
| **license** | Trivy | trivy | Lockfiles, `package.json` |
| **container** | Trivy image | trivy | `*.tar`, `--scan-image <ref>` |

### 3.3 CLI Design

```
vat-scan [global-opts] <command> [command-opts]

Commands:
  scan <path>           Scan folder and push to VAT
  scan-image <image>    Scan container image and push
  config                Validate and show effective config
  version               Print version

Global options:
  --config <file>       Config file path
  --vat-url <url>      VAT instance URL (env: VAT_URL)
  --api-key <key>       Ingest API key (env: VAT_API_KEY)
  --admin-token <tok>   Admin token for source creation (env: VAT_ADMIN_TOKEN)
  --debug               Verbose output

Scan options:
  --asset <name>       Asset name (default: path basename)
  --scan-types <list>  code,dependencies,secrets,iac,license,container
  --exclude <pattern>  Exclude path (repeatable)
  --dry-run            Scan only; do not push
  --gating-mode        release | pr
  --fail-on            low | medium | high | critical
  --gating-result-output <file>  JSON file for gating issues
  --base-commit-id     For PR gating
  --head-commit-id     For PR gating
  --scan-timeout <ms>  Timeout (default: 900000)
  --disable-artifact-scanning  Skip Trivy rootfs
  --reset-keys         Regenerate API keys for sources
```

### 3.4 Config File Schema (`vat-scanner.yaml`)

```yaml
vat_url: https://vat.example.com
asset: my-repo-name
scan_types:
  - code
  - dependencies
  - secrets
  - iac
  - license
  - container
exclude:
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/*.min.js"
gating:
  mode: pr  # or release
  fail_on: high
  base_commit_id: ${GITHUB_BASE_SHA}  # env var expansion
  head_commit_id: ${GITHUB_SHA}
scan_timeout_ms: 600000
disable_artifact_scanning: false
```

### 3.5 Integration with VAT Backend

- **Ingest API:** `POST /api/ingest` with `Authorization: Bearer <source_api_key>`
- **Ensure API:** `POST /api/settings/sources/manual/ensure` (admin) for auto-creating sources
- **Parsers:** Trivy, Grype, Semgrep, Gitleaks, npm_audit, pip_audit — all existing
- **Source ID prefix:** `vat-local` (e.g. `vat-local-trivy`, `vat-local-grype`)
- **Asset type:** Package (for folder scans); Container (for image scans)

### 3.6 Security & Privacy

| Concern | Mitigation |
|---------|------------|
| **Data residency** | No source code sent; only finding metadata (CVE, path, severity, snippet if configured) |
| **Secrets in findings** | Snippets may contain partial secrets; `--no-snippets` to omit |
| **API key storage** | Keys in env vars or config; support for `~/.config/vat/scanner-keys.json` cache |
| **Outbound only** | Scanner initiates HTTPS to VAT; no inbound listeners |

### 3.7 Distribution

| Format | Use Case |
|--------|----------|
| **Docker image** | CI, Kubernetes, air-gapped (image tar) |
| **Python package** | `pip install vat-scanner` — requires Trivy, Grype, etc. on host |
| **Standalone binary** | Future: single executable with embedded scanners |

---

## 4. Phased Rollout

### Phase 1 — MVP (8–10 weeks)

- CLI: `vat-scan scan <path>` with `--dry-run`, `--asset`, `--scan-types`, `--exclude`
- Scanners: Trivy fs, Grype, npm audit, pip-audit (Semgrep optional)
- Push to VAT via ingest API; auto-create sources via ensure API
- Docker image with all deps
- Config file support
- **Deliverable:** Replace/enhance `scan_folder_and_push.py`

### Phase 2 — Gating & CI (4–6 weeks)

- `--gating-mode`, `--fail-on`, `--gating-result-output`
- PR mode: `--base-commit-id`, `--head-commit-id` for diff-aware fail
- GitHub Action, GitLab CI template
- **Deliverable:** CI gating with VAT

### Phase 3 — Polish (4 weeks)

- `vat-scan scan-image <image>`
- Gitleaks integration
- `--no-snippets` for compliance
- Config validation command
- **Deliverable:** Full feature parity with PRD

### Phase 4 — Future

- Standalone binary (Go/Rust)
- SARIF output option
- Custom parser plugins

---

## 5. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Scanner version drift | Pin Trivy/Grype versions in Docker; document compatibility matrix |
| VAT parser changes | Scanner outputs standard formats (Trivy JSON, Grype JSON); VAT parsers are stable |
| Large repo scan time | `--scan-timeout`; `--disable-artifact-scanning`; exclude patterns |
| CI rate limits | Batch findings per run; VAT ingest is single POST per parser |
| Air-gapped deployment | Docker image tar; no external fetches at runtime |

---

## 6. References

- [Aikido Local Scanner](https://aikido.dev/features/local-scanner) — design inspiration
- [Aikido CLI Options](https://help.aikido.dev/doc/local-scanner-cli-options/) — CLI patterns
- [VAT PRD](VAT-PRD.md) — parent product
- [VAT Folder Scan Analysis](folder-scan-analysis.md) — current script design
- [VAT Manual Sources](manual-sources.md) — ingest and source config
