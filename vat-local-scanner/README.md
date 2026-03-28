# VAT Local Scanner

Standalone CLI that runs security scans locally (Trivy, Grype, Semgrep, npm audit, pip-audit) and pushes **only findings** to VAT. No source code leaves your environment.

**Docker image includes:** Trivy, Grype, Semgrep (35+ languages, GA + experimental), Gitleaks, npm, pip-audit, Docker CLI, skopeo (for STIG scans on OCI layouts).

## Quick Start

```bash
# Install (requires Trivy, Grype, etc. on host)
pip install -e .

# Dry run (scan only, no push)
vat-scan scan /path/to/repo --dry-run

# Scan and push to VAT
export VAT_URL=https://vat.example.com
export VAT_ADMIN_TOKEN=<admin API key or JWT from VAT Settings → Access>
vat-scan scan /path/to/repo --asset my-repo

# Scan multiple folders with one command (e.g. one Docker mount)
vat-scan scan /workspace/repo1 /workspace/repo2 /workspace/repo3

# Scan archives without manual extraction (extracts to temp, scans, deletes)
vat-scan scan-archive repo.zip project.tar.gz --dry-run
vat-scan scan-archive /workspace/artifacts/bundle.tar.gz --asset my-bundle
```

## Backend correlation / ingest regression

VAT’s backend includes **reproducible** integration tests that exercise the same parsers (Trivy, Grype, Gitleaks) and source naming patterns as this CLI (`vat-local-trivy`, `vat-local-grype`, …). See `../backend/tests/integration/README.md` and golden fixtures under `../backend/tests/integration/fixtures/correlation/`.

## Commands

| Command | Description |
|---------|-------------|
| `vat-scan scan <path>` | Scan folder(s) and push findings to VAT |
| `vat-scan scan-archive <archive>` | Extract archive(s) to temp, scan, push, then delete |
| `vat-scan scan-image <image>` | Scan container image and push to VAT |
| `vat-scan config` | Show effective config |
| `vat-scan config-validate` | Validate config file schema |
| `vat-scan version` | Print version |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VAT_URL` | VAT instance URL |
| `VAT_API_KEY` | Ingest API key (optional if using admin token) |
| `VAT_ADMIN_TOKEN` | Admin API key or JWT for auto-creating sources (VAT Settings → Access) |
| `VAT_SCANNER_TEMP_DIR` | Temp directory for scanner output (default: /tmp) |

## Config File

Create `vat-scanner.yaml` or `.vat-scanner.yaml` in your repo root:

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
  - stig   # Chainguard GPOS STIG for container tarballs (DISA-aligned)
exclude:
  - "**/node_modules/**"
  - "**/dist/**"
scan_timeout_ms: 600000
disable_artifact_scanning: false
```

CLI flags override config.

## Docker

**Single folder:**
```bash
cd vat-local-scanner
docker build -t vat-scanner .
docker run -v $(pwd)/my-repo:/scan -e VAT_URL=... -e VAT_ADMIN_TOKEN=... vat-scanner scan /scan --asset my-repo
```

**Multiple folders with one mount** (no need to mount each folder separately):
```bash
# Mount parent dir, scan subfolders
docker run -v $(pwd)/repos:/scan -e VAT_URL=... -e VAT_ADMIN_TOKEN=... vat-scanner scan /scan/repo1 /scan/repo2 /scan/repo3
```

**From VAT repo root with docker-compose** (workspace is read-only; temp files go to /tmp):
```bash
# Scan a folder
docker compose --profile scanner run scanner scan /workspace/test/artifacts/2026-03-08_0429

# Scan multiple subfolders
docker compose --profile scanner run scanner scan /workspace/repo1 /workspace/repo2
```

The scanner mounts the project root at `/workspace` read-only. Use `--temp-dir` or `VAT_SCANNER_TEMP_DIR` to change where temp files are written (default: /tmp).

**STIG scans** (Chainguard GPOS STIG for containers) require Docker socket access. Mount it when using the scanner image:

```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/artifacts:/scan -e VAT_URL=... -e VAT_ADMIN_TOKEN=... \
  vat-scanner scan /scan --scan-types container,stig --asset my-images
```

Place container tarballs (`.tar` from `docker save`) or Helm/imgpkg bundles (outer `.tar` with `.wrap` files containing OCI image layouts) in the scan path. The scanner discovers images in both formats, loads each into Docker (via `docker load` or `skopeo copy oci:... docker-daemon:...`), and runs the Chainguard OpenSCAP STIG profile against it. See `docs/container-scan-nested-helm-research.md` for details.

## Gating (CI)

Fail the build when findings exceed a severity threshold:

```bash
vat-scan scan . --gating-mode pr --fail-on high \
  --base-commit-id $BASE_SHA --head-commit-id $HEAD_SHA \
  --gating-result-output gating-result.json
```

Exit code 1 when any finding >= `--fail-on` (low|medium|high|critical). PR mode filters to findings in changed files only.

## Performance Baseline

Use repeatable dry-run timings before/after changes:

```bash
# Small repo
time vat-scan scan /workspace/small-repo --dry-run --scan-types dependencies,secrets

# Medium repo with container artifacts
time vat-scan scan /workspace/medium-repo --dry-run --scan-types container,dependencies,secrets --verbose

# Large repo (full profile)
time vat-scan scan /workspace/large-repo --dry-run --scan-types code,dependencies,secrets,iac,license,container --verbose
```

With `--verbose`, scanner phase totals include:
- container discovery duration
- per-phase totals (`trivy_fs`, `trivy_container`, `trivy_cyclonedx`, etc.)
- per-item timing summaries for container phases
- Trivy CycloneDX mode counters (`--input` success vs fallback paths)

## Incremental Ingest Sessions

Single-path scans now push parser outputs incrementally while scanning and attach session metadata headers:
- `X-VAT-Scan-Id`
- `X-VAT-Scan-Status` (`running`, `completed`, `failed`)
- `X-VAT-Idempotency-Key`

This enables progressive visibility in VAT and idempotent retries for long-running scans.

## SARIF Output

Write findings to SARIF 2.1.0 format for downstream tooling (GitHub Code Scanning, VS Code, etc.):

```bash
vat-scan scan . --sarif-output results.sarif.json
vat-scan scan-image myimage:v1 --sarif-output image-results.sarif.json
```

Each result includes **`partialFingerprints`** with `primaryLocationLineHash/v1` (deterministic from rule id + artifact URI + line) so the file aligns with VAT’s SARIF ingest and fingerprint precedence if you re-upload it to VAT with the `sarif` parser. Normal VAT ingest from this CLI still uses native scanner JSON/XML, not this export.

## CI Templates

See `ci/` for ready-to-use templates:

- `ci/github-actions.yml` — GitHub Actions
- `ci/gitlab-ci.yml` — GitLab CI
- `ci/Jenkinsfile` — Jenkins Pipeline
- `ci/azure-pipelines.yml` — Azure DevOps

## License

MIT
