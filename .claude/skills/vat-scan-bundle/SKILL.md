---
name: vat-scan-bundle
description: Scan a Kamiwaza offline release bundle (.tar.gz of helm/extension images + RPM) with vat-scanner and push findings to VAT. Use when asked to scan an offline bundle, run a release/STIG/dependency scan of a kamiwaza-* bundle, or "scan this bundle into VAT".
---

# VAT — Scan an Offline Bundle

Prepares a Kamiwaza offline bundle for `vat-scanner` and pushes findings to the live VAT
instance. A helper script (`scan-bundle.sh`) automates the whole flow; this doc explains the
decisions and the non-obvious gotchas it handles.

## Quick start

```bash
cd /home/shkevin/code/compliance/vat
VAT_ADMIN_TOKEN='vat_…' \
  .claude/skills/vat-scan-bundle/scan-bundle.sh ./2026-04-13-1250.tar.gz
```

Defaults: `--scan-types code,dependencies,container,stig`, `--asset kamiwaza-bundle`, tag auto-derived
from `release_origination.md`, endpoint auto-discovered (LB VIP preferred — see below), `--reset-keys` on.
The scan runs in the foreground and is **multi-hour** for full image scope — launch it with
`run_in_background: true` and tail the log.

## What the script does (and why)

1. **Picks a reachable VAT endpoint — probed from INSIDE the scanner container.**
   Order: explicit `--vat-url`/`$VAT_URL` → **LB VIP** → NodePort fallback.
   *Why probe from the container, and VIP first:* the scan runs in a container. On
   WSL2/Docker-Desktop the **host** can reach the NodePort node IPs `<node-ip>/61/62:<nodePort>`
   but the **container cannot** (Docker's network is the Docker VM, not the WSL2 distro) — even
   `--network host` fails. A host-side probe would pick a NodePort the scan can't reach, dying at
   `Ensure source failed: [Errno 113] No route to host`. The LB VIP `<lb-vip>:3000` IS
   container-reachable, so `try_url` runs the probe in the scanner image and prefers the VIP.
   See `[[scanner-container-reaches-vip-not-nodeport]]`.
2. **Extracts the bundle and nested archives.** Top tarball → extensions `.tar.gz`,
   RPM payload (`rpm2cpio | cpio`), helm `.tar`. The scanner only descends **one level** into
   archives, so nested content must be pre-extracted or its code/deps are invisible.
3. **Flattens container-image tars to a shallow `_images/` dir.** This is the critical gotcha:
   `collect_container_sources` uses `rglob("*.tar")` with **`max_depth=3`** relative to the scan
   root. Extension image tars live ~9 levels deep (`.../repos/<ext>/registry/garden/v3/docker-images/*.tar`)
   and would be **silently skipped** — no STIG/container findings. Flattening to `_images/<name>.tar`
   (depth 2) makes them discoverable. Helm `.tar` stays at root (depth 1); the scanner auto-extracts
   its `.wrap` bundles and finds the OCI layouts inside.
4. **Verifies checksums** (best-effort; the helm `.sha256` references the un-split `kamiwaza-helm.tar`
   name, so verify the hash value, not the filename).
5. **Derives the tag** from `offline_app_image_tag: release-X.Y.Z` → `vX.Y.Z`.
6. **Runs the scan** with the same mounts as the manual command (`$PWD:/workspace:ro`,
   docker.sock, `/tmp`) and pushes to VAT.

## Scan types — important

- `code` → semgrep + gitleaks over source files (RPM payload, extension repo source).
- `dependencies` → CycloneDX **SBOM** per image (components + **License** findings, **NOT CVEs**) plus
  grype over the *filesystem* (finds little — deps live inside the images).
- `container` → **trivy image per tar = per-image CVE vulnerability findings.** This is the ONLY
  scan-type that yields container CVEs; `dependencies` alone gives an SBOM but zero CVEs. Include it
  for any real release/vuln scan (it's in the default set).
- `stig` → OpenSCAP per image (DISA STIG). Runs **only on container images**; distroless/chainguard
  images legitimately yield 0. No images in scope ⇒ zero STIG findings.

So `--image-scope` controls coverage vs. time:

| `--image-scope` | What runs | Time |
|---|---|---|
| `all` (default) | core helm images + extension images; STIG over everything | multi-hour |
| `extensions` | extension images only (skips the 9 GB+ core helm `.tar`) | ~30–60 min |
| `none` | source-only; **drops STIG** | minutes |

For a real STIG/release scan use `all`. Use `none` only when the caller just wants code/dependency
findings fast.

## Decisions to confirm with the user before a long run

- **Image scope** (above) — the time/coverage tradeoff. Default `all`.
- `--reset-keys` rotates the asset's scan key (on by default, matches the established workflow).
- **Incremental push:** each parser pushes to VAT the moment it completes (`scan_status=running`),
  not only at the end — so a mid-run crash KEEPS everything already pushed. To recover, re-run with
  only the scan-types that hadn't pushed (e.g. drop `stig` if STIG already landed).
  See `[[scanner-scan-types-and-incremental-resume]]`.

## Verifying it's working

- `docker ps --filter ancestor=vat-scanner:latest` → container `Up`.
- Tail the log for `→ STIG i/N` and `→ Trivy i/N` per-image progress, then
  `Pushing to VAT…` and `Done. Asset(s): kamiwaza-bundle` at the end. `container` scans push the
  merged trivy report in batches (20 Results/POST) to stay under the ingest timeout — a single giant
  POST hits `ClientDisconnect` → HTTP 500.
- Confirm in VAT: `GET /api/findings?asset=kamiwaza-bundle&tag=vX.Y.Z` via the selected endpoint.
  All images roll up under the single `kamiwaza-bundle` asset (single mode); each finding records
  its source image as provenance (`componentBase`/`file_path`). Use `--asset-mode multi` for one
  asset per image instead.

## Cleanup

The prepared scan tree (`artifacts/<asset>-<tag>/`) is retained after the run (tens of GB).
Remove it to reclaim disk once findings are confirmed in VAT.

## Related

- `[[scanner-container-reaches-vip-not-nodeport]]` — why the scanner container reaches the VIP, not NodePort.
- `[[scanner-scan-types-and-incremental-resume]]` — scan-type semantics, incremental push / crash recovery, the docker-load + ingest-batching fixes.
- `[[reference_vat_access_topology]]` — endpoints (HOST access; opposite of the container case above).
- `[[feedback_use_k8s_not_compose]]` — verify against the live cluster, not docker compose.
- Scanner source: `vat-local-scanner/vat_scanner/` (`scan.py`, `cli.py`, `scanners/runners.py`).
