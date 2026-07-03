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

Defaults: `--scan-types code,dependencies,stig`, `--asset kamiwaza-bundle`, tag auto-derived
from `release_origination.md`, endpoint auto-discovered (NodePort preferred), `--reset-keys` on.
The scan runs in the foreground and is **multi-hour** for full image scope — launch it with
`run_in_background: true` and tail the log.

## What the script does (and why)

1. **Picks a reachable VAT endpoint.** Probes `/api/findings` with the token. Order:
   explicit `--vat-url`/`$VAT_URL` → **NodePort on each node IP** → LB external IP.
   *Why NodePort first:* the frontend LoadBalancer **VIP `10.0.40.173:3000` is flaky** —
   it has gone fully connection-refused mid-session while the cluster stayed healthy
   (VIP failover / stale ARP). NodePort `:<nodePort>` on `10.0.40.60/61/62` is stable.
   See `[[reference_vat_access_topology]]`.
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

- `code` → semgrep over source files (RPM payload, extension repo source).
- `dependencies` → grype over the filesystem **and** over container images.
- `stig` → OpenSCAP, runs **only on container images**. No images in scope ⇒ **zero STIG findings**.

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
- Findings push **only at the end**; nothing partial lands in VAT if it's interrupted.

## Verifying it's working

- `docker ps --filter ancestor=vat-scanner:latest` → container `Up`.
- Tail the log for `→ STIG i/N` and `→ Trivy i/N` per-image progress, then
  `Pushing to VAT…` and `pushed (N created, M merged)` at the end.
- Confirm in VAT: `GET /api/findings?asset=kamiwaza-bundle&tag=vX.Y.Z` via the selected endpoint.

## Cleanup

The prepared scan tree (`artifacts/<asset>-<tag>/`) is retained after the run (tens of GB).
Remove it to reclaim disk once findings are confirmed in VAT.

## Related

- `[[reference_vat_access_topology]]` — endpoints / why the VIP 502s and flakes.
- `[[feedback_use_k8s_not_compose]]` — verify against the live cluster, not docker compose.
- Scanner source: `vat-local-scanner/vat_scanner/` (`scan.py`, `scanners/detection.py`).
