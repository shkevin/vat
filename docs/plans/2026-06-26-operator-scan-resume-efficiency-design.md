# Operator Scan Resume and Efficiency Design

## Goal

Make VAT operator scanning resilient to restarts, partial failures, and rotated ingest keys, while setting the direction for a more efficient single-agent scanner model.

## Current Problem

The operator publishes inventory snapshots, but scanner workers decide what to scan from local JSON state files. Those state files are mounted with `emptyDir`, so pod restarts lose progress. The image worker checkpoints per successful image, but the Kubernetes config worker only flushes state at the end of the whole run. The workers also commonly run with a static `VAT_API_KEY`; when parser keys rotate, they cannot self-heal and repeated ingest attempts fail with `401`.

This creates two user-visible failures:

- Missing or partial scans are retried only on the next long interval and cannot be checked against VAT as source of truth.
- A worker can appear alive while every ingest attempt is rejected.

## Phase 1: Durable Worker Resume

Implement immediately:

- Mount scanner worker state on persistent PVCs instead of `emptyDir`.
- Mount `VAT_ADMIN_TOKEN` for both scanner workers so they can ensure parser-specific ingest keys and recover from key rotation.
- Save Kubernetes object scan state after each successful object, matching image scan behavior.
- Seed `lastFullScanAt` after the first complete image/runtime pass so scheduled full rescans actually run.
- Keep local state as an optimization, not a correctness boundary.

## Phase 2: VAT-Side Scan Ledger

Add a backend scan ledger keyed by:

- `asset_id`
- `source_image` or image digest/ref
- `parser_id`
- `scan_type`
- inventory signature

Workers will ask VAT for missing or stale work before scanning and mark each parser result as `running`, `completed`, or `failed`. This allows partial completion: SCA can be committed while SBOM or STIG remains pending and retryable. The UI can then report scan coverage explicitly instead of inferring from findings.

## Phase 3: Efficient Single-Agent Model

Move toward a Twistlock/Defender-like shape:

- One compact cluster scanner worker owns both image inventory and Kubernetes config inventory loops.
- Node-local runtime and host scanning stays in the node-agent DaemonSet because it requires host sockets and filesystems.
- The process deduplicates images locally by digest and scan type.
- It sends normalized deltas and results to VAT, rather than splitting work across multiple shell loops.
- Heavy scanners remain internal runners with shared image/rootfs preparation and cache directories.

## Phase 3a: Cluster Worker Aggregation

Implemented as the next incremental slice:

- `vat-scanner-worker` runs two supervised loops in one container: image inventory scanning and Kubernetes config/RBAC scanning.
- `vat-config-worker` no longer renders in kustomize or Helm.
- The combined worker mounts both inventory ConfigMaps and writes separate state files under one durable worker state volume.
- `scanner.configWorker` Helm values remain as backward-compatible tuning knobs for the Kubernetes config lane.

## Accuracy Rules

- Bundle/release assets use the release tag as reviewer-facing version.
- Internal image digests remain evidence context, not bundle tag variants.
- A scan is complete only per scan type. Partial completion is valid and retryable.
- Local scanner state must never hide work that VAT has not acknowledged.

## Initial Verification

- Scanner unit tests cover state seeding and per-object checkpointing.
- Kubernetes manifests render with persistent worker state and admin-token env.
- Live operator credentials are refreshed after key rotation.
