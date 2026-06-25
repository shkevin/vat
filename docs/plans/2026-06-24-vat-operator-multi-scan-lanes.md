# VAT Operator Multi-Scan Lanes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expand the VAT Kubernetes operator from a Trivy-only image vulnerability lane into an all-on, bounded, multi-scan operator covering image SCA, SBOM, Kubernetes posture, RBAC posture, secrets/misconfiguration, and node/container OpenSCAP lanes.

**Architecture:** Keep the low-noise controller-plus-worker model. The operator publishes compact inventories into ConfigMaps; fixed workers consume those inventories with local state files so unchanged inputs are skipped, and expensive scan families run in isolated lanes with their own cadence and resource limits. Privileged node scanning remains a DaemonSet lane, not part of the normal image worker.

**Tech Stack:** Go controller-runtime-style operator using Kubernetes client-go, Python `vat-scan` CLI, Trivy, Grype, Semgrep, Gitleaks, npm audit, pip-audit, CycloneDX, OpenSCAP, Kustomize, Helm, FastAPI ingest.

---

## Design

The operator should deploy all scan families by default, but bounded:

- `image-sca`: current workload image inventory, using Trivy JSON ingest.
- `image-sbom`: same image inventory, using Trivy CycloneDX ingest.
- `k8s-config`: Kubernetes object inventory, rendered to YAML and scanned for misconfiguration/secrets with Trivy filesystem mode.
- `rbac`: Kubernetes RBAC inventory, included in the config inventory and tagged separately for report filtering.
- `node-stig`: privileged node-agent lane, using OpenSCAP where host content/profile support exists.
- `node-oval-cve`: privileged node-agent lane for OpenSCAP OVAL CVE checks where supported.
- `source-code`: not enabled from the cluster by default because the cluster does not contain source code. The existing `vat-scan scan` path remains available when repositories or source archives are mounted.

The default install should deploy all lanes, but each lane must have:

- An interval.
- A full-rescan interval.
- A local state file.
- A failure policy that does not block other lanes.
- Resources sized independently.
- An explicit `ScanPolicy` knob.

## Task 1: Preserve Kubernetes Asset Identity

**Files:**
- Modify: `backend/app/services/assets_service.py`
- Modify: `frontend/lib/assetUtils.ts`
- Test: `backend/tests/test_metric_semantics.py`
- Test: `backend/tests/test_assets_group_key.py`
- Test: `frontend/lib/assetUtils.identity.test.ts`

**Steps:**

1. Write a failing backend test proving `k8s/<cluster>/...` finding images join to persisted `k8s/<cluster>/...` asset rows.
2. Write a failing backend grouping test proving `k8s/<cluster>/...` is not normalized as a Docker Hub path.
3. Write a failing frontend grouping test proving `containerImageGroupKey("k8s/...")` returns the original ID.
4. Update backend and frontend grouping helpers to preserve `k8s/` IDs.
5. Run:
   - `cd backend && PYTHONPATH=. uv run pytest tests/test_metric_semantics.py tests/test_assets_group_key.py`
   - `cd frontend && npm run test -- lib/assetUtils.identity.test.ts`

## Task 2: Make `/api/assets` Rollups Uncapped

**Files:**
- Modify: `backend/app/services/assets_service.py`
- Test: `backend/tests/test_metric_semantics.py`

**Steps:**

1. Write a failing test showing a small asset `limit` must not cap findings used for asset rollups.
2. Fetch all matching findings when `include_finding_derived_assets=false`.
3. Apply the asset `limit` after payload construction.
4. Run:
   - `cd backend && PYTHONPATH=. uv run pytest tests/test_metric_semantics.py`

## Task 3: Add Image SBOM Inventory Scanning

**Files:**
- Modify: `vat-local-scanner/vat_scanner/scanners/runners.py`
- Modify: `vat-local-scanner/vat_scanner/cli.py`
- Modify: `vat-local-scanner/tests/test_scan_cli_core.py`

**Steps:**

1. Write a failing test for `scan-inventory --scan-types image-sca,image-sbom` proving one image scan can ingest both Trivy findings and CycloneDX SBOM for every workload target.
2. Add `run_trivy_image_ref_cyclonedx(image_ref, timeout=180)` that runs:
   - `trivy image <image_ref> --format cyclonedx --list-all-pkgs --quiet`
3. Extend `scan-inventory` with `--scan-types`, defaulting to `image-sca,image-sbom`.
4. Reuse the image inventory state signature, but track scan-family success independently so SBOM failure does not mark SCA as failed.
5. Ingest CycloneDX documents with parser `cyclonedx`, `X-VAT-Asset`, `X-VAT-Tag`, `X-VAT-Image-Digest`, and idempotency keys.
6. Run:
   - `cd vat-local-scanner && PYTHONPATH=. uv run pytest tests/test_scan_cli_core.py`

## Task 4: Publish Kubernetes Object Inventory

**Files:**
- Modify: `operator/internal/reconcile/deployment_scanner.go`
- Create: `operator/internal/reconcile/kubernetes_inventory_test.go`
- Modify: `operator/cmd/vat-operator/main.go`
- Modify: `deploy/k8s/operator/base/rbac.yaml`
- Modify: `deploy/helm/vat-operator/templates/rbac.yaml`

**Steps:**

1. Write a failing Go test for `BuildKubernetesInventory` covering Deployments, DaemonSets, StatefulSets, Jobs, CronJobs, Pods, Services, Ingresses, ConfigMaps metadata, Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings.
2. Add a `vat-k8s-inventory` ConfigMap with a JSON document containing object metadata and YAML manifests.
3. Avoid embedding Secret values. Include only Secret metadata unless explicitly enabled.
4. Add RBAC for read-only discovery of required resource types.
5. Run:
   - `cd operator && go test ./...`

## Task 5: Add Kubernetes Config/RBAC Scanner CLI Lane

**Files:**
- Modify: `vat-local-scanner/vat_scanner/cli.py`
- Modify: `vat-local-scanner/vat_scanner/scanners/runners.py`
- Create: `vat-local-scanner/tests/test_k8s_inventory_scan.py`

**Steps:**

1. Write a failing test for `vat-scan scan-k8s-inventory /inventory/kubernetes.json`.
2. Implement a command that renders inventory objects into temporary YAML files grouped by namespace/kind/name.
3. Run Trivy filesystem scanning with scan types `iac,secrets`.
4. Normalize results to assets like `k8s/<cluster>/<namespace>/<kind>/<name>`.
5. Ingest with source `trivy` and tags that identify `k8s-config` or `rbac`.
6. Add state file support so unchanged object resource versions are skipped.
7. Run:
   - `cd vat-local-scanner && PYTHONPATH=. uv run pytest tests/test_k8s_inventory_scan.py`

## Task 6: Deploy Config/RBAC Worker Lane

**Files:**
- Create: `deploy/k8s/operator/base/config-worker.yaml`
- Create: `deploy/helm/vat-operator/templates/config-worker.yaml`
- Modify: `deploy/k8s/operator/base/kustomization.yaml`
- Modify: `deploy/helm/vat-operator/values.yaml`
- Modify: `deploy/k8s/operator/base/crd-scanpolicies.yaml`

**Steps:**

1. Add a fixed-replica `vat-config-worker` Deployment.
2. Mount `vat-k8s-inventory` read-only and `/state` as an `emptyDir`.
3. Run `vat-scan scan-k8s-inventory` on its own interval.
4. Add Helm values for interval, full-rescan interval, resources, and scan families.
5. Run:
   - `kubectl kustomize deploy/k8s/operator/base`
   - `helm template vat-operator deploy/helm/vat-operator`

## Task 7: Implement Node Agent STIG/OVAL Lane

**Files:**
- Modify: `vat-local-scanner/vat_scanner/cli.py`
- Create: `vat-local-scanner/tests/test_node_scan_cli.py`
- Modify: `deploy/k8s/operator/components/node-scanning/node-agent-daemonset.yaml`
- Modify: `deploy/helm/vat-operator/templates/node-agent.yaml`
- Modify: `deploy/helm/vat-operator/values.yaml`

**Steps:**

1. Write a failing test for `vat-scan scan-node --scan-types node-stig,node-oval-cve`.
2. Implement a guarded CLI command that checks required host mounts and reports a clear skipped status when OpenSCAP content is unavailable.
3. Use assets like `k8s/<cluster>/node/<node-name>/host`.
4. Run node scans on a long default interval.
5. Ensure failures on one node do not block image/config workers.
6. Run:
   - `cd vat-local-scanner && PYTHONPATH=. uv run pytest tests/test_node_scan_cli.py`

## Task 8: Update ScanPolicy and Docs

**Files:**
- Modify: `deploy/k8s/operator/base/crd-scanpolicies.yaml`
- Modify: `deploy/k8s/README.md`
- Modify: `deploy/helm/vat-operator/values.yaml`
- Modify: `vat-local-scanner/README.md`

**Steps:**

1. Add scan-family fields:
   - `imageSca.enabled`
   - `imageSbom.enabled`
   - `kubernetesConfig.enabled`
   - `rbac.enabled`
   - `nodeStig.enabled`
   - `nodeOvalCve.enabled`
   - `sourceCode.enabled`
2. Document that all deployable cluster lanes are enabled by default.
3. Document that source SAST requires mounted source/repo/archive input.
4. Document security implications of node scanning.
5. Run docs/render checks available in the repo.

## Task 9: Live Verification on `k3s-remote`

**Files:**
- No source changes expected.

**Steps:**

1. Build scanner and operator images.
2. Push to Harbor `latest`.
3. Deploy Helm or Kustomize to `k3s-remote`.
4. Verify worker pods:
   - `vat-scanner-worker`
   - `vat-config-worker`
   - `vat-operator-node-agent`
5. Query VAT:
   - image findings exist under `k8s/<cluster>/...`
   - SBOM packages exist for image assets
   - config/RBAC findings exist under `k8s/<cluster>/<namespace>/<kind>/<name>`
   - node scan assets exist under `k8s/<cluster>/node/<node>/host`
6. Verify unchanged inventory is skipped in every lane.
