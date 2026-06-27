# Implementation Plan — Event-Driven Container Scanning

Execution plan for `docs/event-driven-scanning-design.md`. Phased and
non-breaking: each phase ships independently, the polling path stays live behind
a flag until the new path is proven, and a backstop reconcile guarantees coverage
throughout.

## Decisions carried in (from the design)

- **Dispatch**: `vat-scanner-worker` becomes a queue consumer (no per-digest Jobs).
- **Queue**: a namespaced `ScanRequest` CRD (`vat.io/v1`).
- **Node agents**: host scans only by default; image scanning behind
  `VAT_NODE_AGENT_IMAGE_SCANS`.
- **Flag**: `VAT_OPERATOR_EVENT_DRIVEN_SCANS` gates the whole new path.

## Component map (what changes where)

| Area | Path | Change |
|---|---|---|
| Backend | `app/api/` (+ route reg in `app/main.py`) | new `GET /api/scan/known-digests` |
| Backend | `app/services/` | `scan_digests` projection service + tests |
| Operator | `operator/cmd/vat-operator/main.go` | replace reconcile ticker with Pod informer + backstop |
| Operator | `operator/internal/watch/` (new) | informer, image/digest extraction, dedup |
| Operator | `operator/internal/scanrequest/` (new) | CRD client, create/dedupe/GC |
| Scanner | `vat-local-scanner/vat_scanner/cli.py` | new `scan-queue` mode (watch ScanRequests, pull-by-digest) |
| CRDs | `deploy/k8s/operator/base/crd-scanrequests.yaml`, `deploy/helm/vat-operator/crds/` | `ScanRequest` |
| RBAC | `deploy/k8s/operator/base/rbac.yaml` | pods watch/list; scanrequests CRUD |
| Manifests | node-agent + worker (kustomize + helm) | flags, worker→consumer, node-agent host-only |

---

## Phase 0 — Backend `known-digests` projection (no behavior change)

Lets the operator dedup against VAT's source of truth and survive restarts.

- **`GET /api/scan/known-digests`** → `{ "digests": ["sha256:…", …], "generatedAt": … }`.
  Backed by `SELECT DISTINCT image_digest FROM findings WHERE image_digest IS NOT NULL`
  `UNION SELECT last_digest FROM asset_observed_tags WHERE last_digest IS NOT NULL`.
  Normalize via the existing `image_digest` parser. Auth: admin/ingest token.
- Cardinality is small (hundreds); return a flat list with an `ETag` so the
  operator can cheaply poll for changes. Add `?since=<ts>` later only if needed.
- **Tests**: projection dedups across both tables; normalization; empty DB.

**Exit:** endpoint returns the digest set; no scanner/operator change yet.
**Risk:** none (read-only, additive). **Rollback:** delete the route.

---

## Phase 1 — `ScanRequest` CRD + RBAC (declare only)

- **CRD** `scanrequests.vat.io` (namespaced, in `vat-operator`), alongside the
  existing `scanpolicies`/`scanreports`/`vatoperatorconfigs`:

  ```yaml
  spec:
    imageRef: string            # ref as observed (registry/repo:tag)
    digest: string              # resolved sha256 (dedup key); empty if not yet resolved
    tags: [string]              # observed tag(s) for this digest
    scanTypes: [string]         # image-sca, image-sbom, container-stig
    observedRefs:               # provenance (for debugging/audit)
      - {namespace, kind, name, container}
  status:
    phase: string               # pending | scanning | done | failed
    attempts: integer
    lastError: string
    startedAt, finishedAt: date-time
  ```
  Name the CR by digest hash (or imageRef hash when digest unknown) so creation
  is idempotent — the dedup key *is* the object name.
- **RBAC**: operator `create/get/list/watch/update/delete` on `scanrequests`;
  cluster-wide `get/list/watch` on `pods`. Worker `get/list/watch/update` on
  `scanrequests`.
- Add to both kustomize base and helm `crds/` + the k3s overlay.

**Exit:** `kubectl get scanrequests -n vat-operator` works (empty). Nothing
creates or consumes them yet.
**Risk:** low (additive CRD/RBAC). **Rollback:** remove CRD + RBAC.

---

## Phase 2 — Operator Pod informer + dedup, **shadow mode**

- New `internal/watch`: a client-go SharedInformer on Pods (all namespaces),
  resync 10–30 min.
- On Add/Update, build the work set from `spec.containers + initContainers +
  ephemeralContainers` (refs) and `status.*containerStatuses[].imageID`
  (digests). Resolve `(imageRef, digest, tags, observedRefs, scanTypes)`.
- **Dedup**: in-memory set warmed from `GET /api/scan/known-digests` on startup,
  then maintained from events; key on digest (fall back to imageRef when digest
  not yet available).
- Gate everything on `VAT_OPERATOR_EVENT_DRIVEN_SCANS` (default **off**).
- **Shadow**: when on, **do not** create `ScanRequest`s — `log()` "would scan
  digest X for refs …". Keep the existing reconcile poll fully intact.
- Validation: run the `kubectl get pods -A` ↔ canonical-asset coverage check
  from the prior session; confirm the shadow log's digest set ⊇ current coverage
  with no surprises.

**Exit:** with the flag on, operator logs the exact scans it *would* trigger;
real behavior unchanged. **Risk:** low (log-only). **Rollback:** flag off.

---

## Phase 3 — Worker `scan-queue` consumer (parallel path)

- New `vat-scan scan-queue` mode in `cli.py`: watch `ScanRequest` CRs; for each
  `pending`, atomically claim (`status.phase → scanning` via update; lose-the-race
  → skip), then **pull `repo@sha256:<digest>`** through the egress proxy with the
  pull secrets and run `image-sca`/`image-sbom`/`container-stig` (reusing the
  existing scan + ingest code, with the correct image tag). Mark `done`, or
  `failed` with `attempts++` and exponential backoff (mirror the ingest /
  `ensure_source` retry budget); exhausted → leave for the backstop.
- Concurrency bounded by `MaxConcurrentScanJobs`.
- Deploy as a **second** mode of the worker (or a sidecar) so the inventory poll
  still runs — no removal yet.
- RBAC: worker watch/update `scanrequests`.

**Exit:** manually `kubectl apply` a `ScanRequest` → worker scans that digest and
ingests with the right tag; status reaches `done`. **Risk:** medium (new scan
path); contained because the operator isn't creating CRs yet.

---

## Phase 4 — Wire it together; demote the poll to backstop

- Operator (flag on) **creates `ScanRequest`s** for new digests instead of
  shadow-logging.
- Repurpose the reconcile loop as the **backstop**: every 4–6h, list pods →
  compute digest set → diff vs `known-digests` + open `ScanRequest`s → create CRs
  for anything missing. This replaces the hourly operator reconcile.
- Raise the worker inventory poll interval to the backstop cadence (it stops
  being the primary path; the CRD consumer is).
- GC `done`/`failed` CRs after a TTL.
- **Validate**: measure pod-created → ingest latency (target p95 < 60s); re-run
  the coverage check; confirm `image_scans_total{trigger="event"}` dominates and
  the `backstop` tail is small.

**Exit:** new containers scanned in seconds; coverage equals the poll baseline.
**Risk:** medium. **Rollback:** flag off → operator reverts to hourly reconcile +
worker inventory poll (kept intact through this phase).

---

## Phase 5 — Drop blind full re-scans; node agents → host-only

Only after Phase 4 is proven in production for a soak period.

- Remove the 24h `*_FULL_RESCAN` blanket image re-scan behavior (worker + node
  agent runtime). Vuln freshness continues via the hourly SBOM↔feed re-match
  (`vuln_feeds.py`) — add a test asserting a new feed CVE surfaces on an existing
  SBOM **without** a re-scan.
- Node agents: run `scan-node` (host STIG/OVAL) only; gate `scan-runtime` behind
  `VAT_NODE_AGENT_IMAGE_SCANS` (default off). Update node-agent manifests
  (kustomize + helm).
- Optional: a rare, version-gated full re-scan (trivy DB/engine bump) — separate,
  low-frequency trigger.

**Exit:** steady-state image scans ≈ new digests/day; one image vantage (no
cross-vantage digest conflicts possible). **Rollback:** re-enable the rescan
interval / `VAT_NODE_AGENT_IMAGE_SCANS=true`.

---

## Phase 6 — Observability + tuning

- Metrics (operator + worker): `scan_latency_seconds`,
  `image_scans_total{trigger="event|backstop"}`, `scan_dedup_hits_total`,
  `scanrequest_backlog`, `scan_failures_total{reason}`.
- Alerts: backstop-trigger ratio too high (informer unhealthy); any digest
  unscanned past N backstop cycles; pull-failure rate.
- Tune informer resync, backstop cadence, retry budget, CR TTL from observed data
  (the design's remaining open questions).

---

## Cross-cutting

- **Rollback at any phase**: `VAT_OPERATOR_EVENT_DRIVEN_SCANS=false` returns to
  pure polling; the poll path is removed only in Phase 5, after a soak.
- **Burst safety**: digest-dedup + bounded worker concurrency + claim-via-update
  prevent the single-replica backend stampede we hit restarting all node agents
  at once. (Backend HA is a separate, recommended follow-up.)
- **Leader election** (`client-go/leaderelection`) before running >1 operator
  replica so only the leader runs the informer/backstop.
- **Tests**: backend projection (Phase 0); CRD round-trip + dedup-by-name
  (Phase 1); image/digest extraction incl. init/ephemeral + missing-digest
  fallback (Phase 2); claim race + retry/backoff + tag correctness (Phase 3);
  backstop diff fills gaps (Phase 4); SBOM re-match without re-scan (Phase 5).

## Sequencing

0 → 1 → 2 may proceed in parallel with 3 (worker mode) since both are dormant
until 4 wires them. 5 and 6 follow a production soak of 4.
