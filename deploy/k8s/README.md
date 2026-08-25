# VAT Kubernetes manifests

Kustomize manifests for deploying VAT. These are the generic, environment-neutral
bases; per-site overlays (real VIPs, DNS, encrypted runtime secrets) are expected
to live in a separate private repo and are not published here.

## Layout

```
deploy/k8s/
├── base/               Namespace, Postgres StatefulSet, Valkey StatefulSet,
│                       backend Deployment (+ Alembic initContainer),
│                       frontend Deployment, Celery workers & beat, ConfigMap.
├── operator/           VAT operator: CRDs, RBAC, scanner worker, node-scanning
│                       component, and k0s/k3s/kind runtime-profile overlays.
└── templates/          Plaintext Secret templates (copy, fill, then `sops -e`).
```

Deploy the core app straight from base:

```bash
kubectl apply -k deploy/k8s/base
```

## Building a site overlay

Create an overlay in your own private repo that references this base and supplies
the environment-specific parts:

```yaml
# overlays/<env>/kustomization.yaml
resources:
  - <path-or-remote-ref-to>/deploy/k8s/base
images:
  - name: vat-backend
    newName: <your-registry>/vat/backend
    newTag: latest
  - name: vat-frontend
    newName: <your-registry>/vat/frontend
    newTag: latest
patches:
  - path: patch-frontend-lb.yaml   # your LoadBalancer VIP / Service type
```

## Networking

The frontend Service is a plain `LoadBalancer` on port 3000; how it is exposed is
site-specific. Two patterns that work:

- **LoadBalancer VIP** (MetalLB or a cloud LB) — simplest. Note that MetalLB L2
  ownership can move between speakers after node or workload restarts, and stale
  ARP caches can briefly blackhole traffic even while the Service reports healthy.
- **External proxy over pinned NodePorts** — front the app from an external
  load balancer across all node IPs with a health check. Immune to the stale-ARP
  failure mode above, at the cost of pinning a `nodePort`.

Prefer the second pattern if you have seen intermittent post-restart outages. For
TLS, terminate at the external load balancer or add cert-manager plus a dedicated
Ingress controller inside the `vat` namespace.

## Secrets

`vat-runtime` holds the database URL, broker URL, and app secret key. Generate it
per environment with SOPS/KSOPS from the template:

```bash
cp deploy/k8s/templates/vat-runtime.template.yaml vat-runtime.plain.yaml
$EDITOR vat-runtime.plain.yaml
export SOPS_AGE_KEY_FILE=/path/to/your/age.key
sops -e vat-runtime.plain.yaml > overlays/<env>/vat-runtime.enc.yaml
rm vat-runtime.plain.yaml
```

Commit only `*.enc.yaml`. `*.plain.yaml` and `age.key` are `.gitignore`d.

## Image pull credentials

Published images are `ghcr.io/shkevin/vat/{backend,frontend}`. For a private
registry, create a pull Secret in the `vat` namespace and reference it — each
workload already declares `imagePullSecrets`.

## Image build pipeline

`.gitlab-ci.yml` at the repo root builds backend + frontend with Kaniko and
pushes to Harbor. Tagging rules:

| Trigger               | Tags pushed                                   |
|-----------------------|-----------------------------------------------|
| branch `main`         | `latest`, `sha-<short>`                       |
| branch `develop`      | `develop`, `sha-<short>`                      |
| git tag `v*`          | `<tag>`, `sha-<short>`                        |
| merge request         | dry-run build (`--no-push`), no tags pushed   |

Required CI/CD variables:

- `HARBOR_USER` (masked, protected) — Harbor robot or user
- `HARBOR_TOKEN` (masked, protected) — Harbor token with push on project `vat`

Optional:

- `SOPS_AGE_KEY` (masked, protected, file) — enables the
  `validate:overlays` job to render the KSOPS-enabled overlays in CI.

The frontend Kaniko job passes `--build-arg API_UPSTREAM_URL=http://vat-backend:8000`
so Next.js rewrites `/api/*` to the in-cluster Service `vat-backend` (not
`backend`, which is only valid in docker-compose).

## First login (local auth)

Alembic migration `006` seeds user id `admin`, email `admin@vat.local`, password
`admin` (bcrypt). `POST /api/auth/login` accepts **either** the user id or the
email in the username field. If you see *Use Sign in with Google*, the default
tenant was switched to Google SSO — use Google or reset `tenants.auth_method`
to `local` for `t-default`.

## Local validation

```bash
kubectl apply -k deploy/k8s/base --dry-run=client >/dev/null
kubectl apply -k deploy/k8s/operator/base --dry-run=client >/dev/null
```

For overlays that use KSOPS generators, both flags are required — `--enable-exec`
alone leaves the generator disabled in nested builds:

```bash
export SOPS_AGE_KEY_FILE=/path/to/your/age.key
kustomize build --enable-alpha-plugins --enable-exec overlays/<env> >/dev/null
```

## VAT operator

The VAT operator is packaged separately from the core app. It discovers
Kubernetes workloads and cluster objects, publishes compact inventories, and
lets bounded workers scan those inventories sequentially. This avoids creating
one Kubernetes Job per container and keeps VAT as the source of record for
findings, SBOMs, deduplication, and correlation.

The default cluster lanes are:

- `vat-scanner-worker`: a single cluster worker that runs image SCA/SBOM from
  `vat-scan-inventory` and Kubernetes config, secrets posture, and RBAC posture
  from `vat-k8s-inventory`.
- `vat-operator-node-agent`: privileged node OpenSCAP STIG/OVAL lane, enabled
  by the runtime profile overlays and enabled by default in Helm.

For private images, the image inventory stores only referenced
`imagePullSecrets` names. The scanner worker reads those Kubernetes Secrets at
scan time with its service account and writes a temporary Docker auth config for
Trivy. Secret contents are not written into inventory ConfigMaps.

Source-code SAST is not enabled from the cluster by default because Kubernetes
does not contain source repositories. Use `vat-scan scan`, `scan-archive`, or a
separate mounted source workflow for Semgrep/Gitleaks/source dependency scans.

Base install, non-privileged image/config/RBAC scanning:

```bash
kubectl apply -k deploy/k8s/operator/base
```

The image lane is runtime-first. The node-agent enumerates containers and
image-store entries known to the node runtime, running or stopped, and scans the
corresponding local images. It also checks the host Docker socket at
`/host/var/run/docker.sock` when available so Docker-only containers/images can
be included. The central scanner-worker defaults to
`VAT_OPERATOR_IMAGE_INVENTORY_MODE=non-running`, publishing only desired
workload images that are not already represented by a running Pod. Use
`running` to publish only running Pod containers, `runtime` to publish an empty
central image inventory, or `workload` when you explicitly want registry scans
for every desired Deployment, StatefulSet, DaemonSet, Job, CronJob, and
standalone Pod image.

Profile overlays enable the privileged node-agent tier for infrastructure
scans. The node agent is a small DaemonSet, separate from the bounded scanner
worker:

```bash
kubectl apply -k deploy/k8s/operator/overlays/k0s
kubectl apply -k deploy/k8s/operator/overlays/k3s
kubectl apply -k deploy/k8s/operator/overlays/kind
```

`kind` support is intentionally limited by kind's architecture: Kubernetes
nodes are Docker containers, so node scans see the containerized node unless
the host runtime is explicitly mounted into the cluster.

Node STIG/OVAL scanning mounts the host root read-only at `/host` in a
privileged DaemonSet. The scanner image includes the `oscap` binary, but STIG
datastream and OVAL definition content are OS-specific and must be provided by
mounting files or setting:

- `VAT_NODE_STIG_DATASTREAM`
- `VAT_NODE_STIG_PROFILE`
- `VAT_NODE_OVAL_DEFINITIONS`

If those files are absent or the host is unsupported, the node agent logs a
clear skip and keeps running.

Helm install:

```bash
helm install vat-operator deploy/helm/vat-operator \
  --namespace vat-operator \
  --create-namespace \
  --set vat.url=http://vat-backend.vat.svc.cluster.local:8000
```

Set `--set nodeAgent.enabled=false` if you want the Helm install to skip the
privileged host-root node lane.

k0s node-agent install:

```bash
helm install vat-operator deploy/helm/vat-operator \
  --namespace vat-operator \
  --create-namespace \
  --set operator.runtimeProfile=k0s \
  --set nodeAgent.enabled=true \
  --set nodeAgent.runtimeProfile=k0s \
  --set nodeAgent.containerdSocketPath=/host/run/k0s/containerd.sock \
  --set nodeAgent.kubeletRootPath=/host/var/lib/k0s/kubelet \
  --set nodeAgent.staticPodManifestPath=/host/var/lib/k0s/manifests
```

Create `vat-operator-credentials` in the operator namespace with an
`adminToken` key before enabling scans. The operator uses that token to let
scanner workers auto-provision VAT ingest sources. You may also provide an
`apiKey` key for direct ingest where a preconfigured source key is preferred.
