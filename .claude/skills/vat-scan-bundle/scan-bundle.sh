#!/usr/bin/env bash
#
# scan-bundle.sh — Prepare and scan a Kamiwaza offline release bundle with vat-scanner.
#
# Automates the manual workflow:
#   1. Pick a reachable VAT endpoint (NodePort preferred; the LB VIP is flaky).
#   2. Extract the bundle + nested archives (extensions .tar.gz, RPM payload, helm .tar).
#   3. Flatten container-image tars to a shallow dir so the scanner's max_depth=3
#      container discovery actually finds them (otherwise STIG/container findings are
#      silently skipped).
#   4. Verify checksums, derive the release tag, run the scan, push to VAT.
#
# Usage:
#   VAT_ADMIN_TOKEN=vat_xxx ./scan-bundle.sh <bundle.tar.gz> [options]
#
# Options:
#   --scan-types T     Comma list (default: code,dependencies,stig)
#   --asset NAME       VAT asset name (default: kamiwaza-bundle)
#   --tag TAG          Scan tag (default: auto-derived from release_origination.md, e.g. v0.13.2)
#   --vat-url URL      Override endpoint (default: auto-discover via kubectl, prefer NodePort)
#   --work-dir DIR     Scratch + scan tree root (default: ./artifacts)
#   --image-scope S    all | extensions | none   (default: all)
#                        all        = core helm images + extension images (STIG over everything)
#                        extensions = extension images only (skip 9GB+ core helm .tar)
#                        none       = source-only; drops STIG (it needs images)
#   --reset-keys       Pass through to scanner (rotates the asset's scan key). Default: on.
#   --no-reset-keys    Do not rotate keys.
#   --dry-run          Scan but do not push to VAT.
#   --keep-stage       Don't delete intermediate extraction staging (debug).
#   --scanner-image I  Scanner image (default: vat-scanner:latest)
#
# Env: VAT_ADMIN_TOKEN (required), VAT_URL (optional override).
set -euo pipefail

# ---- defaults ----
SCAN_TYPES="code,dependencies,container,stig"
ASSET="kamiwaza-bundle"
ASSET_MODE="single"
TAG=""
VAT_URL="${VAT_URL:-}"
WORK_DIR="./artifacts"
IMAGE_SCOPE="all"
RESET_KEYS="--reset-keys"
DRY_RUN=""
KEEP_STAGE=""
SCANNER_IMAGE="vat-scanner:latest"
NAMESPACE="vat"

log()  { printf '\033[1;34m[scan-bundle]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[scan-bundle] WARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[scan-bundle] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ---- args ----
[ $# -ge 1 ] || die "Usage: VAT_ADMIN_TOKEN=... $0 <bundle.tar.gz> [options]"
BUNDLE="$1"; shift
while [ $# -gt 0 ]; do
  case "$1" in
    --scan-types) SCAN_TYPES="$2"; shift 2;;
    --asset) ASSET="$2"; shift 2;;
    --asset-mode) ASSET_MODE="$2"; shift 2;;
    --tag) TAG="$2"; shift 2;;
    --vat-url) VAT_URL="$2"; shift 2;;
    --work-dir) WORK_DIR="$2"; shift 2;;
    --image-scope) IMAGE_SCOPE="$2"; shift 2;;
    --reset-keys) RESET_KEYS="--reset-keys"; shift;;
    --no-reset-keys) RESET_KEYS=""; shift;;
    --dry-run) DRY_RUN="--dry-run"; shift;;
    --keep-stage) KEEP_STAGE=1; shift;;
    --scanner-image) SCANNER_IMAGE="$2"; shift 2;;
    *) die "Unknown option: $1";;
  esac
done

[ -e "$BUNDLE" ] || die "Bundle not found: $BUNDLE"
[ -f "$BUNDLE" ] || [ -d "$BUNDLE" ] || die "Bundle must be a .tar.gz file or a directory: $BUNDLE"
[ -n "${VAT_ADMIN_TOKEN:-}" ] || { [ -n "$DRY_RUN" ] || die "VAT_ADMIN_TOKEN env var is required (or use --dry-run)"; }
command -v docker >/dev/null || die "docker not found"
docker image inspect "$SCANNER_IMAGE" >/dev/null 2>&1 || die "Scanner image not present: $SCANNER_IMAGE"
case "$IMAGE_SCOPE" in all|extensions|none) ;; *) die "--image-scope must be all|extensions|none";; esac
case "$ASSET_MODE" in single|multi) ;; *) die "--asset-mode must be single|multi";; esac

# ---- endpoint selection -----------------------------------------------------
# The frontend proxies /api -> backend. We probe /api/findings (needs token).
# CRITICAL: probe from INSIDE the scanner container, not the host. On
# WSL2/Docker-Desktop the host can reach the NodePort node IPs but the scanner
# container CANNOT (Docker's network is the Docker VM, not the WSL2 distro), so a
# host-side probe picks an endpoint the scan can't reach -> the scan dies at
# "Ensure source failed: [Errno 113] No route to host". Preference:
# explicit URL > LB VIP (container-reachable) > NodePort (fallback).
try_url() {
  local url="$1" code
  # Probe in the scanner image so it uses the same network context as the scan.
  # Returns the HTTP status (200 == reachable + authed).
  code=$(docker run --rm --entrypoint python3 "$SCANNER_IMAGE" -c '
import sys, urllib.request, urllib.error
try:
    req = urllib.request.Request(sys.argv[1] + "/api/findings?limit=1",
                                 headers={"Authorization": "Bearer " + sys.argv[2]})
    with urllib.request.urlopen(req, timeout=6) as r: print(r.status)
except urllib.error.HTTPError as e: print(e.code)
except Exception: print(0)
' "$url" "${VAT_ADMIN_TOKEN:-x}" 2>/dev/null || true)
  [ "$code" = "200" ]
}
discover_url() {
  if [ -n "$VAT_URL" ]; then
    try_url "$VAT_URL" && { echo "$VAT_URL"; return 0; }
    warn "Provided VAT_URL ($VAT_URL) not reachable from the scanner container; falling back to discovery"
  fi
  if command -v kubectl >/dev/null 2>&1; then
    local np port lb
    # LB VIP first — it is what the scanner container can actually reach.
    lb=$(kubectl get svc vat-frontend -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
    port=$(kubectl get svc vat-frontend -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].port}' 2>/dev/null || true)
    if [ -n "$lb" ] && [ -n "$port" ] && try_url "http://$lb:$port"; then echo "http://$lb:$port"; return 0; fi
    # NodePort fallback (only where the container can route to node IPs).
    np=$(kubectl get svc vat-frontend -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || true)
    if [ -n "$np" ]; then
      local ip
      for ip in $(kubectl get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}' 2>/dev/null); do
        if try_url "http://$ip:$np"; then echo "http://$ip:$np"; return 0; fi
      done
    fi
  fi
  return 1
}

if [ -n "$DRY_RUN" ] && [ -z "${VAT_ADMIN_TOKEN:-}" ]; then
  SELECTED_URL="http://unused-dry-run:8000"
  log "Dry run with no token: skipping endpoint discovery"
else
  SELECTED_URL=$(discover_url) || die "No reachable VAT endpoint (tried VAT_URL, NodePorts, LB). Check cluster/token."
  log "VAT endpoint: $SELECTED_URL"
fi

# ---- helpers ----------------------------------------------------------------
is_docker_save() { tar tf "$1" 2>/dev/null | grep -qx 'manifest.json'; }
has_wrap()       { tar tf "$1" 2>/dev/null | grep -q '\.wrap$'; }

# ---- layout -----------------------------------------------------------------
mkdir -p "$WORK_DIR"
WORK_DIR=$(cd "$WORK_DIR" && pwd)
STAGE="$WORK_DIR/_stage.$$"
SCAN="$WORK_DIR/$ASSET-${TAG:-scan}"
# tag not known yet -> use a temp name then rename after derivation
SCAN="$WORK_DIR/$ASSET-prep.$$"
mkdir -p "$STAGE" "$SCAN/_images" "$SCAN/_rpm"

cleanup() { [ -n "$KEEP_STAGE" ] || rm -rf "$STAGE"; }
trap cleanup EXIT

if [ -d "$BUNDLE" ]; then
  # ponytail: bundle already unpacked to a dir (CI run output). Hardlink members
  # into the stage so the script's in-place moves/extracts don't mutate the
  # original artifact. Falls back to a real copy if hardlinks can't span the fs.
  log "Bundle is a directory; staging members (hardlink copy)..."
  cp -al "$BUNDLE"/. "$STAGE"/ 2>/dev/null || cp -a "$BUNDLE"/. "$STAGE"/
else
  log "Extracting top-level bundle (this streams the whole archive once)..."
  tar xzf "$BUNDLE" -C "$STAGE"
fi
# collapse single leading dir if present
inner=$(find "$STAGE" -mindepth 1 -maxdepth 1)
if [ "$(printf '%s\n' "$inner" | wc -l)" = "1" ] && [ -d "$inner" ]; then STAGE_ROOT="$inner"; else STAGE_ROOT="$STAGE"; fi

# ---- derive tag from release metadata --------------------------------------
META=$(find "$STAGE_ROOT" -maxdepth 2 -name release_origination.md | head -1 || true)
if [ -z "$TAG" ] && [ -n "$META" ]; then
  ver=$(grep -oE 'offline_app_image_tag: *release-[0-9.]+' "$META" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
  [ -n "$ver" ] && TAG="v$ver"
fi
[ -n "$TAG" ] || TAG=$(date +%Y-%m-%d_%H%M%S)
log "Scan tag: $TAG"

# verify any *.sha256 sidecars we can (best effort)
while IFS= read -r shafile; do
  ( cd "$(dirname "$shafile")" && sha256sum -c "$(basename "$shafile")" >/dev/null 2>&1 ) \
    && log "checksum OK: $(basename "$shafile")" \
    || warn "checksum could not be verified (name mismatch or absent file): $(basename "$shafile")"
done < <(find "$STAGE_ROOT" -maxdepth 2 -name '*.sha256')

# ---- distribute bundle members into the scan tree ---------------------------
shopt -s nullglob
for item in "$STAGE_ROOT"/* "$STAGE_ROOT"/**/*; do
  [ -f "$item" ] || continue
  base=$(basename "$item")
  case "$base" in
    *.rpm)
      log "Unpacking RPM payload: $base"
      d="$SCAN/_rpm/${base%.rpm}"; mkdir -p "$d"
      ( cd "$d" && rpm2cpio "$item" | cpio -idm --quiet ) || warn "rpm unpack failed: $base"
      ;;
    *.tar.gz|*.tgz)
      # an extension/source bundle: extract, harvest image tars, keep source
      log "Unpacking nested archive: $base"
      ed="$STAGE/ext.${base%.tar.gz}.$$"; mkdir -p "$ed"
      tar xzf "$item" -C "$ed" || { warn "extract failed: $base"; continue; }
      # move docker-save image tars out to the shallow _images dir
      while IFS= read -r t; do
        if is_docker_save "$t"; then mv -f "$t" "$SCAN/_images/"; fi
      done < <(find "$ed" -type f -name '*.tar')
      # keep remaining tree as source for code/dependency scanning
      mkdir -p "$SCAN/src"
      mv "$ed" "$SCAN/src/${base%.tar.gz}"
      ;;
    *.tar)
      if is_docker_save "$item"; then
        mv -f "$item" "$SCAN/_images/"           # core/extension image -> shallow
      elif has_wrap "$item"; then
        cp -f "$item" "$SCAN/"                    # helm wrap bundle -> root (depth 1)
      else
        mkdir -p "$SCAN/src/${base%.tar}"; tar xf "$item" -C "$SCAN/src/${base%.tar}" || true
      fi
      ;;
    *.md|*.asc|*.json) cp -f "$item" "$SCAN/" 2>/dev/null || true;;
  esac
done
shopt -u nullglob

# ---- image-scope handling ---------------------------------------------------
if [ "$IMAGE_SCOPE" = "none" ]; then
  log "image-scope=none: removing image tars + wrap bundles (source-only; STIG will yield nothing)"
  rm -f "$SCAN"/_images/*.tar "$SCAN"/*.tar 2>/dev/null || true
  case "$SCAN_TYPES" in *stig*) warn "stig requested but image-scope=none -> STIG will produce no findings";; esac
elif [ "$IMAGE_SCOPE" = "extensions" ]; then
  log "image-scope=extensions: removing core helm wrap .tar at root (keeping extension images)"
  rm -f "$SCAN"/*.tar 2>/dev/null || true
fi

n_images=$(find "$SCAN/_images" -name '*.tar' 2>/dev/null | wc -l | tr -d ' ')
n_wraps=$(find "$SCAN" -maxdepth 1 -name '*.tar' 2>/dev/null | wc -l | tr -d ' ')
log "Scan tree ready: $SCAN"
log "  shallow image tars: $n_images   wrap bundles at root: $n_wraps"
log "  (wrap bundles expand to many more images at scan time)"

# rename prep dir to final tagged name
FINAL="$WORK_DIR/$ASSET-$TAG"
rm -rf "$FINAL"; mv "$SCAN" "$FINAL"; SCAN="$FINAL"

# ---- run the scan -----------------------------------------------------------
HOST_ROOT=$(cd "$WORK_DIR/.." && pwd)              # mount the parent of artifacts as /workspace
REL=${SCAN#"$HOST_ROOT"/}
log "Launching scanner ($SCANNER_IMAGE)"
log "  types=$SCAN_TYPES asset=$ASSET tag=$TAG url=$SELECTED_URL ${DRY_RUN:+[DRY RUN]}"
set -x
docker run --rm \
  -v "$HOST_ROOT:/workspace:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /tmp:/tmp \
  -e VAT_URL="$SELECTED_URL" \
  -e VAT_ADMIN_TOKEN="${VAT_ADMIN_TOKEN:-}" \
  "$SCANNER_IMAGE" \
  scan "/workspace/$REL" \
    --asset-mode single --asset "$ASSET" --tag "$TAG" \
    -v --scan-types "$SCAN_TYPES" $RESET_KEYS $DRY_RUN
rc=$?
set +x
log "Scanner exited rc=$rc"
log "Scan tree retained at: $SCAN  (remove when done to reclaim disk)"
exit $rc
