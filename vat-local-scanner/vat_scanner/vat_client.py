"""VAT API client: ingest and ensure source."""

from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Source ID prefix for local scanner. Empty = use parser name only (trivy, gitleaks, etc.)
SOURCE_ID_PREFIX = ""

CACHE_DIR = Path.home() / ".config" / "vat"
CACHE_FILE = CACHE_DIR / "scanner-keys.json"


def _source_id_prefix() -> str:
    return (os.environ.get("VAT_SOURCE_ID_PREFIX") or SOURCE_ID_PREFIX).strip()


def key_cache_dir() -> Path:
    raw = (os.environ.get("VAT_SCANNER_KEY_CACHE_DIR") or "").strip()
    if raw:
        return Path(raw)
    return CACHE_DIR


def key_cache_file() -> Path:
    return key_cache_dir() / "scanner-keys.json"


def _validated_base_url(base_url: str) -> str:
    """Return a normalized VAT base URL after rejecting unsafe request targets."""
    raw = (base_url or "").strip()
    parsed = urllib.parse.urlsplit(raw)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise VATClientError("Unsafe VAT URL: expected http(s) URL without credentials, query, or fragment")
    path = parsed.path.rstrip("/")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _api_url(base_url: str, path: str) -> str:
    return f"{_validated_base_url(base_url)}{path}"


def _load_key_cache() -> dict[str, str]:
    """Load source_id -> key from cache."""
    cache_file = key_cache_file()
    if not cache_file.exists():
        return {}
    try:
        with open(cache_file) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def source_id_for_parser(parser: str) -> str:
    """Return source_id for a parser. When prefix empty, use parser name only."""
    prefix = _source_id_prefix()
    if prefix:
        return f"{prefix}-{parser}"
    return parser


def _save_key_cache(cache: dict[str, str]) -> None:
    """Save key cache."""
    cache_dir = key_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = key_cache_file()
    with open(cache_file, "w") as f:
        json.dump(cache, f, indent=2)
    cache_file.chmod(0o600)


def _urlopen_json_with_retry(
    req: urllib.request.Request,
    *,
    timeout: float,
    label: str,
    attempts: int = 7,
) -> dict:
    """POST with retry on transient failures (connection refused, 5xx) using
    jittered exponential backoff, so a scan isn't lost to a brief backend herd
    (single-replica backend refusing connections under load). A 4xx is a real
    error and fails fast. ``req`` must carry bytes data — it is re-sent verbatim.
    Ingest is idempotent (idempotency_key), so retries can't double-count.
    """
    last_reason = "unknown error"
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code < 500:
                body_text = e.read().decode() if e.fp else ""
                raise VATClientError(
                    f"{label} failed (HTTP {e.code}): {body_text}"
                ) from e
            last_reason = f"HTTP {e.code}"
        except urllib.error.URLError as e:
            last_reason = str(e.reason)
        if attempt < attempts:
            # Jittered backoff (~1-3, 2-6, 4-12, 8-24, 15-45, 15-45s): spans a
            # multi-minute herd without synchronizing retries across agents.
            base = min(2**attempt, 30)
            time.sleep(base * (0.5 + random.random()))
    raise VATClientError(f"{label} failed after {attempts} retries: {last_reason}")


def ensure_source(
    base_url: str,
    admin_token: str,
    parser: str,
    *,
    create_key: bool = True,
    regenerate_key: bool = False,
    asset_type: str = "package",
) -> tuple[str, str | None]:
    """
    Ensure a Manual source exists for the parser.
    POST /api/settings/sources/manual/ensure
    Returns (source_id, key or None).
    """
    url = _api_url(base_url, "/api/settings/sources/manual/ensure")
    body = {
        "parser": parser,
        "sourceIdPrefix": _source_id_prefix(),
        "assetType": asset_type,
        "createKey": create_key,
        "regenerateKey": regenerate_key,
    }
    data_bytes = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data_bytes,
        method="POST",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
        },
    )
    data = _urlopen_json_with_retry(req, timeout=30, label="Ensure source")
    return data.get("sourceId", ""), data.get("key")


def _ingest_headers(
    api_key: str,
    asset: str | None = None,
    tag: str | None = None,
    source_image: str | None = None,
    image_digest: str | None = None,
    scan_id: str | None = None,
    scan_status: str | None = None,
    idempotency_key: str | None = None,
) -> dict:
    """Build ingest request headers. X-VAT-Asset, X-VAT-Tag, X-VAT-Source-Image override asset context for bundle scans."""
    h = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if asset and str(asset).strip():
        h["X-VAT-Asset"] = str(asset).strip()
    if tag and str(tag).strip():
        h["X-VAT-Tag"] = str(tag).strip()
    if source_image and str(source_image).strip():
        h["X-VAT-Source-Image"] = str(source_image).strip()
    if image_digest and str(image_digest).strip():
        h["X-VAT-Image-Digest"] = str(image_digest).strip()
    if scan_id and str(scan_id).strip():
        h["X-VAT-Scan-Id"] = str(scan_id).strip()
    if scan_status and str(scan_status).strip():
        h["X-VAT-Scan-Status"] = str(scan_status).strip()
    if idempotency_key and str(idempotency_key).strip():
        h["X-VAT-Idempotency-Key"] = str(idempotency_key).strip()
    # Multi-cluster attribution: stamp which cluster produced this report. A
    # deployment-wide constant, so read from env rather than threading it through
    # every ingest call site. This is the SAME identifier used in k8s/node asset
    # paths and the cluster->tenant map, so all three stay consistent.
    cluster = (
        os.environ.get("VAT_CLUSTER_NAME")
        or os.environ.get("CLUSTER_NAME")
        or ""
    ).strip()
    if cluster:
        h["X-VAT-Cluster"] = cluster
    return h


def fetch_known_digests(base_url: str, api_key: str, timeout: int = 30) -> set[str] | None:
    """GET /api/scan/known-digests -> set of normalized sha256 digests VAT already
    has findings/SBOMs for. Used to reconcile incremental scan state against VAT's
    actual state: if a previously-scanned digest is no longer known (asset deleted),
    the scanner re-scans instead of skipping. Returns None on any failure, so the
    caller falls back to pure local-state behavior (never a thundering re-scan)."""
    try:
        url = _api_url(base_url, "/api/scan/known-digests")
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {api_key}"})
        data = _urlopen_json_with_retry(req, timeout=timeout, label="known-digests")
    except Exception:
        return None
    digests = data.get("digests") if isinstance(data, dict) else None
    if not isinstance(digests, list):
        return None
    return {str(d).strip().lower() for d in digests if str(d).strip()}


def ingest_report(
    base_url: str,
    api_key: str,
    report: dict | list,
    *,
    asset: str | None = None,
    tag: str | None = None,
    source_image: str | None = None,
    image_digest: str | None = None,
    scan_id: str | None = None,
    scan_status: str | None = None,
    idempotency_key: str | None = None,
) -> dict:
    """
    POST report to VAT ingest.
    POST /api/ingest with Authorization: Bearer <key>
    Optional asset/tag set X-VAT-Asset/X-VAT-Tag headers for bundle scans.
    Returns response dict.
    """
    url = _api_url(base_url, "/api/ingest")
    req = urllib.request.Request(
        url,
        data=json.dumps(report).encode(),
        method="POST",
        headers=_ingest_headers(
            api_key,
            asset,
            tag,
            source_image,
            image_digest=image_digest,
            scan_id=scan_id,
            scan_status=scan_status,
            idempotency_key=idempotency_key,
        ),
    )
    return _urlopen_json_with_retry(req, timeout=60, label="Ingest")


def ingest_openscap_report(
    base_url: str,
    api_key: str,
    xml_content: str | bytes,
    *,
    asset: str | None = None,
    tag: str | None = None,
    source_image: str | None = None,
    image_digest: str | None = None,
    scan_id: str | None = None,
    scan_status: str | None = None,
    idempotency_key: str | None = None,
) -> dict:
    """
    POST OpenSCAP XCCDF XML to VAT ingest.
    Uses Content-Type: application/xml. Source must have parser=openscap.
    Optional asset/tag/source_image set headers for bundle scans.
    source_image: container label (e.g. redis, metrics-server) so component identifies which image failed.
    Returns response dict.
    """
    url = _api_url(base_url, "/api/ingest")
    data = xml_content.encode("utf-8") if isinstance(xml_content, str) else xml_content
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            **_ingest_headers(
                api_key,
                asset,
                tag,
                source_image,
                image_digest=image_digest,
                scan_id=scan_id,
                scan_status=scan_status,
                idempotency_key=idempotency_key,
            ),
            "Content-Type": "application/xml",
        },
    )
    return _urlopen_json_with_retry(req, timeout=120, label="Ingest")


def ingest_openscap_oval_report(
    base_url: str,
    api_key: str,
    xml_content: str | bytes,
    *,
    asset: str | None = None,
    tag: str | None = None,
    source_image: str | None = None,
    image_digest: str | None = None,
    scan_id: str | None = None,
    scan_status: str | None = None,
    idempotency_key: str | None = None,
) -> dict:
    """
    POST OpenSCAP OVAL Results XML to VAT ingest.
    Uses Content-Type: application/xml. Source must have parser=openscap_oval.
    Optional asset/tag/source_image set headers for bundle scans.
    Returns response dict.
    """
    url = _api_url(base_url, "/api/ingest")
    data = xml_content.encode("utf-8") if isinstance(xml_content, str) else xml_content
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            **_ingest_headers(
                api_key,
                asset,
                tag,
                source_image,
                image_digest=image_digest,
                scan_id=scan_id,
                scan_status=scan_status,
                idempotency_key=idempotency_key,
            ),
            "Content-Type": "application/xml",
        },
    )
    return _urlopen_json_with_retry(req, timeout=120, label="Ingest")


def get_cached_key(source_id: str) -> str | None:
    """Get API key for source from cache."""
    return _load_key_cache().get(source_id)


def cache_key(source_id: str, key: str) -> None:
    """Cache API key for source."""
    try:
        cache = _load_key_cache()
        cache[source_id] = key
        _save_key_cache(cache)
    except OSError:
        # Containerized scanner lanes often run with read-only root filesystems;
        # lack of a writable key cache must not block the current ingest.
        return


class VATClientError(Exception):
    """VAT API client error."""

    pass
