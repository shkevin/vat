"""VAT API client: ingest and ensure source."""

from __future__ import annotations

import json
import os
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
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode() if e.fp else ""
        raise VATClientError(f"Ensure source failed (HTTP {e.code}): {body_text}") from e
    except urllib.error.URLError as e:
        raise VATClientError(f"Ensure source failed: {e.reason}") from e

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
    return h


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
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode() if e.fp else ""
        raise VATClientError(f"Ingest failed (HTTP {e.code}): {body_text}") from e
    except urllib.error.URLError as e:
        raise VATClientError(f"Ingest failed: {e.reason}") from e


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
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode() if e.fp else ""
        raise VATClientError(f"Ingest failed (HTTP {e.code}): {body_text}") from e
    except urllib.error.URLError as e:
        raise VATClientError(f"Ingest failed: {e.reason}") from e


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
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode() if e.fp else ""
        raise VATClientError(f"Ingest failed (HTTP {e.code}): {body_text}") from e
    except urllib.error.URLError as e:
        raise VATClientError(f"Ingest failed: {e.reason}") from e


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
