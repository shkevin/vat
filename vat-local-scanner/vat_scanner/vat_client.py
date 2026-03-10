"""VAT API client: ingest and ensure source."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

# Source ID prefix for local scanner. Empty = use parser name only (trivy, gitleaks, etc.)
SOURCE_ID_PREFIX = ""

CACHE_DIR = Path.home() / ".config" / "vat"
CACHE_FILE = CACHE_DIR / "scanner-keys.json"


def _load_key_cache() -> dict[str, str]:
    """Load source_id -> key from cache."""
    if not CACHE_FILE.exists():
        return {}
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def source_id_for_parser(parser: str) -> str:
    """Return source_id for a parser. When prefix empty, use parser name only."""
    if SOURCE_ID_PREFIX:
        return f"{SOURCE_ID_PREFIX}-{parser}"
    return parser


def _save_key_cache(cache: dict[str, str]) -> None:
    """Save key cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)
    CACHE_FILE.chmod(0o600)


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
    url = f"{base_url.rstrip('/')}/api/settings/sources/manual/ensure"
    body = {
        "parser": parser,
        "sourceIdPrefix": SOURCE_ID_PREFIX,
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
    return h


def ingest_report(
    base_url: str,
    api_key: str,
    report: dict | list,
    *,
    asset: str | None = None,
    tag: str | None = None,
) -> dict:
    """
    POST report to VAT ingest.
    POST /api/ingest with Authorization: Bearer <key>
    Optional asset/tag set X-VAT-Asset/X-VAT-Tag headers for bundle scans.
    Returns response dict.
    """
    url = f"{base_url.rstrip('/')}/api/ingest"
    req = urllib.request.Request(
        url,
        data=json.dumps(report).encode(),
        method="POST",
        headers=_ingest_headers(api_key, asset, tag),
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
) -> dict:
    """
    POST OpenSCAP XCCDF XML to VAT ingest.
    Uses Content-Type: application/xml. Source must have parser=openscap.
    Optional asset/tag/source_image set headers for bundle scans.
    source_image: container label (e.g. redis, metrics-server) so component identifies which image failed.
    Returns response dict.
    """
    url = f"{base_url.rstrip('/')}/api/ingest"
    data = xml_content.encode("utf-8") if isinstance(xml_content, str) else xml_content
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            **_ingest_headers(api_key, asset, tag, source_image),
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
) -> dict:
    """
    POST OpenSCAP OVAL Results XML to VAT ingest.
    Uses Content-Type: application/xml. Source must have parser=openscap_oval.
    Optional asset/tag/source_image set headers for bundle scans.
    Returns response dict.
    """
    url = f"{base_url.rstrip('/')}/api/ingest"
    data = xml_content.encode("utf-8") if isinstance(xml_content, str) else xml_content
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            **_ingest_headers(api_key, asset, tag, source_image),
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
    cache = _load_key_cache()
    cache[source_id] = key
    _save_key_cache(cache)


class VATClientError(Exception):
    """VAT API client error."""

    pass
