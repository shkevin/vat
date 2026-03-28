"""
Deterministic container image digest from on-disk artifacts (scanner-agnostic).

We do **not** rely on Trivy/Grype/OpenSCAP to report digests — each tool may use
different fields (RepoDigests vs ArtifactID vs config hash).

Definitions
-----------
- **OCI layout** (``oci-layout`` + ``blobs/``): Use the OCI **image manifest**
  descriptor digest from ``index.json`` (and recurse into manifest lists/indexes
  deterministically). This matches the registry manifest digest when the layout
  was produced by tools like skopeo without re-encoding.
- **Docker save tarball**: Use ``sha256`` of the **config JSON blob** referenced
  in ``manifest.json`` — Docker's image ID for that export. This generally does
  **not** equal a registry manifest digest; prefer OCI layouts for cross-source
  parity with registry-backed systems.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

_OCI_IMAGE_MANIFEST_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)
_OCI_INDEX_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)


def _normalize_sha256_digest(s: str) -> str | None:
    """Canonical ``sha256:<hex>`` with at least 12 hex chars (Trivy-compatible)."""
    t = (s or "").strip()
    if not t.startswith("sha256:"):
        return None
    hex_part = re.sub(r"[^0-9a-f]", "", t[7:].lower())[:64]
    if len(hex_part) < 12:
        return None
    return f"sha256:{hex_part}"


def normalize_sha256_digest(s: str | None) -> str | None:
    """Normalize a digest string for ``image_digest`` fields (public API)."""
    if not isinstance(s, str):
        return None
    return _normalize_sha256_digest(s)


def _blob_path(layout_dir: Path, digest: str) -> Path | None:
    norm = _normalize_sha256_digest(digest)
    if not norm:
        return None
    hex_part = norm[7:]
    # OCI blob filenames use the full 64-hex form
    if len(hex_part) != 64:
        return None
    p = layout_dir / "blobs" / "sha256" / hex_part
    return p if p.is_file() else None


def _digest_from_index_object(layout_dir: Path, data: object) -> str | None:
    if not isinstance(data, dict):
        return None
    manifests = data.get("manifests") or []
    if not isinstance(manifests, list):
        return None

    image_digests: list[str] = []
    nested_index_digests: list[str] = []

    for m in manifests:
        if not isinstance(m, dict):
            continue
        mt = str(m.get("mediaType") or "")
        d = m.get("digest")
        if not isinstance(d, str) or not d.strip():
            continue
        if mt in _OCI_IMAGE_MANIFEST_TYPES:
            nd = _normalize_sha256_digest(d)
            if nd:
                image_digests.append(nd)
        elif mt in _OCI_INDEX_TYPES:
            nd = _normalize_sha256_digest(d)
            if nd:
                nested_index_digests.append(nd)

    if image_digests:
        return sorted(image_digests)[0]

    for nd in sorted(nested_index_digests):
        bp = _blob_path(layout_dir, nd)
        if not bp:
            continue
        try:
            nested = json.loads(bp.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        got = _digest_from_index_object(layout_dir, nested)
        if got:
            return got
    return None


def oci_image_manifest_digest_from_layout(layout_dir: Path) -> str | None:
    """
    Return a canonical ``sha256:…`` digest for the image in an OCI layout dir.

    Reads ``index.json`` and selects an **image manifest** descriptor digest;
    if the index is a manifest list, recurses into nested blobs deterministically
    (sorted digests).
    """
    idx = layout_dir / "index.json"
    if not idx.is_file():
        return None
    try:
        data = json.loads(idx.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return _digest_from_index_object(layout_dir, data)


def docker_save_config_digest_from_tar(tar_path: Path) -> str | None:
    """
    SHA256 of the **config** JSON blob in a ``docker save`` tarball (Docker image ID).
    """
    try:
        r = subprocess_run_tar_config(tar_path)
        if r is None:
            return None
        return f"sha256:{hashlib.sha256(r).hexdigest()}"
    except OSError:
        return None


def subprocess_run_tar_config(tar_path: Path) -> bytes | None:
    """Extract config blob bytes from docker-save tar; exposed for tests."""
    import subprocess

    try:
        man = subprocess.run(
            ["tar", "-xOf", str(tar_path), "manifest.json"],
            capture_output=True,
            timeout=120,
        )
        if man.returncode != 0 or not (man.stdout or b"").strip():
            return None
        data = json.loads(man.stdout.decode("utf-8"))
    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        return None
    if not isinstance(data, list) or not data:
        return None
    first = data[0]
    if not isinstance(first, dict):
        return None
    config_name = first.get("Config")
    if not isinstance(config_name, str) or not config_name.strip():
        return None
    try:
        cfg = subprocess.run(
            ["tar", "-xOf", str(tar_path), config_name.strip()],
            capture_output=True,
            timeout=120,
        )
        if cfg.returncode != 0:
            return None
        return cfg.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def compute_container_image_digest(path: Path, format: str) -> str | None:
    """
    Single entry point: deterministic digest for a ``ContainerSource``.

    - ``oci-layout``: manifest descriptor digest from OCI ``index.json``.
    - ``docker-save``: SHA256 of config JSON blob inside the tar.
    """
    fmt = (format or "").strip().lower()
    path = path.resolve()
    if fmt == "oci-layout":
        return oci_image_manifest_digest_from_layout(path)
    if fmt == "docker-save":
        return docker_save_config_digest_from_tar(path)
    return None
