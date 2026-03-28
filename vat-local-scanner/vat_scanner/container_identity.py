"""Aikido-style container asset identity: ``containers/images/<name>`` + image tag.

Scanner-agnostic: derived from OCI/docker ``image_ref`` when present, else from
discovery ``label`` (tar stem, wrap layout label). Used for VAT ``image``/``tag``
and ingest headers so local scans align with integration container assets.
"""

from __future__ import annotations

import re


def image_digest_from_ref(ref: str | None) -> str | None:
    """
    Parse manifest digest from OCI ref ``registry/repo@sha256:hex``.
    Returns normalized ``sha256:<hex>`` or None.
    """
    r = (ref or "").strip()
    if not r or "@sha256:" not in r:
        return None
    part = r.split("@sha256:", 1)[1]
    hex_part = re.sub(r"[^0-9a-f]", "", part.lower())[:64]
    if len(hex_part) < 12:
        return None
    return f"sha256:{hex_part}"


def split_repo_and_tag(ref: str) -> tuple[str, str]:
    """
    Split a container reference into repository path and tag.

    Strips ``@sha256:...`` digest. Uses the last ``:`` when the right side looks
    like a tag (no ``/``), so ``registry.io/a/b:latest`` and ``host:5000/a/b:v1``
    both split correctly.
    """
    ref = (ref or "").strip()
    if not ref:
        return "", "latest"
    if "@sha256:" in ref:
        ref = ref.split("@sha256:", 1)[0].strip()
    if ":" not in ref:
        return ref, "latest"
    left, right = ref.rsplit(":", 1)
    if right and "/" not in right:
        return left, right
    return ref, "latest"


def _label_to_image_name(label: str) -> str:
    """Derive a short image name from a scanner discovery label (path/tar/wrap)."""
    s = (label or "").strip()
    if not s:
        return "unknown"
    if "-images-" in s:
        s = s.split("-images-", 1)[-1]
    # e.g. metrics-server-release-0.11.0 -> metrics-server
    m = re.match(r"^(.+?)-release-[\d.]+(?:-|$)", s)
    if m:
        s = m.group(1)
    s = re.sub(r"[^a-zA-Z0-9._-]", "-", s).lower().strip("-")
    return s or "unknown"


def canonical_container_asset(
    image_ref: str | None,
    label: str,
) -> tuple[str, str]:
    """
    Return ``(image, tag)`` for VAT — same shape as Aikido container assets:

    - ``image``: ``containers/images/<short-name>`` (no registry; tag not in ``image``)
    - ``tag``: from reference when parseable, else ``latest``
    """
    ref = (image_ref or "").strip()
    tag = "latest"
    name = ""
    if ref:
        repo, tag = split_repo_and_tag(ref)
        base = repo.rsplit("/", 1)[-1] if repo else ""
        name = re.sub(r"[^a-zA-Z0-9._-]", "-", base).lower().strip("-")
    if not name:
        name = _label_to_image_name(label)
    return f"containers/images/{name}", tag
