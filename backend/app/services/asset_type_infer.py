"""
Asset scope type inference — single place for repo/container/package/path.

Uses all findings for an asset (not only the first), with priority merge so
mixed STIG + dependency data still classifies as container when appropriate.
"""

from __future__ import annotations

import re
from typing import Any

# Highest wins when merging per-finding candidates
_TYPE_PRIORITY: dict[str, int] = {
    "container": 4,
    "repo": 3,
    "path": 2,
    "package": 1,
}

_CODE_FINDING_TYPES = frozenset({"sast", "secret", "iac"})
_CONTAINER_BIAS_SOURCES = frozenset({"openscap", "openscap_oval"})


def looks_like_container_image_ref(image: str | None) -> bool:
    """True when ``image`` is a container reference, not a bundle folder name."""
    s = (image or "").strip()
    if not s or s.startswith("path:"):
        return False
    if "/images/" in s:
        return True
    if "@sha256:" in s:
        return True
    if ":" not in s:
        return False
    before = s.split(":", 1)[0]
    if "/" in before:
        return True
    # nginx:1.24, alpine:3
    if re.match(r"^[a-z0-9._-]+$", before, re.I):
        return True
    return False


def infer_asset_type_from_one_finding(d: dict[str, Any]) -> str:
    """Classify one finding's contribution to asset scope (not merged)."""
    img = (d.get("image") or "").strip()
    branch = (d.get("branch") or "").strip()
    comp = (d.get("component") or "").strip()
    fp = (d.get("filePath") or d.get("file_path") or "").strip()
    ft = (d.get("findingType") or d.get("finding_type") or "").lower()
    src = (d.get("source") or "").strip().lower()
    is_code = ft in _CODE_FINDING_TYPES

    # Secrets: bundle scans reuse image=folder — not a git repo unless branch/container ref
    if ft == "secret":
        if branch:
            return "repo"
        if img and looks_like_container_image_ref(img):
            return "container"
        return "path"

    # STIG / OpenSCAP host-in-container: treat as container when image is set
    if src in _CONTAINER_BIAS_SOURCES and img:
        return "container"

    if "/images/" in img:
        return "container"

    if img and branch:
        return "repo"
    if img and is_code:
        return "repo"
    if img and looks_like_container_image_ref(img):
        return "container"
    if img:
        return "container"
    if fp and not img and not comp:
        return "path"
    if fp and is_code:
        return "repo"
    if comp:
        return "package"
    return "package"


def infer_asset_type_from_findings(findings: list[dict[str, Any]]) -> str:
    """Merge per-finding types (container > repo > path > package)."""
    if not findings:
        return "package"
    candidates = [infer_asset_type_from_one_finding(d) for d in findings]
    return max(candidates, key=lambda c: _TYPE_PRIORITY.get(c, 0))
