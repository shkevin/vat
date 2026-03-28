"""SARIF partialFingerprints resolution per implementation plan §4.5."""

from __future__ import annotations

import hashlib
import logging
from typing import Literal

logger = logging.getLogger(__name__)

BranchUsed = Literal[
    "primaryLocationLineHash/v1",
    "primaryLocationLineHash",
    "contextRegionHash/v1",
    "contextRegionHash",
    "sorted_all_keys_sha256",
    "none",
]


def resolve_partial_fingerprints(
    partial_fingerprints: dict[str, str] | None,
) -> tuple[str | None, BranchUsed]:
    """
    Returns (canonical_material_hash, branch_used).

    The hash is SHA-256 hex of the selected material string (stable for dedup).
    """
    if not partial_fingerprints:
        return None, "none"

    pf = partial_fingerprints
    material: str | None = None
    branch: BranchUsed = "none"

    v1 = pf.get("primaryLocationLineHash/v1")
    if v1 and str(v1).strip():
        material = str(v1).strip()
        branch = "primaryLocationLineHash/v1"
    else:
        for k in sorted(pf.keys()):
            if k.startswith("primaryLocationLineHash") and pf.get(k):
                material = str(pf[k]).strip()
                branch = "primaryLocationLineHash"
                break

    if material is None:
        cv1 = pf.get("contextRegionHash/v1")
        if cv1 and str(cv1).strip():
            material = str(cv1).strip()
            branch = "contextRegionHash/v1"
        elif pf.get("contextRegionHash") and str(pf["contextRegionHash"]).strip():
            material = str(pf["contextRegionHash"]).strip()
            branch = "contextRegionHash"

    if material is None:
        pairs = sorted(partial_fingerprints.items())
        blob = "|".join(f"{k}={v}" for k, v in pairs if v)
        if not blob:
            return None, "none"
        material = blob
        branch = "sorted_all_keys_sha256"

    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    logger.debug("SARIF partialFingerprints: branch=%s hash=%s...", branch, digest[:12])
    return digest, branch
