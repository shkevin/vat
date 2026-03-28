"""Extract container image identity (digest, tag) from CycloneDX BOM metadata.

Used for Aikido license/SBOM exports and other CycloneDX sources where the root
``metadata.component`` carries oci purl or tool-specific properties (e.g. Trivy).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from app.parsers.image_digest import normalize_image_digest


@dataclass(frozen=True)
class CycloneDxContainerIdentity:
    """Best-effort identity for a scanned container image."""

    digest: str | None  # manifest-style sha256:...
    tag: str | None  # e.g. 3.19, latest
    display_name: str | None  # e.g. alpine:3.19
    stamp_ref: str | None  # ref to stamp on components / SBOM.component (prefer digest-pinned)


def unwrap_cyclonedx_document(data: Any) -> dict | None:
    """Return a CycloneDX JSON object or None if not recognized."""
    if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
        return data
    if not isinstance(data, dict):
        return None
    for key in ("sbom", "bom", "cyclonedx", "document", "data", "licenses"):
        inner = data.get(key)
        if isinstance(inner, dict) and inner.get("bomFormat") == "CycloneDX":
            return inner
        if isinstance(inner, str) and inner.strip().startswith("{"):
            try:
                parsed = json.loads(inner)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict) and parsed.get("bomFormat") == "CycloneDX":
                return parsed
    return None


def _digest_from_oci_purl(purl: str) -> str | None:
    """Parse sha256 from pkg:oci/... purl (version segment often sha256%3A...)."""
    if not purl or not isinstance(purl, str):
        return None
    raw = unquote(purl.strip())
    if "@sha256:" not in raw:
        return None
    part = raw.split("@sha256:", 1)[1]
    hex_part = re.sub(r"[^0-9a-fA-F]", "", part)[:64]
    return normalize_image_digest(f"sha256:{hex_part}")


def _tag_from_name(name: str | None) -> str | None:
    if not name or not isinstance(name, str):
        return None
    s = name.strip()
    if ":" in s:
        tag = s.rsplit(":", 1)[-1].strip()
        if tag and "/" not in tag:
            return tag
    return None


def _prop_map(props: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(props, list):
        return out
    for p in props:
        if isinstance(p, dict):
            n = str(p.get("name") or "").strip()
            v = str(p.get("value") or "").strip()
            if n and v:
                out[n.lower()] = v
    return out


def extract_container_identity_from_cyclonedx(doc: dict) -> CycloneDxContainerIdentity:
    """
    Read metadata.component (container root). Supports:
    - oci purl with sha256 version (Trivy, Syft-style)
    - aquasecurity:trivy:RepoDigest / RepoTag
    - name like image:tag for tag fallback
    """
    meta = doc.get("metadata") or {}
    comp = meta.get("component") if isinstance(meta, dict) else None
    if not isinstance(comp, dict):
        return CycloneDxContainerIdentity(None, None, None, None)

    purl = str(comp.get("purl") or "").strip()
    name = str(comp.get("name") or "").strip() or None

    digest: str | None = None
    if purl:
        digest = _digest_from_oci_purl(purl)

    props = _prop_map(comp.get("properties"))
    repo_digest_full = props.get("aquasecurity:trivy:repodigest") or props.get(
        "repodigest"
    )
    if not digest and repo_digest_full:
        rd = repo_digest_full
        if "@sha256:" in rd:
            digest = normalize_image_digest(rd.split("@sha256:", 1)[1])
        else:
            digest = normalize_image_digest(rd)

    rt = props.get("aquasecurity:trivy:repotag") or props.get("repotag")
    tag = _tag_from_name(rt) or _tag_from_name(name)

    stamp_ref: str | None = None
    if repo_digest_full and "@sha256:" in repo_digest_full:
        stamp_ref = repo_digest_full
    elif digest and name and "@" not in name:
        stamp_ref = f"{name}@sha256:{digest[7:]}" if digest.startswith("sha256:") else f"{name}@{digest}"
    elif digest:
        stamp_ref = digest
    elif name:
        stamp_ref = name

    return CycloneDxContainerIdentity(
        digest=digest,
        tag=tag,
        display_name=name,
        stamp_ref=stamp_ref,
    )


def stamp_vat_container_ref_on_cyclonedx(doc: dict, container_ref: str) -> dict:
    """Add vat:container_ref to each top-level component (matches local scanner behavior)."""
    ref = (container_ref or "").strip()
    if not ref or not isinstance(doc, dict):
        return doc
    components = doc.get("components")
    if not isinstance(components, list):
        return doc
    out = dict(doc)
    patched: list[dict] = []
    for c in components:
        if not isinstance(c, dict):
            continue
        props = c.get("properties")
        if not isinstance(props, list):
            props = []
        has_ref = False
        for p in props:
            if isinstance(p, dict):
                n = str(p.get("name") or "").strip().lower()
                if n in {"vat:container_ref", "vat.container_ref"}:
                    has_ref = True
                    break
        if not has_ref:
            props = [*props, {"name": "vat:container_ref", "value": ref}]
        patched.append({**c, "properties": props})
    out["components"] = patched
    return out
