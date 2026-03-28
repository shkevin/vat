"""Normalize scanner output for VAT ingest (asset name, target, scan tag)."""

import re

from vat_scanner.container_digest import normalize_sha256_digest
from vat_scanner.container_identity import (
    canonical_container_asset,
    image_digest_from_ref,
)

# Key injected into reports for backend parsers to set finding.tag (package delineation)
VAT_SCAN_TAG_KEY = "_vat_scan_tag"

# Key for source image/container when scanning a bundle — parser uses for file_path (provenance)
VAT_SOURCE_IMAGE_KEY = "_vat_source_image"

# Key for original path when scanning filesystem — parser uses for file_path (we overwrite Target for grouping)
VAT_SOURCE_PATH_KEY = "_vat_source_path"

# Aikido-style container identity (must match backend app.parsers.utils)
VAT_CONTAINER_IMAGE_KEY = "_vat_container_image"
VAT_CONTAINER_TAG_KEY = "_vat_container_tag"
VAT_CONTAINER_DIGEST_KEY = "_vat_container_digest"


def _sha256_value_from_trivy(s: str | None) -> str | None:
    """Normalize ``sha256:<hex>`` (ArtifactID / ImageID) to canonical digest string."""
    if not isinstance(s, str):
        return None
    v = s.strip()
    if not v.startswith("sha256:"):
        return None
    hex_part = re.sub(r"[^0-9a-f]", "", v[7:].lower())[:64]
    if len(hex_part) < 12:
        return None
    return f"sha256:{hex_part}"


def _digest_from_trivy_report(report: dict) -> str | None:
    """
    Trivy JSON often includes manifest-linked digests in RepoDigests even when the
    reference string is only ``repo:tag`` (no ``@sha256``), e.g. docker pulls.

    For ``trivy image --input <oci_layout>``, RepoDigests is often **null** (no
    registry metadata); Trivy still sets **ArtifactID** / **Metadata.ImageID**
    (image config digest). We use those as a last resort — they may differ from
    a registry **manifest** digest used elsewhere; RepoDigests remains preferred.
    """
    if not isinstance(report, dict):
        return None
    candidates: list[str] = []
    meta = report.get("Metadata") or report.get("metadata")
    if isinstance(meta, dict):
        for key in ("RepoDigests", "repoDigests"):
            vals = meta.get(key)
            if isinstance(vals, list):
                candidates.extend(str(x) for x in vals)
        for key in ("ArtifactName", "artifactName"):
            an = meta.get(key)
            if isinstance(an, str) and an.strip():
                candidates.append(an.strip())
    for key in ("RepoDigests", "repoDigests"):
        vals = report.get(key)
        if isinstance(vals, list):
            candidates.extend(str(x) for x in vals)
    for key in ("ArtifactName", "artifactName"):
        an = report.get(key)
        if isinstance(an, str) and an.strip():
            candidates.append(an.strip())
    for c in candidates:
        d = image_digest_from_ref(c)
        if d:
            return d
    for key in ("ArtifactID", "artifactID"):
        raw = report.get(key)
        d = _sha256_value_from_trivy(raw if isinstance(raw, str) else None)
        if d:
            return d
    if isinstance(meta, dict):
        for key in ("ImageID", "imageID"):
            raw = meta.get(key)
            d = _sha256_value_from_trivy(raw if isinstance(raw, str) else None)
            if d:
                return d
    return None


def _inject_scan_tag(report: dict, scan_tag: str) -> None:
    """Inject scan tag into report for backend parsers. Mutates in place."""
    if isinstance(report, dict) and scan_tag:
        report[VAT_SCAN_TAG_KEY] = scan_tag


def normalize_gitleaks(report: dict | list, asset_name: str, scan_tag: str = "") -> dict | list:
    """Set target/asset for Gitleaks so findings group under the scan asset."""
    if isinstance(report, list):
        out = {"findings": report, "target": asset_name}
        _inject_scan_tag(out, scan_tag)
        return out
    if isinstance(report, dict):
        report = dict(report)
        report["target"] = asset_name
        _inject_scan_tag(report, scan_tag)
        return report
    return report


def normalize_trivy(
    report: dict,
    asset_name: str,
    scan_tag: str = "",
    *,
    source_image: str | None = None,
    image_ref: str | None = None,
    rewrite_target: bool = True,
    canonical_image_digest: str | None = None,
) -> dict:
    """
    Set Target in Trivy Results to asset_name so findings group under the bundle asset.
    When rewrite_target=False, preserve original Target and only inject metadata.
    When scanning with --asset (e.g. kamiwaza-bundle), all package findings appear as
    sub-assets within that parent asset instead of as top-level package assets.
    When source_image is provided (e.g. container label), store it so the parser can
    set file_path for provenance — e.g. "kamiwaza-images-core-release-0.11.0".
    When image_ref is set (docker RepoTags / OCI ref.name), inject Aikido-style
    ``containers/images/<name>`` and image tag for correlation (scanner-agnostic).
    When ``canonical_image_digest`` is set (from ``container_digest.compute`` on the
    artifact), it wins over Trivy-reported digests so every scanner type shares
    one deterministic value per container source.
    """
    results = report.get("Results") or report.get("results") or []
    can_img: str | None = None
    can_tag: str | None = None
    can_dig: str | None = None
    if source_image and str(source_image).strip():
        can_img, can_tag = canonical_container_asset(image_ref, str(source_image).strip())
    if canonical_image_digest and str(canonical_image_digest).strip():
        can_dig = normalize_sha256_digest(str(canonical_image_digest).strip())
    if not can_dig and image_ref and str(image_ref).strip():
        can_dig = image_digest_from_ref(str(image_ref).strip())
    if not can_dig:
        can_dig = _digest_from_trivy_report(report)
    for r in results:
        if not isinstance(r, dict):
            continue
        original_target = r.get("Target") or r.get("target") or ""
        original_target = str(original_target).strip() if original_target else ""
        if rewrite_target:
            r["Target"] = asset_name
            r["target"] = asset_name
        if source_image and str(source_image).strip():
            r[VAT_SOURCE_IMAGE_KEY] = str(source_image).strip()
        elif original_target:
            # Preserve original path for fs scans so parser can set file_path (e.g. path/to/.env)
            r[VAT_SOURCE_PATH_KEY] = original_target
        if can_img and can_tag:
            r[VAT_CONTAINER_IMAGE_KEY] = can_img
            r[VAT_CONTAINER_TAG_KEY] = can_tag
        if can_dig:
            r[VAT_CONTAINER_DIGEST_KEY] = can_dig
    report["Results"] = results
    _inject_scan_tag(report, scan_tag)
    return report


def normalize_grype(report: dict, asset_name: str, scan_tag: str = "") -> dict:
    """Replace source.target with asset_name."""
    src = report.get("source") or {}
    if isinstance(src, dict):
        src["target"] = asset_name
        src["userInput"] = asset_name
    report["source"] = src
    _inject_scan_tag(report, scan_tag)
    return report
