"""Normalize scanner output for VAT ingest (asset name, target, scan tag)."""

# Key injected into reports for backend parsers to set finding.tag (package delineation)
VAT_SCAN_TAG_KEY = "_vat_scan_tag"

# Key for source image/container when scanning a bundle — parser uses for file_path (provenance)
VAT_SOURCE_IMAGE_KEY = "_vat_source_image"

# Key for original path when scanning filesystem — parser uses for file_path (we overwrite Target for grouping)
VAT_SOURCE_PATH_KEY = "_vat_source_path"


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
) -> dict:
    """
    Set Target in Trivy Results to asset_name so findings group under the bundle asset.
    When scanning with --asset (e.g. kamiwaza-bundle), all package findings appear as
    sub-assets within that parent asset instead of as top-level package assets.
    When source_image is provided (e.g. container label), store it so the parser can
    set file_path for provenance — e.g. "kamiwaza-images-core-release-0.11.0".
    """
    results = report.get("Results") or report.get("results") or []
    for r in results:
        if not isinstance(r, dict):
            continue
        original_target = r.get("Target") or r.get("target") or ""
        original_target = str(original_target).strip() if original_target else ""
        r["Target"] = asset_name
        r["target"] = asset_name
        if source_image and str(source_image).strip():
            r[VAT_SOURCE_IMAGE_KEY] = str(source_image).strip()
        elif original_target:
            # Preserve original path for fs scans so parser can set file_path (e.g. path/to/.env)
            r[VAT_SOURCE_PATH_KEY] = original_target
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
