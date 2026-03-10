"""Extract SBOM packages from scanner reports (Trivy, Grype) for import_sbom."""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Map Trivy Type / Grype ecosystem to CycloneDX language
_TYPE_TO_LANGUAGE = {
    "npm": "javascript",
    "yarn": "javascript",
    "pnpm": "javascript",
    "pip": "python",
    "pipenv": "python",
    "poetry": "python",
    "gomod": "go",
    "go": "go",
    "cargo": "rust",
    "maven": "java",
    "gradle": "java",
    "composer": "php",
    "rubygems": "ruby",
    "gem": "ruby",
    "nuget": "csharp",
    "dotnet": "csharp",
    "alpine": "",
    "apk": "",
    "deb": "",
    "rpm": "",
}


def _trivy_type_to_language(t: str) -> str:
    return _TYPE_TO_LANGUAGE.get((t or "").lower(), (t or "").lower() or "")


def _make_component(
    name: str,
    version: str,
    license_id: Optional[str],
    component: Optional[str],
    language: str,
) -> dict:
    """Build CycloneDX-compatible component for _parse_cyclonedx."""
    c: dict = {
        "name": name,
        "version": version,
        "licenses": [{"license": {"id": license_id}}] if license_id else [],
        "group": component,
        "language": language or "",
    }
    return c


def extract_sbom_from_trivy(raw: dict, source: str) -> Optional[dict]:
    """
    Extract package list from Trivy JSON and build CycloneDX components.
    Returns { "components": [...] } or None if no packages found.
    """
    results = raw.get("Results") or raw.get("results") or []
    if not isinstance(results, list):
        return None

    seen: set[tuple[str, str, str]] = set()
    components: list[dict] = []

    for res in results:
        if not isinstance(res, dict):
            continue
        target = (res.get("Target") or res.get("target") or "").strip()
        res_type = res.get("Type") or res.get("type") or ""
        language = _trivy_type_to_language(res_type)

        # 1. Packages array (Trivy 0.20+)
        for pkg in res.get("Packages") or res.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            name = (pkg.get("Name") or pkg.get("name") or "").strip()
            version = (pkg.get("Version") or pkg.get("version") or "").strip()
            if not name:
                continue
            key = (name, version, target)
            if key in seen:
                continue
            seen.add(key)
            license_id = None
            licenses = pkg.get("Licenses") or pkg.get("licenses") or []
            if licenses and isinstance(licenses[0], dict):
                lic = licenses[0]
                license_id = lic.get("ID") or lic.get("id") or lic.get("Name") or lic.get("name")
            elif licenses:
                license_id = str(licenses[0])
            components.append(_make_component(name, version, license_id, target, language))

        # 2. Vulnerabilities (packages with vulns, may not be in Packages)
        for v in res.get("Vulnerabilities") or res.get("vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            name = (v.get("PkgName") or v.get("pkgName") or "").strip()
            version = (v.get("InstalledVersion") or v.get("installedVersion") or "").strip()
            if not name:
                continue
            key = (name, version, target)
            if key in seen:
                continue
            seen.add(key)
            components.append(_make_component(name, version, None, target, language))

        # 3. Licenses (packages with license info)
        for lic in res.get("Licenses") or res.get("licenses") or []:
            if not isinstance(lic, dict):
                continue
            name = (lic.get("PkgName") or lic.get("pkgName") or "").strip()
            version = (lic.get("Version") or lic.get("version") or "").strip()
            license_id = lic.get("Name") or lic.get("name") or lic.get("ID") or lic.get("id")
            if not name:
                continue
            key = (name, version, target)
            if key in seen:
                # Update license on existing component
                for c in components:
                    if c.get("name") == name and c.get("version") == version and c.get("group") == (target or None):
                        if not (c.get("licenses") or []) and license_id:
                            c["licenses"] = [{"license": {"id": license_id}}]
                        break
                continue
            seen.add(key)
            components.append(_make_component(name, version, license_id, target, language))

    if not components:
        return None
    return {"components": components}


def extract_sbom_from_grype(raw: dict, source: str) -> Optional[dict]:
    """
    Extract package list from Grype JSON and build CycloneDX components.
    Returns { "components": [...] } or None if no packages found.
    """
    matches = raw.get("matches") or []
    if not isinstance(matches, list):
        return None

    source_obj = raw.get("source") or {}
    target_val = source_obj.get("target") if isinstance(source_obj, dict) else None
    if isinstance(target_val, dict):
        asset = (target_val.get("userInput") or target_val.get("target") or "").strip()
    else:
        asset = str(target_val or "").strip()

    seen: set[tuple[str, str]] = set()
    components: list[dict] = []

    for m in matches:
        if not isinstance(m, dict):
            continue
        artifact = m.get("artifact") or {}
        if not isinstance(artifact, dict):
            continue
        name = (artifact.get("name") or "").strip()
        version = (artifact.get("version") or "").strip()
        if not name:
            continue
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        # Grype doesn't provide license in match; use purl for language hint if needed
        purl = artifact.get("purl") or ""
        language = ""
        if purl and "pkg:npm/" in purl:
            language = "javascript"
        elif purl and "pkg:pypi/" in purl:
            language = "python"
        elif purl and "pkg:maven/" in purl:
            language = "java"
        elif purl and "pkg:golang/" in purl:
            language = "go"
        components.append(_make_component(name, version, None, asset or None, language))

    if not components:
        return None
    return {"components": components}


def extract_sbom_from_report(
    parser_id: str,
    raw: dict | list | bytes,
    source: str,
) -> Optional[dict]:
    """
    Extract SBOM from scanner report if supported.
    Returns CycloneDX-like { "components": [...] } or None.
    """
    if not isinstance(raw, dict):
        return None
    parser_id = (parser_id or "").strip().lower()
    if parser_id == "trivy":
        return extract_sbom_from_trivy(raw, source)
    if parser_id == "grype":
        return extract_sbom_from_grype(raw, source)
    if parser_id == "cyclonedx":
        # Raw is already CycloneDX; pass through if it has components
        if raw.get("components"):
            return raw
        return None
    return None
