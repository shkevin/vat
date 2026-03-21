"""Grype JSON parser — grype -o json (container, filesystem, SBOM)."""

import logging

from app.schemas.ingest import (
    CanonicalFindingPayload,
    CanonicalFindingType,
    CanonicalSeverity,
)
from app.parsers.base import IngestParser
from app.parsers.utils import extract_scan_tag

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": CanonicalSeverity.CRITICAL,
    "high": CanonicalSeverity.HIGH,
    "medium": CanonicalSeverity.MEDIUM,
    "low": CanonicalSeverity.LOW,
    "negligible": CanonicalSeverity.INFORMATIONAL,
    "informational": CanonicalSeverity.INFORMATIONAL,
    "unknown": CanonicalSeverity.INFORMATIONAL,
}


def _severity(s: str | None) -> CanonicalSeverity:
    return _SEVERITY_MAP.get((s or "").lower(), CanonicalSeverity.MEDIUM)


class GrypeParser(IngestParser):
    """Parse Grype JSON (grype -o json). Supports deb, rpm, apk, npm, pypi, etc."""

    format_name = "grype"

    def parse(self, raw: dict | list) -> list[CanonicalFindingPayload]:
        if not isinstance(raw, dict):
            raise ValueError("Grype input must be a JSON object")
        scan_tag = extract_scan_tag(raw)
        matches = raw.get("matches") or []
        if not isinstance(matches, list):
            raise ValueError("Grype input must have matches array")
        # Asset context: Grype source.target (container image) or first artifact location path
        source = raw.get("source") or {}
        target_val = source.get("target") if isinstance(source, dict) else None
        if isinstance(target_val, dict):
            asset = (
                target_val.get("userInput") or target_val.get("target") or ""
            ).strip()
        else:
            asset = str(target_val or "").strip()
        payloads: list[CanonicalFindingPayload] = []
        for m in matches:
            if not isinstance(m, dict):
                continue
            try:
                p = self._parse_match(m, asset, scan_tag)
                if p:
                    payloads.append(p)
            except (KeyError, TypeError, ValueError) as e:
                logger.debug("Skipping Grype match: %s", e)
        return payloads

    def _parse_match(
        self, m: dict, asset: str, scan_tag: str | None = None
    ) -> CanonicalFindingPayload | None:
        vuln = m.get("vulnerability") or {}
        artifact = m.get("artifact") or {}
        vuln_id = vuln.get("id") or "unknown"
        artifact_name = artifact.get("name") or "unknown"
        artifact_version = artifact.get("version") or ""
        component = f"{artifact_name} {artifact_version}".strip()
        file_path = None
        locs = artifact.get("locations") or []
        if locs and isinstance(locs[0], dict) and locs[0].get("path"):
            file_path = locs[0].get("path")
        # Use artifact path as asset if source.target not set (e.g. filesystem scan)
        if not asset and file_path:
            asset = file_path
        if not asset:
            return None
        desc_parts = []
        if vuln.get("description"):
            desc_parts.append(vuln["description"])
        if vuln.get("urls"):
            urls = vuln["urls"]
            if isinstance(urls, list) and urls:
                desc_parts.append(f"URL: {urls[0]}")
            elif isinstance(urls, str):
                desc_parts.append(f"URL: {urls}")
        if not desc_parts and m.get("relatedVulnerabilities"):
            rel = m["relatedVulnerabilities"][0]
            if isinstance(rel, dict) and rel.get("description"):
                desc_parts.append(rel["description"])
        desc = "\n".join(desc_parts) or vuln_id
        cvss = None
        cvss_v = vuln.get("cvss") or []
        if not cvss_v and m.get("relatedVulnerabilities"):
            rel = m["relatedVulnerabilities"][0]
            if isinstance(rel, dict):
                cvss_v = rel.get("cvss") or []
        if cvss_v and isinstance(cvss_v[0], dict):
            metrics = cvss_v[0].get("metrics") or {}
            cvss = str(metrics.get("baseScore") or cvss_v[0].get("baseScore") or "")
        fix_versions = []
        if "fix" in vuln and isinstance(vuln["fix"], dict):
            fix_versions = vuln["fix"].get("versions") or []
        if fix_versions:
            desc = f"{desc}\nFix: upgrade to {', '.join(fix_versions)}"
        fields = {
            "cve_id": str(vuln_id),
            "severity": _severity(vuln.get("severity")),
            "description": str(desc)[:10000],
            "component": component,
            "file_path": file_path,
            "title": f"{vuln_id} in {artifact_name}:{artifact_version}",
            "finding_type": CanonicalFindingType.SCA,
            "cvss": cvss,
        }
        if scan_tag:
            fields["tag"] = scan_tag
        return self._create_payload(fields, asset=asset)
