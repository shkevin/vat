"""Snyk JSON parser — vulnerabilities from snyk test --json."""

import logging

from app.schemas.ingest import CanonicalFindingPayload, CanonicalFindingType, CanonicalSeverity
from app.parsers.base import IngestParser

logger = logging.getLogger(__name__)

_SNYK_TO_VAT_SEVERITY = {
    "critical": CanonicalSeverity.CRITICAL,
    "high": CanonicalSeverity.HIGH,
    "medium": CanonicalSeverity.MEDIUM,
    "low": CanonicalSeverity.LOW,
    "info": CanonicalSeverity.INFORMATIONAL,
    "informational": CanonicalSeverity.INFORMATIONAL,
}


def _map_severity(s: str | None) -> CanonicalSeverity:
    if not s:
        return CanonicalSeverity.MEDIUM
    return _SNYK_TO_VAT_SEVERITY.get(str(s).lower(), CanonicalSeverity.MEDIUM)


def _snyk_package_manager_to_ecosystem(pm: str | None) -> str | None:
    """Map Snyk packageManager to ecosystem."""
    if not pm:
        return None
    pm = str(pm).lower()
    mapping = {"npm": "npm", "yarn": "npm", "pnpm": "npm", "pip": "pypi", "poetry": "pypi", "maven": "maven", "gradle": "maven", "nuget": "nuget", "gomod": "go", "composer": "composer", "rubygems": "rubygems"}
    return mapping.get(pm) or pm


def _collect_vulnerabilities(raw: dict | list) -> list[dict]:
    """Extract vulnerabilities from Snyk JSON. Handles top-level and nested."""
    vulns: list[dict] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                vulns.extend(_collect_vulnerabilities(item))
        return vulns
    if not isinstance(raw, dict):
        return []
    top = raw.get("vulnerabilities") or raw.get("Vulnerabilities")
    if isinstance(top, list):
        for v in top:
            if isinstance(v, dict):
                vulns.append(v)
    return vulns


class SnykParser(IngestParser):
    """Parse Snyk JSON (snyk test --json) to canonical format."""

    format_name = "snyk"

    def parse(self, raw: dict | list) -> list[CanonicalFindingPayload]:
        if isinstance(raw, list):
            raw = {"vulnerabilities": raw}
        if not isinstance(raw, dict):
            raise ValueError("Snyk input must be a JSON object or array")
        vulns = _collect_vulnerabilities(raw)
        if not vulns and not (raw.get("vulnerabilities") or raw.get("Vulnerabilities")):
            vulns = _collect_vulnerabilities(raw.get("runs", raw.get("projects", [raw])))

        # Ecosystem from packageManager (top-level or from package)
        ecosystem = _snyk_package_manager_to_ecosystem(raw.get("packageManager") or raw.get("package_manager"))

        # Asset context: Snyk provides targetFile, projectName, or displayTargetFile
        asset = (
            (raw.get("targetFile") or raw.get("target_file") or "").strip()
            or (raw.get("projectName") or raw.get("project_name") or "").strip()
            or (raw.get("displayTargetFile") or raw.get("display_target_file") or "").strip()
        )
        if not asset:
            return []  # No asset context — ingest validation would fail; skip entire parse

        payloads: list[CanonicalFindingPayload] = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            try:
                cve_id = v.get("id") or v.get("name") or "unknown"
                idents = v.get("identifiers")
                if isinstance(idents, dict):
                    cves = idents.get("CVE")
                    if isinstance(cves, list) and cves:
                        cve_id = str(cves[0])
                cve_id = str(cve_id)
                pkg = v.get("packageName") or v.get("package") or ""
                ver = v.get("version") or v.get("installedVersion") or ""
                component = f"{pkg} {ver}".strip() if pkg or ver else None
                title = v.get("title") or v.get("name") or cve_id
                desc = v.get("description") or v.get("from", [])
                if isinstance(desc, list):
                    desc = " → ".join(str(x) for x in desc[:5]) if desc else title
                desc = str(desc)[:10000]
                sev = _map_severity(v.get("severity"))
                cvss = v.get("CVSSv3") or v.get("cvssScore")
                cvss_str = str(cvss) if cvss is not None else None
                payloads.append(
                    self._create_payload(
                        {
                            "cve_id": cve_id,
                            "severity": sev,
                            "description": desc,
                            "component": component,
                            "title": title,
                            "finding_type": CanonicalFindingType.SCA,
                            "cvss": cvss_str,
                            "ecosystem": ecosystem or _snyk_package_manager_to_ecosystem(v.get("packageManager") or v.get("package_manager")),
                        },
                        asset=asset,
                    )
                )
            except (KeyError, TypeError, ValueError) as e:
                logger.debug("Skipping Snyk vulnerability: %s", e)
        return payloads
