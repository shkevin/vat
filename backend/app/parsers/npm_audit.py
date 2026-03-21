"""npm audit JSON parser — npm audit --json (v6 advisories, v7+ vulnerabilities)."""

import logging
import re

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
    "moderate": CanonicalSeverity.MEDIUM,
    "medium": CanonicalSeverity.MEDIUM,
    "low": CanonicalSeverity.LOW,
    "info": CanonicalSeverity.INFORMATIONAL,
    "informational": CanonicalSeverity.INFORMATIONAL,
}


def _severity(s: str | None) -> CanonicalSeverity:
    return _SEVERITY_MAP.get((s or "").lower(), CanonicalSeverity.MEDIUM)


def _censor_path(path: str | None) -> str | None:
    """Replace npm audit git hash placeholders for stable dedup."""
    if not path:
        return None
    return re.sub(r"[a-f0-9]{64}", "censored_by_npm_audit", path)


class NpmAuditParser(IngestParser):
    """Parse npm audit JSON (v6 advisories or v7+ vulnerabilities)."""

    format_name = "npm_audit"

    def parse(self, raw: dict | list) -> list[CanonicalFindingPayload]:
        if not isinstance(raw, dict):
            raise ValueError("npm audit input must be a JSON object")
        if raw.get("error"):
            err = raw["error"]
            raise ValueError(
                f"npm audit error: {err.get('code')} - {err.get('summary', '')}"
            )
        scan_tag = extract_scan_tag(raw)
        if raw.get("auditReportVersion") == 2:
            return self._parse_v7(raw, scan_tag)
        return self._parse_v6(raw, scan_tag)

    def _parse_v6(
        self, raw: dict, scan_tag: str | None = None
    ) -> list[CanonicalFindingPayload]:
        advisories = raw.get("advisories") or {}
        payloads: list[CanonicalFindingPayload] = []
        for adv_id, adv in advisories.items():
            if not isinstance(adv, dict):
                continue
            module_name = adv.get("module_name") or "unknown"
            cves = adv.get("cves") or []
            cve_id = cves[0] if cves else f"npm:{adv_id}"
            findings = adv.get("findings") or []
            first = findings[0] if findings else {}
            version = first.get("version") or ""
            paths = first.get("paths") or []
            path_str = paths[0] if paths else None
            file_path = (
                _censor_path(path_str) if path_str else f"package.json>{module_name}"
            )
            component = f"{module_name} {version}".strip()
            fields = {
                "cve_id": str(cve_id),
                "severity": _severity(adv.get("severity")),
                "description": (adv.get("overview") or adv.get("title") or "")[:10000],
                "component": component,
                "file_path": file_path,
                "title": adv.get("title") or cve_id,
                "finding_type": CanonicalFindingType.SCA,
            }
            if scan_tag:
                fields["tag"] = scan_tag
            payloads.append(self._create_payload(fields, asset=file_path))
        return payloads

    def _parse_v7(
        self, raw: dict, scan_tag: str | None = None
    ) -> list[CanonicalFindingPayload]:
        vulns = raw.get("vulnerabilities") or {}
        payloads: list[CanonicalFindingPayload] = []
        for pkg_name, pkg_data in vulns.items():
            if not isinstance(pkg_data, dict):
                continue
            via = pkg_data.get("via") or []
            if not via:
                continue
            severity = _severity(pkg_data.get("severity"))
            version_range = pkg_data.get("range") or ""
            nodes = pkg_data.get("nodes") or []
            file_path = _censor_path(nodes[0]) if nodes else f"package.json>{pkg_name}"
            component = f"{pkg_name} {version_range}".strip() or pkg_name
            for v in via:
                if v == "ms" or v == "npm" or not isinstance(v, dict):
                    continue
                vuln_id = str(
                    v.get("source") or v.get("name") or v.get("dependency") or pkg_name
                )
                title = v.get("title") or vuln_id
                desc = v.get("url") or v.get("description") or title
                fields = {
                    "cve_id": vuln_id,
                    "severity": _severity(v.get("severity")) or severity,
                    "description": str(desc)[:10000],
                    "component": component,
                    "file_path": file_path,
                    "title": title,
                    "finding_type": CanonicalFindingType.SCA,
                }
                if scan_tag:
                    fields["tag"] = scan_tag
                payloads.append(self._create_payload(fields, asset=file_path))
        return payloads
