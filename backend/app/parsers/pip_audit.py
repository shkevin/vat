"""pip-audit JSON parser — pip-audit --format json."""

import logging

from app.schemas.ingest import CanonicalFindingPayload, CanonicalFindingType, CanonicalSeverity
from app.parsers.base import IngestParser
from app.parsers.utils import extract_scan_tag

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": CanonicalSeverity.CRITICAL,
    "high": CanonicalSeverity.HIGH,
    "medium": CanonicalSeverity.MEDIUM,
    "low": CanonicalSeverity.LOW,
    "info": CanonicalSeverity.INFORMATIONAL,
}


def _severity(s: str | None) -> CanonicalSeverity:
    return _SEVERITY_MAP.get((s or "").lower(), CanonicalSeverity.MEDIUM)


class PipAuditParser(IngestParser):
    """Parse pip-audit JSON (legacy array or dependencies format)."""

    format_name = "pip_audit"

    def parse(self, raw: dict | list) -> list[CanonicalFindingPayload]:
        if isinstance(raw, list):
            return self._parse_legacy(raw, None)
        if isinstance(raw, dict) and "dependencies" in raw:
            return self._parse_new(raw, extract_scan_tag(raw))
        if isinstance(raw, dict):
            return []
        raise ValueError("pip-audit input must be JSON array or object with dependencies")

    def _parse_legacy(self, data: list, scan_tag: str | None) -> list[CanonicalFindingPayload]:
        payloads: list[CanonicalFindingPayload] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            payloads.extend(self._item_findings(item, scan_tag))
        return payloads

    def _parse_new(self, data: dict, scan_tag: str | None = None) -> list[CanonicalFindingPayload]:
        payloads: list[CanonicalFindingPayload] = []
        for dep in data.get("dependencies") or []:
            if not isinstance(dep, dict):
                continue
            payloads.extend(self._item_findings(dep, scan_tag))
        return payloads

    def _item_findings(self, item: dict, scan_tag: str | None = None) -> list[CanonicalFindingPayload]:
        payloads: list[CanonicalFindingPayload] = []
        name = item.get("name") or "unknown"
        version = item.get("version") or ""
        if item.get("skip_reason"):
            return []
        for vuln in item.get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = vuln.get("id") or f"PYSEC-{name}"
            desc = vuln.get("description") or vuln_id
            fix_versions = vuln.get("fix_versions") or []
            if fix_versions:
                desc = f"{desc}\nFix: upgrade to {', '.join(fix_versions)}"
            component = f"{name} {version}".strip()
            fields = {
                "cve_id": str(vuln_id),
                "severity": CanonicalSeverity.MEDIUM,
                "description": str(desc)[:10000],
                "component": component,
                "file_path": f"requirements.txt>{name}",
                "title": vuln_id,
                "finding_type": CanonicalFindingType.SCA,
            }
            if scan_tag:
                fields["tag"] = scan_tag
            payloads.append(self._create_payload(fields, asset=f"requirements.txt>{name}"))
        return payloads
