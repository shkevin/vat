"""Semgrep JSON parser — semgrep scan --json."""

import logging

from app.schemas.ingest import (
    CanonicalFindingPayload,
    CanonicalFindingType,
    CanonicalSeverity,
)
from app.parsers.base import IngestParser
from app.parsers.utils import extract_cwe_id, extract_scan_tag, normalize_snippet

logger = logging.getLogger(__name__)

_SEMGREP_TO_VAT_SEVERITY = {
    "error": CanonicalSeverity.HIGH,
    "warning": CanonicalSeverity.MEDIUM,
    "info": CanonicalSeverity.LOW,
    "experimental": CanonicalSeverity.INFORMATIONAL,
}


def _map_severity(s: str | None) -> CanonicalSeverity:
    if not s:
        return CanonicalSeverity.MEDIUM
    return _SEMGREP_TO_VAT_SEVERITY.get(str(s).lower(), CanonicalSeverity.MEDIUM)


class SemgrepParser(IngestParser):
    """Parse Semgrep JSON (semgrep scan --json) to canonical format."""

    format_name = "semgrep"

    def parse(self, raw: dict | list) -> list[CanonicalFindingPayload]:
        if not isinstance(raw, dict):
            raise ValueError("Semgrep input must be a JSON object")
        scan_tag = extract_scan_tag(raw)
        results = raw.get("results") or []
        if not isinstance(results, list):
            raise ValueError("Semgrep input must have results array")

        payloads: list[CanonicalFindingPayload] = []
        for r in results:
            if not isinstance(r, dict):
                continue
            try:
                check_id = (
                    r.get("check_id")
                    or r.get("rule_id")
                    or r.get("ruleId")
                    or "unknown"
                )
                path = (
                    r.get("path")
                    or r.get("extra", {}).get("metadata", {}).get("source")
                    or ""
                ).strip()
                if not path:
                    logger.debug("Skipping Semgrep result without path: %s", check_id)
                    continue
                start = r.get("start") or {}
                line = start.get("line") if isinstance(start, dict) else None
                extra = r.get("extra") or {}
                metadata = extra.get("metadata") or {}
                cwe_list = metadata.get("cwe") or metadata.get("CWE")
                cwe_id = extract_cwe_id(cwe_list)
                message = extra.get("message") or extra.get("lines") or check_id
                if isinstance(message, str):
                    pass
                elif isinstance(message, dict):
                    message = message.get("message") or check_id
                else:
                    message = str(message)[:500] if message else check_id
                # extra.lines: matched line content (Semgrep AppSec Platform; may be absent in CE)
                snippet_raw = extra.get("lines")
                snippet_masked = normalize_snippet(snippet_raw) if snippet_raw else None
                sev = _map_severity(extra.get("severity"))
                fields = {
                    "cve_id": str(check_id),
                    "severity": sev,
                    "description": str(message)[:10000],
                    "file_path": path,
                    "line": line,
                    "title": check_id,
                    "finding_type": CanonicalFindingType.SAST,
                    "rule_id": str(check_id),
                    "cwe_id": cwe_id,
                    "snippet_masked": snippet_masked,
                }
                if scan_tag:
                    fields["tag"] = scan_tag
                payloads.append(self._create_payload(fields, asset=path))
            except (KeyError, TypeError, ValueError) as e:
                logger.debug("Skipping Semgrep result: %s", e)
        return payloads
