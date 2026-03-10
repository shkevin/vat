"""Gitleaks JSON parser — secrets detection."""

import logging
import re

from app.schemas.ingest import CanonicalFindingPayload, CanonicalFindingType, CanonicalSeverity
from app.parsers.base import IngestParser
from app.parsers.utils import extract_scan_tag, normalize_snippet

logger = logging.getLogger(__name__)

MASK = "***REDACTED***"


def _mask_sensitive(line: str, secret: str) -> str | None:
    """Replace secret in line with mask. Returns normalized snippet or None."""
    if not line or not isinstance(line, str):
        return None
    line = line.strip()
    if not line:
        return None
    if secret and isinstance(secret, str) and secret.strip():
        escaped = re.escape(secret.strip())
        line = re.sub(escaped, MASK, line, flags=re.IGNORECASE)
    return normalize_snippet(line)


class GitleaksParser(IngestParser):
    """Parse Gitleaks JSON report to canonical format."""

    format_name = "gitleaks"

    def parse(self, raw: dict | list) -> list[CanonicalFindingPayload]:
        report_asset: str | None = None
        scan_tag: str | None = None
        if isinstance(raw, list):
            findings = raw
        elif isinstance(raw, dict):
            scan_tag = extract_scan_tag(raw)
            report_asset = raw.get("target") or raw.get("asset")
            findings = raw.get("findings") or raw.get("Findings") or raw.get("results") or []
            if not isinstance(findings, list):
                findings = []
        else:
            raise ValueError("Gitleaks input must be a JSON object or array of findings")

        payloads: list[CanonicalFindingPayload] = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            try:
                rule_id = f.get("RuleID") or f.get("ruleId") or f.get("rule_id") or "unknown"
                secret_type = (f.get("Description") or f.get("description") or "").strip() or None
                secret = f.get("Secret") or f.get("Match") or ""
                desc = f"Secret detected ({rule_id})" if secret else (f.get("Description") or f.get("description") or rule_id)
                file_path = f.get("File") or f.get("file") or f.get("path")
                if not file_path and f.get("Commit"):
                    file_path = f"commit:{str(f['Commit'])[:12]}"
                start_line = f.get("StartLine") or f.get("start_line") or f.get("line")
                if not file_path:
                    logger.debug("Skipping Gitleaks finding without File or Commit: %s", rule_id)
                    continue
                asset = (report_asset or str(file_path)).strip()
                line_content = f.get("Content") or f.get("line") or f.get("Line") or ""
                snippet_masked = _mask_sensitive(line_content, secret)
                fields = {
                    "cve_id": str(rule_id),
                    "severity": CanonicalSeverity.HIGH,
                    "description": str(desc)[:10000],
                    "file_path": str(file_path),
                    "line": int(start_line) if start_line is not None else None,
                    "title": rule_id,
                    "finding_type": CanonicalFindingType.SECRET,
                    "rule_id": str(rule_id),
                    "secret_type": secret_type[:128] if secret_type else None,
                    "snippet_masked": snippet_masked,
                }
                if scan_tag:
                    fields["tag"] = scan_tag
                payloads.append(self._create_payload(fields, asset=asset))
            except (KeyError, TypeError, ValueError) as e:
                logger.debug("Skipping Gitleaks finding: %s", e)
        return payloads
