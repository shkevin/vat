"""Trivy JSON parser — vulnerabilities, misconfigurations, secrets, licenses."""

import logging
import re

from app.schemas.ingest import (
    CanonicalFindingPayload,
    CanonicalFindingType,
    CanonicalSeverity,
)
from app.parsers.utils import (
    extract_scan_tag,
    normalize_snippet,
    VAT_SOURCE_IMAGE_KEY,
    VAT_SOURCE_PATH_KEY,
)

MASK = "***REDACTED***"


def _mask_secret_in_line(line: str, secret: str) -> str | None:
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


from app.parsers.base import IngestParser

logger = logging.getLogger(__name__)

_TRIVY_TO_VAT_SEVERITY = {
    "critical": CanonicalSeverity.CRITICAL,
    "high": CanonicalSeverity.HIGH,
    "medium": CanonicalSeverity.MEDIUM,
    "low": CanonicalSeverity.LOW,
    "info": CanonicalSeverity.INFORMATIONAL,
    "informational": CanonicalSeverity.INFORMATIONAL,
    "unknown": CanonicalSeverity.INFORMATIONAL,
}


def _map_severity(s: str | None) -> CanonicalSeverity:
    if not s:
        return CanonicalSeverity.MEDIUM
    return _TRIVY_TO_VAT_SEVERITY.get(str(s).lower(), CanonicalSeverity.MEDIUM)


def _trivy_type_to_ecosystem(t: str) -> str | None:
    """Map Trivy Result Type to ecosystem for grouping."""
    if not t:
        return None
    t = str(t).lower()
    mapping = {
        "debian": "debian",
        "ubuntu": "debian",
        "npm": "npm",
        "yarn": "npm",
        "pnpm": "npm",
        "pip": "pypi",
        "pipenv": "pypi",
        "poetry": "pypi",
        "go": "go",
        "gomod": "go",
        "cargo": "cargo",
        "rust": "cargo",
        "maven": "maven",
        "gradle": "maven",
        "composer": "composer",
        "php": "composer",
        "rubygems": "rubygems",
        "gem": "rubygems",
        "nuget": "nuget",
        "dotnet": "nuget",
        "alpine": "alpine",
        "apk": "alpine",
        "redhat": "rpm",
        "rpm": "rpm",
        "centos": "rpm",
        "fedora": "rpm",
    }
    return mapping.get(t) or (t if t in ("os", "library", "container") else None)


class TrivyParser(IngestParser):
    """Parse Trivy JSON (vulns, misconfig, secrets, licenses) to canonical format."""

    format_name = "trivy"

    def parse(self, raw: dict | list) -> list[CanonicalFindingPayload]:
        if isinstance(raw, list):
            # Trivy can output Results at top level in some modes
            raw = {"Results": raw}
        if not isinstance(raw, dict):
            raise ValueError("Trivy input must be a JSON object")
        scan_tag = extract_scan_tag(raw)
        results = raw.get("Results") or raw.get("results") or []
        if not isinstance(results, list):
            raise ValueError("Trivy input must have Results array")

        payloads: list[CanonicalFindingPayload] = []
        for res in results:
            if not isinstance(res, dict):
                continue
            target = res.get("Target") or res.get("target") or ""
            target_str = str(target).strip() if target else ""
            # Skip results without target: asset context (image/branch/tag) is required for ingest
            if not target_str:
                continue
            res_type = res.get("Type") or res.get("type") or ""
            ecosystem = _trivy_type_to_ecosystem(str(res_type))
            source_image = res.get(VAT_SOURCE_IMAGE_KEY) or ""
            source_image = str(source_image).strip() if source_image else None
            source_path = res.get(VAT_SOURCE_PATH_KEY) or ""
            source_path = str(source_path).strip() if source_path else None

            for p in self._parse_vulnerabilities(
                res, target_str, ecosystem, scan_tag, source_image, source_path
            ):
                payloads.append(p)
            for p in self._parse_misconfigurations(
                res, target_str, scan_tag, source_image, source_path
            ):
                payloads.append(p)
            for p in self._parse_secrets(
                res, target_str, scan_tag, source_image, source_path
            ):
                payloads.append(p)
            for p in self._parse_licenses(
                res, target_str, ecosystem, scan_tag, source_image, source_path
            ):
                payloads.append(p)

        return payloads

    def _parse_vulnerabilities(
        self,
        res: dict,
        target: str,
        ecosystem: str | None = None,
        scan_tag: str | None = None,
        source_image: str | None = None,
        source_path: str | None = None,
    ) -> list[CanonicalFindingPayload]:
        vulns = res.get("Vulnerabilities") or res.get("vulnerabilities") or []
        if not isinstance(vulns, list):
            return []
        out: list[CanonicalFindingPayload] = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            try:
                cve_id = (
                    v.get("VulnerabilityID")
                    or v.get("vulnerabilityID")
                    or v.get("ID")
                    or "unknown"
                )
                pkg = v.get("PkgName") or v.get("pkgName") or ""
                ver = v.get("InstalledVersion") or v.get("installedVersion") or ""
                component = f"{pkg} {ver}".strip() if pkg or ver else (target or None)
                file_path = (
                    source_image or source_path or target or ""
                ).strip() or None
                if not component and not file_path:
                    continue
                title = v.get("Title") or v.get("title") or cve_id
                desc = v.get("Description") or v.get("description") or title
                sev = _map_severity(v.get("Severity") or v.get("severity"))
                cvss_val = v.get("CVSS") or v.get("cvss")
                cvss_str = None
                if isinstance(cvss_val, dict):
                    cvss_str = str(
                        cvss_val.get("nvd", {}).get("V3Score")
                        or cvss_val.get("V3Score")
                        or ""
                    )
                elif cvss_val is not None:
                    cvss_str = str(cvss_val)
                fields = {
                    "cve_id": str(cve_id),
                    "severity": sev,
                    "description": str(desc)[:10000],
                    "component": component,
                    "file_path": file_path,
                    "title": title,
                    "finding_type": CanonicalFindingType.SCA,
                    "cvss": cvss_str,
                    "ecosystem": ecosystem,
                }
                if scan_tag:
                    fields["tag"] = scan_tag
                out.append(self._create_payload(fields, asset=target))
            except (KeyError, TypeError, ValueError) as e:
                logger.debug("Skipping Trivy vulnerability: %s", e)
        return out

    def _parse_misconfigurations(
        self,
        res: dict,
        target: str,
        scan_tag: str | None = None,
        source_image: str | None = None,
        source_path: str | None = None,
    ) -> list[CanonicalFindingPayload]:
        mis = res.get("Misconfigurations") or res.get("misconfigurations") or []
        if not isinstance(mis, list):
            return []
        target_str = (target or "").strip()
        if not target_str:
            return []
        base_path = (source_image or source_path or target or "").strip() or None
        out: list[CanonicalFindingPayload] = []
        for m in mis:
            if not isinstance(m, dict):
                continue
            try:
                rule_id = m.get("ID") or m.get("id") or "unknown"
                title = m.get("Title") or m.get("title") or rule_id
                msg = m.get("Message") or m.get("message") or title
                sev = _map_severity(m.get("Severity") or m.get("severity"))
                # Per-item path when available (Trivy may include CauseMetadata, etc.)
                item_path = (
                    m.get("Path")
                    or m.get("path")
                    or m.get("FilePath")
                    or m.get("filePath")
                    or m.get("Target")
                    or m.get("File")
                    or m.get("file")
                )
                item_path = str(item_path).strip() if item_path else ""
                if source_image and item_path:
                    file_path = f"{source_image}:{item_path}"
                elif source_image or item_path:
                    file_path = source_image or item_path
                else:
                    file_path = base_path
                fields = {
                    "cve_id": str(rule_id),
                    "severity": sev,
                    "description": str(msg)[:10000],
                    "file_path": file_path,
                    "title": title,
                    "finding_type": CanonicalFindingType.IAC,
                    "rule_id": str(rule_id),
                    "resource": file_path or target_str,
                }
                if scan_tag:
                    fields["tag"] = scan_tag
                out.append(self._create_payload(fields, asset=target_str))
            except (KeyError, TypeError, ValueError) as e:
                logger.debug("Skipping Trivy misconfiguration: %s", e)
        return out

    def _parse_secrets(
        self,
        res: dict,
        target: str,
        scan_tag: str | None = None,
        source_image: str | None = None,
        source_path: str | None = None,
    ) -> list[CanonicalFindingPayload]:
        secrets = res.get("Secrets") or res.get("secrets") or []
        if not isinstance(secrets, list):
            return []
        target_str = (target or "").strip()
        if not target_str:
            return []
        out: list[CanonicalFindingPayload] = []
        for s in secrets:
            if not isinstance(s, dict):
                continue
            # Trivy fanal: Secret has FilePath + Findings[]. Support both nested and flat structures.
            findings = s.get("Findings") or s.get("findings") or []
            secret_file_path = (
                s.get("FilePath")
                or s.get("filePath")
                or s.get("Target")
                or s.get("target")
                or s.get("File")
                or s.get("file")
            )
            secret_file_path = str(secret_file_path).strip() if secret_file_path else ""
            if findings:
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    try:
                        payload = self._secret_to_payload(
                            f,
                            target_str,
                            scan_tag,
                            source_image,
                            source_path,
                            secret_file_path,
                        )
                        if payload:
                            out.append(payload)
                    except (KeyError, TypeError, ValueError) as e:
                        logger.debug("Skipping Trivy secret finding: %s", e)
            else:
                # Flat: treat s as single finding
                try:
                    payload = self._secret_to_payload(
                        s,
                        target_str,
                        scan_tag,
                        source_image,
                        source_path,
                        secret_file_path,
                    )
                    if payload:
                        out.append(payload)
                except (KeyError, TypeError, ValueError) as e:
                    logger.debug("Skipping Trivy secret: %s", e)
        return out

    def _secret_to_payload(
        self,
        s: dict,
        target: str,
        scan_tag: str | None,
        source_image: str | None,
        source_path: str | None,
        secret_file_path: str,
    ) -> CanonicalFindingPayload | None:
        """Build canonical payload for one secret finding with proper location."""
        rule_id = s.get("RuleID") or s.get("ruleID") or s.get("RuleId") or "unknown"
        cat = s.get("Category") or s.get("category") or ""
        match = s.get("Match") or s.get("match") or ""
        desc = f"{cat or rule_id} (secret redacted)" if match else (cat or rule_id)
        sev = _map_severity(s.get("Severity") or s.get("severity"))
        raw_code = (
            s.get("Code") or s.get("code") or s.get("Content") or s.get("content")
        )
        if isinstance(raw_code, dict):
            lines = raw_code.get("Lines") or raw_code.get("lines") or []
            line_content = (
                lines[0].get("Content", lines[0].get("content", ""))
                if lines and isinstance(lines[0], dict)
                else ""
            )
        else:
            line_content = str(raw_code) if raw_code else ""
        snippet_masked = (
            _mask_secret_in_line(line_content, match) if line_content else None
        )
        line = s.get("StartLine") or s.get("startLine")
        if line is not None:
            try:
                line = int(line)
            except (TypeError, ValueError):
                line = None

        # Location: source_image (container) + path within image, or source_path (fs), or per-secret path
        path_part = secret_file_path or (
            s.get("Target") or s.get("File") or s.get("file") or s.get("FilePath") or ""
        )
        path_part = str(path_part).strip() if path_part else ""
        if source_image and path_part:
            file_path = f"{source_image}:{path_part}"
        elif source_image:
            file_path = source_image
        elif path_part:
            file_path = path_part
        elif source_path:
            file_path = source_path
        else:
            file_path = (target or "").strip() or None

        fields = {
            "cve_id": str(rule_id),
            "severity": sev,
            "description": str(desc)[:10000],
            "file_path": file_path,
            "title": rule_id,
            "finding_type": CanonicalFindingType.SECRET,
            "rule_id": str(rule_id),
            "secret_type": str(cat).strip() if cat else None,
            "snippet_masked": snippet_masked,
        }
        if line is not None:
            fields["line"] = line
        if scan_tag:
            fields["tag"] = scan_tag
        return self._create_payload(fields, asset=target)

    def _parse_licenses(
        self,
        res: dict,
        target: str,
        ecosystem: str | None = None,
        scan_tag: str | None = None,
        source_image: str | None = None,
        source_path: str | None = None,
    ) -> list[CanonicalFindingPayload]:
        licenses = res.get("Licenses") or res.get("licenses") or []
        if not isinstance(licenses, list):
            return []
        out: list[CanonicalFindingPayload] = []
        for lic in licenses:
            if not isinstance(lic, dict):
                continue
            try:
                pkg = lic.get("PkgName") or lic.get("pkgName") or ""
                cat = lic.get("Category") or lic.get("category") or ""
                name = lic.get("Name") or lic.get("name") or lic.get("ID") or "unknown"
                rule_id = f"license:{name}" if name else "license:unknown"
                desc = f"{name} ({cat})" if cat else str(name)
                sev = _map_severity(lic.get("Severity") or lic.get("severity"))
                component = (
                    f"{pkg} {lic.get('Version', '')}".strip()
                    if pkg
                    else (target or None)
                )
                lic_path = lic.get("FilePath") or lic.get("filePath") or ""
                lic_path = str(lic_path).strip() if lic_path else ""
                file_path = (
                    source_image or source_path or lic_path or target or ""
                ).strip() or None
                if not component and not file_path:
                    continue
                fields = {
                    "cve_id": rule_id,
                    "severity": sev,
                    "description": desc[:10000],
                    "component": component,
                    "file_path": file_path,
                    "title": name,
                    "finding_type": CanonicalFindingType.LICENSE,
                    "ecosystem": ecosystem,
                }
                if scan_tag:
                    fields["tag"] = scan_tag
                out.append(self._create_payload(fields, asset=target))
            except (KeyError, TypeError, ValueError) as e:
                logger.debug("Skipping Trivy license: %s", e)
        return out
