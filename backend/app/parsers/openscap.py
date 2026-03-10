"""OpenSCAP XCCDF parser — NIST checklist format from oscap scans. Supports XCCDF 1.1 and 1.2."""

import logging
import os
import re
from typing import Any

from defusedxml import ElementTree

from app.parsers.base import IngestParser
from app.schemas.ingest import CanonicalFindingPayload

logger = logging.getLogger(__name__)

XCCDF_NS_1_1 = "http://checklists.nist.gov/xccdf/1.1"
XCCDF_NS_1_2 = "http://checklists.nist.gov/xccdf/1.2"
CVE_SYSTEM = "http://cve.mitre.org"


def _detect_xccdf_ns(root: Any) -> str:
    """Detect XCCDF namespace from root. Chainguard GPOS STIG uses 1.2; older scans use 1.1."""
    tag = root.tag or ""
    if tag.startswith("{"):
        ns = tag[1 : tag.index("}")]
        if "xccdf" in ns:
            return ns
    return XCCDF_NS_1_1


def _ns(tag: str, ns: str | None = None) -> str:
    """Return tag with XCCDF namespace."""
    return f"{{{ns or XCCDF_NS_1_1}}}{tag}"


def _text(el: Any | None) -> str:
    """Extract text from element (handles xhtml-titled content)."""
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def _collect_cves(parent: Any, xccdf_ns: str) -> list[str]:
    """Collect CVE IDs from ident elements with CVE system."""
    cves: list[str] = []
    for ident in parent.findall(f".//{_ns('ident', xccdf_ns)}"):
        if ident.get("system") == CVE_SYSTEM and ident.text:
            cid = ident.text.strip()
            if cid and cid.upper().startswith("CVE-") and cid not in cves:
                cves.append(cid)
    return cves


def _collect_refs(parent: Any, xccdf_ns: str) -> list[str]:
    """Collect reference URLs from check-content-ref elements."""
    refs: list[str] = []
    for ref in parent.findall(f".//{_ns('check-content-ref', xccdf_ns)}"):
        name = ref.get("name", "").strip()
        href = ref.get("href", "").strip()
        if name:
            refs.append(name)
        if href and href not in refs:
            refs.append(href)
    return refs


def _cpe_to_component(cpe_text: str) -> str | None:
    """Extract product and version from CPE ident for component display.
    Supports cpe:/a:vendor:product:version and cpe:2.3:a:vendor:product:version:...
    """
    if not cpe_text or not isinstance(cpe_text, str):
        return None
    t = cpe_text.strip().lower()
    if not t.startswith("cpe:"):
        return None
    # cpe:2.3:a:vendor:product:version:...
    m = re.match(r"cpe:2\.3:a:[^:]*:([^:]+):([^:*]*)(?::|$)", t)
    if m:
        product, version = m.group(1), m.group(2)
        if product and product != "*":
            return f"{product} {version}".strip() if version else product
    # cpe:/a:vendor:product:version
    m = re.match(r"cpe:/a:[^:]*:([^:]+):([^:*]*)(?::|$)", t)
    if m:
        product, version = m.group(1), m.group(2)
        if product and product != "*":
            return f"{product} {version}".strip() if version else product
    return None


def _collect_component(parent: Any, xccdf_ns: str) -> str | None:
    """Extract component from CPE ident elements in rule or rule-result."""
    for ident in parent.findall(f".//{_ns('ident', xccdf_ns)}"):
        sys_attr = (ident.get("system") or "").strip()
        if "cpe" in sys_attr.lower() and ident.text:
            comp = _cpe_to_component(ident.text)
            if comp:
                return comp
    return None


# Regex for common config/file paths in fix scripts and descriptions
_FILE_PATH_RE = re.compile(
    r"(?:^|[\s'\"`])(/(?:etc|var|usr|opt|home|root)/[a-zA-Z0-9/_.-]+)(?:[\s'\"`]|$)"
)


def _extract_file_path_from_text(text: str) -> str | None:
    """Extract first config/file path from fix script or description."""
    if not text or not isinstance(text, str):
        return None
    m = _FILE_PATH_RE.search(text)
    return m.group(1).strip() if m else None


def _extract_file_path_from_rule(rule_el: Any, xccdf_ns: str) -> str | None:
    """Extract file path from Rule fix element or description."""
    if rule_el is None:
        return None
    for tag in ("fix", "description"):
        el = rule_el.find(f".//{_ns(tag, xccdf_ns)}")
        if el is not None:
            txt = _text(el)
            if txt:
                fp = _extract_file_path_from_text(txt)
                if fp:
                    return fp
    return None


def _extract_message_from_rule_result(rr: Any, xccdf_ns: str) -> str | None:
    """Extract message text from rule-result (OVAL/check output)."""
    msg_el = rr.find(f".//{_ns('message', xccdf_ns)}")
    if msg_el is None:
        return None
    txt = _text(msg_el)
    return txt[:500] if txt else None


def _map_severity(sev: str | None) -> str:
    """Map XCCDF severity to VAT severity."""
    if not sev:
        return "medium"
    s = str(sev).lower()
    if s in ("critical", "high", "medium", "low"):
        return s
    if s in ("unknown", "info", "informational"):
        return "informational"
    return "medium"


class OpenSCAPParser(IngestParser):
    """Parse OpenSCAP XCCDF 1.1 XML to canonical format."""

    format_name = "openscap"

    def parse(self, raw: dict | list | bytes) -> list[CanonicalFindingPayload]:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if isinstance(raw, str):
            root = ElementTree.fromstring(raw)
        elif isinstance(raw, dict):
            raise ValueError("OpenSCAP parser expects XML bytes or string, not JSON dict")
        else:
            raise ValueError("OpenSCAP parser expects XML bytes or string")

        if root.tag != _ns("Benchmark", XCCDF_NS_1_1) and root.tag != _ns("Benchmark", XCCDF_NS_1_2) and "Benchmark" not in (root.tag or ""):
            raise ValueError("OpenSCAP input must be XCCDF 1.1 or 1.2 Benchmark XML")

        xccdf_ns = _detect_xccdf_ns(root)

        rules: dict[str, str] = {}
        rule_elements: dict[str, Any] = {}
        for rule in root.findall(f".//{_ns('Rule', xccdf_ns)}"):
            rid = rule.get("id")
            if rid:
                title_el = rule.find(f"{_ns('title', xccdf_ns)}")
                rules[rid] = _text(title_el) or rid
                rule_elements[rid] = rule

        test_result = root.find(f".//{_ns('TestResult', xccdf_ns)}")
        if test_result is None:
            return []

        targets: list[str] = []
        target_el = test_result.find(_ns("target", xccdf_ns))
        if target_el is not None and target_el.text:
            targets.append(target_el.text.strip())
        for addr in test_result.findall(_ns("target-address", xccdf_ns)):
            if addr.text:
                targets.append(addr.text.strip())
        asset = targets[0] if targets else "openscap-scan"

        payloads: list[CanonicalFindingPayload] = []
        for rr in test_result.findall(_ns("rule-result", xccdf_ns)):
            result_el = rr.find(_ns("result", xccdf_ns))
            result_text = (result_el.text or "").strip().lower() if result_el is not None else ""
            if "fail" not in result_text:
                continue

            idref = rr.get("idref", "")
            title = rules.get(idref, idref)
            cves = _collect_cves(rr, xccdf_ns)
            refs = _collect_refs(rr, xccdf_ns)
            sev = _map_severity(rr.get("severity"))

            cve_id = cves[0] if cves else idref
            desc_parts = [f"**{title}**", f"Rule: `{idref}`"]
            if cves:
                desc_parts.append(f"CVE(s): {', '.join(cves)}")
            if refs:
                desc_parts.append(f"References: {', '.join(refs[:5])}")
            description = "\n\n".join(desc_parts)

            # Component: CPE ident (package) from rule-result or Rule, else file basename, else rule id
            component = _collect_component(rr, xccdf_ns)
            if not component and idref:
                rule_el = rule_elements.get(idref)
                if rule_el is not None:
                    component = _collect_component(rule_el, xccdf_ns)
            file_path = None
            if idref:
                rule_el = rule_elements.get(idref)
                if rule_el is not None:
                    file_path = _extract_file_path_from_rule(rule_el, xccdf_ns)
            if not component and file_path:
                component = os.path.basename(file_path)  # e.g. sshd_config
            if not component and idref:
                component = idref  # Fallback: rule id identifies the check (STIG config findings)

            snippet_masked = _extract_message_from_rule_result(rr, xccdf_ns)

            fields = {
                "cve_id": cve_id,
                "severity": sev,
                "description": description,
                "rule_id": idref,
                "title": title,
                "references": refs[:20] if refs else None,
                "component": component,
            }
            if file_path:
                fields["file_path"] = file_path
            if snippet_masked:
                fields["snippet_masked"] = snippet_masked

            payloads.append(self._create_payload(fields, asset=asset))

        return payloads
