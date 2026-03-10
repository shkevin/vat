"""OpenSCAP OVAL Results parser — CVE vulnerability scan output from oscap oval eval / oscap-docker image-cve."""

import logging
import re
from typing import Any

from defusedxml import ElementTree

from app.parsers.base import IngestParser
from app.schemas.ingest import CanonicalFindingPayload

logger = logging.getLogger(__name__)

# OVAL Results namespaces (version 5.x)
OVAL_RES_NS = "http://oval.mitre.org/XMLSchema/oval-results-5"
OVAL_DEF_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
OVAL_COMMON_NS = "http://oval.mitre.org/XMLSchema/oval-common-5"
CVE_SYSTEM = "http://cve.mitre.org"


def _ns(tag: str, ns: str = OVAL_RES_NS) -> str:
    return f"{{{ns}}}{tag}"


def _any_ns(parent: Any, local: str, nss: list[str]) -> Any | None:
    """Find first element with local name in any of the given namespaces."""
    for ns in nss:
        el = parent.find(f".//{{{ns}}}{local}")
        if el is not None:
            return el
    return parent.find(f".//*[local-name()='{local}']")


def _all_ns(parent: Any, local: str, nss: list[str]) -> list:
    """Find all elements with local name in any of the given namespaces."""
    results = []
    for ns in nss:
        for el in parent.findall(f".//{{{ns}}}{local}"):
            results.append(el)
    # Fallback: local-name()
    for el in parent.iter():
        if el.tag and el.tag.split("}")[-1] == local and el not in results:
            results.append(el)
    return results


def _text(el: Any | None) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def _collect_cves_from_refs(parent: Any) -> list[str]:
    """Extract CVE IDs from reference elements (source=CVE or ref_id matching CVE-)."""
    cves: list[str] = []
    nss = [OVAL_DEF_NS, OVAL_COMMON_NS, "http://oval.mitre.org/XMLSchema/oval-definitions-5"]
    for ref in _all_ns(parent, "reference", nss):
        ref_id = (ref.get("ref_id") or ref.get("ref_id") or "").strip()
        source = (ref.get("source") or "").strip().upper()
        if ref_id and ref_id.upper().startswith("CVE-") and ref_id not in cves:
            cves.append(ref_id)
        if source == "CVE" and ref_id and ref_id not in cves:
            cves.append(ref_id)
    return cves


def _collect_cves_from_metadata(definition_el: Any) -> list[str]:
    """Extract CVE IDs from definition metadata (references)."""
    cves: list[str] = []
    metadata = definition_el.find(f".//{_ns('metadata', OVAL_DEF_NS)}")
    if metadata is None:
        metadata = definition_el.find(".//*[local-name()='metadata']")
    if metadata is not None:
        cves = _collect_cves_from_refs(metadata)
    return cves


def _map_severity(sev: str | None) -> str:
    if not sev:
        return "medium"
    s = str(sev).lower()
    if s in ("critical", "high", "medium", "low"):
        return s
    if s in ("unknown", "info", "informational"):
        return "informational"
    return "medium"


def _extract_component_from_title(title: str, definition_id: str) -> str:
    """Extract package/component from OVAL definition title when possible.
    E.g. 'RHSA-2024:0001: curl security update (Important)' -> 'curl'
    """
    if not title or len(title) > 400:
        return definition_id
    # Pattern: "X: package security update" or "X: package (Critical)"
    m = re.search(r":\s*([^:(]+?)\s+(?:security\s+update|\()", title, re.I)
    if m:
        comp = m.group(1).strip()
        if comp and len(comp) < 200:
            return comp
    return definition_id


def _get_definition_metadata(
    root: Any, definition_id: str
) -> tuple[str, list[str], str]:
    """Look up definition in oval_definitions; return (title, cves, severity)."""
    title = definition_id
    cves: list[str] = []
    severity = "medium"

    oval_defs = root.find(f".//{{{OVAL_DEF_NS}}}oval_definitions")
    if oval_defs is None:
        for el in root.iter():
            if (el.tag or "").split("}")[-1] == "oval_definitions":
                oval_defs = el
                break
    if oval_defs is None:
        return title, cves, severity

    for def_el in oval_defs.iter():
        if def_el.get("id") != definition_id:
            continue
        title_el = def_el.find(f".//{{{OVAL_DEF_NS}}}title")
        if title_el is None:
            title_el = def_el.find(".//*[local-name()='title']")
        if title_el is not None:
            title = _text(title_el) or title
        cves = _collect_cves_from_metadata(def_el)
        break

    return title, cves, severity


def _get_system_target(root: Any) -> str:
    """Extract target/hostname from oval_system_characteristics."""
    for el in root.iter():
        tag = (el.tag or "").split("}")[-1]
        if tag == "oval_system_characteristics":
            for child in el.iter():
                ctag = (child.tag or "").split("}")[-1]
                if ctag == "hostname":
                    t = _text(child)
                    if t:
                        return t
                if ctag == "os_name":
                    t = _text(child)
                    if t:
                        return t
            break
    return "oval-cve-scan"


class OpenSCAPOvalParser(IngestParser):
    """Parse OpenSCAP OVAL Results XML (from oscap oval eval / oscap-docker image-cve) to canonical format."""

    format_name = "openscap_oval"

    def parse(self, raw: dict | list | bytes) -> list[CanonicalFindingPayload]:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if isinstance(raw, str):
            root = ElementTree.fromstring(raw)
        elif isinstance(raw, dict):
            raise ValueError("OpenSCAP OVAL parser expects XML bytes or string, not JSON dict")
        else:
            raise ValueError("OpenSCAP OVAL parser expects XML bytes or string")

        # Accept oval_results root (with or without namespace)
        tag_lower = (root.tag or "").lower()
        if "oval_results" not in tag_lower and "benchmark" in tag_lower:
            raise ValueError(
                "OpenSCAP OVAL parser expects OVAL Results XML (oval_results root). "
                "For XCCDF Benchmark, use parser=openscap."
            )
        if "oval_results" not in tag_lower:
            raise ValueError("OpenSCAP OVAL parser expects OVAL Results XML (oval_results root)")

        asset = _get_system_target(root)
        payloads: list[CanonicalFindingPayload] = []

        # results/system/definitions/definition
        results = root.find(f".//{{{OVAL_RES_NS}}}results")
        if results is None:
            for el in root.iter():
                if (el.tag or "").split("}")[-1] == "results":
                    results = el
                    break
        if results is None:
            return []

        systems = results.findall(f".//{{{OVAL_RES_NS}}}system") if results is not None else []
        if not systems and results is not None:
            systems = [el for el in results.iter() if (el.tag or "").split("}")[-1] == "system"]

        for system in systems:
            defs_container = system.find(f".//{{{OVAL_RES_NS}}}definitions")
            if defs_container is None:
                defs_container = next(
                    (el for el in system.iter() if (el.tag or "").split("}")[-1] == "definitions"),
                    None,
                )
            if defs_container is None:
                continue

            for def_el in defs_container.findall(f".//{{{OVAL_RES_NS}}}definition"):
                result_attr = (def_el.get("result") or "").strip().lower()
                # For vulnerability class: true = affected (vulnerability found)
                # For patch class: true = patch needed
                if result_attr != "true":
                    continue

                definition_id = (def_el.get("definition_id") or def_el.get("id") or "").strip()
                if not definition_id:
                    continue

                title, cves, severity = _get_definition_metadata(root, definition_id)
                cve_id = cves[0] if cves else definition_id
                if not cve_id.upper().startswith("CVE-") and "CVE-" in definition_id:
                    # Try to extract CVE from definition_id (e.g. oval:com.redhat.rhsa:def:20060101)
                    m = re.search(r"CVE-\d{4}-\d+", definition_id, re.I)
                    if m:
                        cve_id = m.group(0)

                desc_parts = [f"**{title}**", f"OVAL Definition: `{definition_id}`"]
                if cves:
                    desc_parts.append(f"CVE(s): {', '.join(cves)}")
                description = "\n\n".join(desc_parts)

                refs = [f"oval:{definition_id}"]
                if cves:
                    refs = [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:5]] + refs

                component = _extract_component_from_title(title, definition_id)

                payloads.append(
                    self._create_payload(
                        {
                            "cve_id": cve_id,
                            "severity": _map_severity(severity),
                            "description": description,
                            "rule_id": definition_id,
                            "title": title,
                            "references": refs[:20],
                            "component": component,
                        },
                        asset=asset,
                    )
                )

        return payloads
