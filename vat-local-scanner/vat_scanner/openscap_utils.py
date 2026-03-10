"""OpenSCAP XML utilities — count findings, validate format, save for debug."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path


XCCDF_NS = "http://checklists.nist.gov/xccdf/1.1"
OVAL_RES_NS = "http://oval.mitre.org/XMLSchema/oval-results-5"


def _ns(tag: str, ns: str = XCCDF_NS) -> str:
    return f"{{{ns}}}{tag}"


def count_openscap_findings(xml_content: str) -> int:
    """
    Count rule-result elements with result=fail in XCCDF Benchmark XML.
    Matches backend OpenSCAP parser logic.
    """
    if not xml_content or not xml_content.strip():
        return 0
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return 0
    count = 0
    for rr in root.iter():
        tag = (rr.tag or "").split("}")[-1]
        if tag != "rule-result":
            continue
        result_el = None
        for child in rr:
            if (child.tag or "").split("}")[-1] == "result":
                result_el = child
                break
        if result_el is not None and "fail" in (result_el.text or "").strip().lower():
            count += 1
    return count


def count_openscap_oval_findings(xml_content: str) -> int:
    """
    Count definition elements with result=true in OVAL Results XML.
    Matches backend OpenSCAP OVAL parser (true = vulnerability found).
    """
    if not xml_content or not xml_content.strip():
        return 0
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return 0
    count = 0
    for el in root.iter():
        tag = (el.tag or "").split("}")[-1]
        if tag != "definition":
            continue
        result_attr = (el.get("result") or el.get("definition_result") or "").strip().lower()
        if result_attr == "true":
            count += 1
    return count


def save_openscap_xml(
    xml_content: str,
    out_dir: Path,
    parser: str,
    index: int,
    label: str,
) -> Path:
    """Save OpenSCAP XML to disk for debugging. Returns path to saved file."""
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_label = "".join(c if c.isalnum() or c in "._-" else "_" for c in label)
    filename = f"{parser}_{index:03d}_{safe_label}.xml"
    path = out_dir / filename
    path.write_text(xml_content, encoding="utf-8", errors="replace")
    return path
