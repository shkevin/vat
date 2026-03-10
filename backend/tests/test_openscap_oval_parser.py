"""Tests for OpenSCAP OVAL Results parser."""

from pathlib import Path

import pytest

from app.parsers.openscap_oval import OpenSCAPOvalParser

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "openscap_oval"


def test_openscap_oval_one_vuln():
    """Parse OVAL results with one vulnerable definition."""
    parser = OpenSCAPOvalParser()
    xml = (_FIXTURES / "sample_oval_results.xml").read_text()
    payloads = parser.parse(xml)
    assert len(payloads) == 1
    p = payloads[0]
    assert p.cve_id == "CVE-2024-1234"
    assert "curl" in (p.title or "")
    assert "oval:com.redhat.rhsa:def:20240001" in (p.rule_id or "")
    assert p.image == "scanned-container.example.com"
    assert p.component == "curl"


def test_openscap_oval_empty():
    """Parse OVAL results with no vulnerable definitions."""
    parser = OpenSCAPOvalParser()
    xml = """<?xml version="1.0"?>
    <oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5">
      <generator/><directives/>
      <results><system>
        <definitions>
          <definition definition_id="oval:test:def:1" result="false"/>
        </definitions>
      </system></results>
    </oval_results>"""
    payloads = parser.parse(xml)
    assert len(payloads) == 0


def test_openscap_oval_rejects_json():
    """Parser rejects JSON input."""
    parser = OpenSCAPOvalParser()
    with pytest.raises(ValueError, match="expects XML"):
        parser.parse({"foo": "bar"})


def test_openscap_oval_rejects_xccdf():
    """Parser rejects XCCDF Benchmark (should use openscap parser)."""
    parser = OpenSCAPOvalParser()
    xccdf = """<?xml version="1.0"?>
    <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
      <TestResult><rule-result result="fail"/></TestResult>
    </Benchmark>"""
    with pytest.raises(ValueError, match="OVAL Results"):
        parser.parse(xccdf)
