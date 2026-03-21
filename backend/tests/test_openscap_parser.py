"""Tests for OpenSCAP XCCDF parser."""

from pathlib import Path

import pytest

from app.parsers.openscap import OpenSCAPParser

_SAMPLES = Path(__file__).resolve().parent / "fixtures" / "openscap"


def _load(name: str) -> bytes:
    with (_SAMPLES / name).open("rb") as f:
        return f.read()


def test_openscap_empty():
    """No vulns: all rule-results pass."""
    parser = OpenSCAPParser()
    data = _load("no_vuln.xml")
    payloads = parser.parse(data)
    assert len(payloads) == 0


def test_openscap_one_vuln():
    """One rule-result with result=fail."""
    parser = OpenSCAPParser()
    data = _load("one_vuln.xml")
    payloads = parser.parse(data)
    assert len(payloads) == 1
    p = payloads[0]
    assert p.cve_id == "CVE-2024-0002"
    assert p.severity
    assert p.description
    assert "cron daemon" in p.description or "CVE-2024-0002" in p.description
    assert p.tag == "scanned-host.local" or p.image == "scanned-host.local" or p.branch


def test_openscap_many_vulns():
    """Multiple rule-results with result=fail."""
    parser = OpenSCAPParser()
    data = _load("many_vulns.xml")
    payloads = parser.parse(data)
    assert len(payloads) == 3
    cves = {p.cve_id for p in payloads}
    assert cves == {"CVE-2024-0100", "CVE-2024-0101", "CVE-2024-0102"}


def test_openscap_rejects_json():
    """Parser expects XML, not JSON dict."""
    parser = OpenSCAPParser()
    with pytest.raises(ValueError, match="expects XML"):
        parser.parse({"Benchmark": {}})


def test_openscap_xccdf_1_2():
    """Chainguard GPOS STIG uses XCCDF 1.2; parser must support both 1.1 and 1.2."""
    parser = OpenSCAPParser()
    data = _load("xccdf_1_2_one_vuln.xml")
    payloads = parser.parse(data)
    assert len(payloads) == 1
    p = payloads[0]
    assert p.cve_id == "CVE-2024-9999"
    assert p.severity
    assert p.image == "chainguard-container:latest"
    # Component fallback: rule id when no CPE
    assert p.component == "xccdf_test_rule_SV-12345_rule"


def test_openscap_component_from_cpe():
    """Component extracted from CPE ident in Rule when present."""
    parser = OpenSCAPParser()
    data = _load("xccdf_with_cpe.xml")
    payloads = parser.parse(data)
    assert len(payloads) == 1
    p = payloads[0]
    assert p.cve_id == "CVE-2023-34383"
    assert p.component == "openssl 3.0.8"


def test_openscap_file_path_and_snippet():
    """file_path from Rule fix/description, snippet from rule-result message."""
    parser = OpenSCAPParser()
    data = _load("xccdf_with_fix_and_message.xml")
    payloads = parser.parse(data)
    assert len(payloads) == 1
    p = payloads[0]
    assert p.file_path == "/etc/ssh/sshd_config"
    assert p.component == "sshd_config"
    assert "non-compliant" in (p.snippet_masked or "")


def test_openscap_long_rule_title_uses_rule_id_for_title():
    """Very long STIG prose title should be normalized to concise rule id for UI."""
    parser = OpenSCAPParser()
    xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="b1">
  <Rule id="xccdf_rule_very_long">
    <title>The operating system must implement NIST FIPS-validated cryptography for this and that and many additional words so this exceeds the UI-friendly length threshold for list rows.</title>
  </Rule>
  <TestResult id="tr1">
    <target>containers/images/example</target>
    <rule-result idref="xccdf_rule_very_long" severity="high">
      <result>fail</result>
    </rule-result>
  </TestResult>
</Benchmark>
"""
    payloads = parser.parse(xml)
    assert len(payloads) == 1
    p = payloads[0]
    assert p.title == "xccdf_rule_very_long"
    assert "NIST FIPS-validated cryptography" in (p.description or "")
