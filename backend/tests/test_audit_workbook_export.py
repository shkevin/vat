"""Auditor workbook and XCCDF rule extraction."""

from datetime import datetime, timezone

from app.services.audit_workbook_export import (
    build_auditor_workbook_bytes,
    extract_xccdf_rule_results,
)


def test_extract_xccdf_rule_results_parses_namespaced_rule_result():
    xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <TestResult id="xccdf_org.open-scap_testresult_default-profile">
    <rule-result idref="xccdf_org.ssgproject.content_rule_audit_rules_execution" severity="medium" weight="1.0">
      <result>fail</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_other" severity="high" weight="1.0">
      <result>pass</result>
    </rule-result>
  </TestResult>
</Benchmark>
"""
    rows = extract_xccdf_rule_results(xml)
    assert len(rows) == 2
    assert rows[0]["ruleId"].endswith("audit_rules_execution")
    assert rows[0]["result"] == "fail"
    assert rows[0]["severity"] == "medium"
    assert rows[1]["result"] == "pass"


def test_build_auditor_workbook_minimal():
    ts = datetime(2025, 6, 1, tzinfo=timezone.utc)
    data = build_auditor_workbook_bytes(
        findings=[
            {
                "id": "f1",
                "cveId": "CVE-1",
                "status": "Open",
                "severity": "High",
                "source": "openscap",
                "ruleId": "r1",
                "audit": [{"ts": "2025-01-01", "user": "u", "action": "import", "note": None}],
            }
        ],
        stig_file_manifest=[
            {
                "assetId": "host1",
                "sourceId": "src1",
                "filename": "host1_src1.xccdf.xml",
                "parserId": "openscap",
                "createdAt": "2025-01-01",
                "benchmarkId": "b1",
                "benchmarkFamily": "RHEL",
                "profileScope": "stig",
                "contentVersion": "v1",
                "evidenceSha256": "abc",
            }
        ],
        stig_rule_rows=[
            {
                "assetId": "host1",
                "sourceId": "src1",
                "parserId": "openscap",
                "benchmarkId": "b1",
                "ruleId": "xccdf_rule_x",
                "result": "fail",
                "severity": "high",
            }
        ],
        audit_events=None,
        generated_at=ts,
        tenant_id=None,
        backend_version="0.1.0",
        export_options={"include_audit_events": False},
    )
    assert data[:2] == b"PK"
    assert len(data) > 2000
