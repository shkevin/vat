"""Tests for vulnerability feed normalization helpers."""

from app.services.vuln_feeds import (
    SOURCE_CISA_KEV,
    SOURCE_OSV,
    _normalize_cisa_kev,
    _normalize_osv_results,
)


def test_normalize_cisa_kev_records():
    payload = {
        "dateReleased": "2026-03-31",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1000",
                "vendorProject": "ExampleVendor",
                "vulnerabilityName": "Example vuln",
                "dateAdded": "2026-03-31",
                "knownRansomwareCampaignUse": "Known",
            }
        ],
    }
    rows = _normalize_cisa_kev(payload)
    assert len(rows) == 1
    assert rows[0]["source"] == SOURCE_CISA_KEV
    assert rows[0]["vulnerability_id"] == "CVE-2026-1000"
    assert rows[0]["record_key"] == "CVE-2026-1000"


def test_normalize_osv_querybatch_results():
    payload = [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "version": "2.31.0",
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "aliases": ["CVE-2025-1234"],
                    "summary": "Example summary",
                    "modified": "2026-03-31T00:00:00Z",
                    "published": "2026-03-30T00:00:00Z",
                    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                }
            ],
        }
    ]
    rows = _normalize_osv_results(payload)
    assert len(rows) == 1
    assert rows[0]["source"] == SOURCE_OSV
    assert rows[0]["vulnerability_id"] == "GHSA-xxxx-yyyy-zzzz"
    assert rows[0]["aliases"] == ["CVE-2025-1234"]
    assert "GHSA-xxxx-yyyy-zzzz|requests|PyPI|2.31.0" == rows[0]["record_key"]
