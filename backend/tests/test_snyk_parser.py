"""Tests for Snyk parser."""

import pytest

from app.parsers.snyk import SnykParser
from app.schemas.ingest import CanonicalFindingType, CanonicalSeverity


def test_snyk_parser_empty():
    parser = SnykParser()
    assert parser.parse({"targetFile": "package.json", "vulnerabilities": []}) == []
    # No asset context (targetFile/projectName) -> parse returns [] to avoid ingest with empty asset
    assert parser.parse({}) == []


def test_snyk_parser_vulnerabilities():
    snyk = {
        "targetFile": "package.json",
        "vulnerabilities": [
            {
                "id": "SNYK-JS-LODASH-123",
                "packageName": "lodash",
                "version": "4.17.20",
                "title": "Prototype Pollution",
                "description": "A vulnerability allows prototype pollution.",
                "severity": "high",
            },
            {
                "id": "CVE-2024-1234",
                "packageName": "pkg-x",
                "version": "1.0.0",
                "identifiers": {"CVE": ["CVE-2024-1234"]},
                "severity": "critical",
                "CVSSv3": "9.8",
            },
        ]
    }
    parser = SnykParser()
    payloads = parser.parse(snyk)
    assert len(payloads) == 2
    assert payloads[0].cve_id == "SNYK-JS-LODASH-123"
    assert payloads[0].severity == CanonicalSeverity.HIGH
    assert payloads[0].component == "lodash 4.17.20"
    assert payloads[0].finding_type == CanonicalFindingType.SCA
    assert payloads[1].cve_id == "CVE-2024-1234"
    assert payloads[1].severity == CanonicalSeverity.CRITICAL
    assert payloads[1].cvss == "9.8"


def test_snyk_parser_invalid():
    parser = SnykParser()
    with pytest.raises(ValueError, match="must be a JSON object"):
        parser.parse("not json")
