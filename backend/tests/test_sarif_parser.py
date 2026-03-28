"""Tests for SARIF parser."""

import json
from pathlib import Path

import pytest

from app.parsers.sarif import SarifParser
from app.schemas.ingest import CanonicalSeverity
from app.schemas.vat import VatFindingType


def test_sarif_parser_empty_results():
    sarif = {
        "$schema": "https://sarif",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": []}],
    }
    parser = SarifParser()
    payloads = parser.parse(sarif)
    assert payloads == []


def test_sarif_parser_single_result():
    sarif = {
        "$schema": "https://sarif",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Trivy"}},
                "results": [
                    {
                        "ruleId": "CVE-2024-1234",
                        "message": {"text": "Remote code execution"},
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "package.json"},
                                    "region": {"startLine": 10},
                                }
                            }
                        ],
                        "properties": {
                            "packageName": "lib-x",
                            "installedVersion": "1.2.3",
                            "security-severity": "8.5",
                        },
                    }
                ],
            }
        ],
    }
    parser = SarifParser()
    payloads = parser.parse(sarif)
    assert len(payloads) == 1
    assert payloads[0].cve_id == "CVE-2024-1234"
    assert payloads[0].severity == CanonicalSeverity.HIGH
    assert payloads[0].description == "Remote code execution"
    assert payloads[0].component == "lib-x 1.2.3"
    assert payloads[0].file_path == "package.json"
    assert payloads[0].line == 10
    assert payloads[0].cvss == "8.5"
    assert payloads[0].finding_type == VatFindingType.SAST
    assert payloads[0].rule_id == "CVE-2024-1234"


def test_sarif_parser_partial_fingerprints_preserved():
    sarif = {
        "$schema": "https://sarif",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Test"}},
                "results": [
                    {
                        "ruleId": "R1",
                        "message": {"text": "m"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "f.py"},
                                    "region": {"startLine": 5},
                                }
                            }
                        ],
                        "partialFingerprints": {
                            "primaryLocationLineHash/v1": "deadbeef",
                        },
                    }
                ],
            }
        ],
    }
    payloads = SarifParser().parse(sarif)
    assert len(payloads) == 1
    assert payloads[0].partial_fingerprints == {
        "primaryLocationLineHash/v1": "deadbeef",
    }


def test_sarif_parser_invalid_schema():
    parser = SarifParser()
    with pytest.raises(ValueError, match="Invalid SARIF"):
        parser.parse({"version": "2.1.0", "runs": []})


def test_sarif_parser_unsupported_version():
    parser = SarifParser()
    with pytest.raises(ValueError, match="Unsupported SARIF version"):
        parser.parse({"$schema": "https://sarif", "version": "1.0.0", "runs": []})


def test_sarif_parser_fixture():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "sarif" / "trivy-sample.sarif.json"
    )
    if not fixture_path.exists():
        pytest.skip("Fixture not found")
    with open(fixture_path) as f:
        sarif = json.load(f)
    parser = SarifParser()
    payloads = parser.parse(sarif)
    assert len(payloads) >= 1
    assert any(p.cve_id == "CVE-2024-1234" for p in payloads)
