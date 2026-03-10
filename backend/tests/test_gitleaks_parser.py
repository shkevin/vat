"""Tests for Gitleaks parser."""

import pytest

from app.parsers.gitleaks import GitleaksParser
from app.schemas.ingest import CanonicalFindingType, CanonicalSeverity


def test_gitleaks_parser_empty():
    parser = GitleaksParser()
    assert parser.parse({"findings": []}) == []
    assert parser.parse([]) == []


def test_gitleaks_parser_findings():
    gitleaks = {
        "findings": [
            {
                "RuleID": "aws-access-key",
                "Description": "AWS Access Key",
                "File": ".env",
                "StartLine": 5,
                "Secret": "AKIA...",
            },
            {
                "RuleID": "generic-api-key",
                "File": "config.json",
                "StartLine": 12,
            },
        ]
    }
    parser = GitleaksParser()
    payloads = parser.parse(gitleaks)
    assert len(payloads) == 2
    assert payloads[0].cve_id == "aws-access-key"
    assert payloads[0].severity == CanonicalSeverity.HIGH
    assert payloads[0].file_path == ".env"
    assert payloads[0].line == 5
    assert payloads[0].finding_type == CanonicalFindingType.SECRET
    assert payloads[1].cve_id == "generic-api-key"
    assert payloads[1].line == 12


def test_gitleaks_parser_array():
    parser = GitleaksParser()
    payloads = parser.parse([
        {"RuleID": "test", "Description": "Test", "File": "x"},
    ])
    assert len(payloads) == 1
    assert payloads[0].cve_id == "test"


def test_gitleaks_parser_invalid():
    parser = GitleaksParser()
    with pytest.raises(ValueError, match="must be a JSON object or array"):
        parser.parse("not json")
