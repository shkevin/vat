"""Tests for grype parser."""

import json
from pathlib import Path

import pytest

from app.parsers.grype import GrypeParser

_SAMPLES = (
    Path(__file__).resolve().parent.parent.parent
    / "django-DefectDojo"
    / "unittests"
    / "scans"
    / "anchore_grype"
)


def _load(name: str) -> dict:
    sample = _SAMPLES / name
    if not sample.exists():
        pytest.skip(f"Missing external parser fixture: {sample}")
    with sample.open(encoding="utf-8") as f:
        return json.load(f)


def test_grype_empty():
    parser = GrypeParser()
    data = _load("no_vuln.json")
    payloads = parser.parse(data)
    assert len(payloads) == 0


def test_grype_many():
    parser = GrypeParser()
    data = _load("many_vulns.json")
    payloads = parser.parse(data)
    assert len(payloads) >= 1
    p = payloads[0]
    assert p.cve_id
    assert p.component
    assert "libgnutls" in p.component or "deb" in str(p.component).lower()


def test_grype_parser_extracts_structured_risk_scoring():
    parser = GrypeParser()
    payloads = parser.parse(
        {
            "source": {"target": {"userInput": "registry.example/api:1.0.0"}},
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-9999",
                        "severity": "High",
                        "description": "Example vulnerability",
                        "cvss": [
                            {
                                "version": "3.1",
                                "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                "metrics": {"baseScore": 7.4},
                            }
                        ],
                        "fix": {"versions": ["2.0.0"]},
                    },
                    "artifact": {
                        "name": "example",
                        "version": "1.0.0",
                        "type": "python-package",
                    },
                }
            ],
        }
    )

    assert payloads[0].risk_scoring == {
        "source": {
            "source": "grype",
            "cvssVersion": "3.1",
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "score": "7.4",
            "severity": "High",
            "scannerTitle": "CVE-2024-9999 in example:1.0.0",
            "fixedVersion": "2.0.0",
        },
        "context": {"fixAvailable": True},
    }
