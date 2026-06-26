"""Tests for cyclonedx parser."""

import json
from pathlib import Path

import pytest

from app.parsers.cyclonedx import CyclonedxParser

_SAMPLES = (
    Path(__file__).resolve().parent.parent.parent
    / "django-DefectDojo"
    / "unittests"
    / "scans"
    / "cyclonedx"
)


def _load_json(name: str) -> dict:
    sample = _SAMPLES / name
    if not sample.exists():
        pytest.skip(f"Missing external parser fixture: {sample}")
    with sample.open(encoding="utf-8") as f:
        return json.load(f)


def test_cyclonedx_empty():
    parser = CyclonedxParser()
    data = {"components": [], "vulnerabilities": []}
    payloads = parser.parse(data)
    assert len(payloads) == 0


def test_cyclonedx_valid_vulnerability():
    parser = CyclonedxParser()
    data = _load_json("valid-vulnerability-1.4.json")
    payloads = parser.parse(data)
    assert len(payloads) >= 1
    p = payloads[0]
    assert p.cve_id
    assert p.component
    assert "jackson" in p.component.lower() or "CVE" in p.cve_id


def test_cyclonedx_parser_splits_cvss_score_and_vector():
    parser = CyclonedxParser()
    payloads = parser.parse(
        {
            "metadata": {"component": {"name": "registry.example/api:1.0.0"}},
            "components": [
                {
                    "bom-ref": "pkg:pypi/ecdsa@0.19.2",
                    "name": "ecdsa",
                    "version": "0.19.2",
                }
            ],
            "vulnerabilities": [
                {
                    "id": "CVE-2024-23342",
                    "description": "Minerva attack",
                    "recommendation": "No fixed version is available.",
                    "ratings": [
                        {
                            "method": "CVSSv31",
                            "score": 7.4,
                            "severity": "high",
                            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        }
                    ],
                    "affects": [{"ref": "pkg:pypi/ecdsa@0.19.2"}],
                }
            ],
        }
    )

    assert payloads[0].cvss == "7.4"
    assert payloads[0].risk_scoring == {
        "source": {
            "source": "cyclonedx",
            "cvssVersion": "3.1",
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "score": "7.4",
            "severity": "High",
            "scannerTitle": "ecdsa:0.19.2 | CVE-2024-23342",
        },
        "context": {"fixAvailable": False},
    }
