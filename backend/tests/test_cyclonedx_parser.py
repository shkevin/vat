"""Tests for cyclonedx parser."""

import json
from pathlib import Path

from app.parsers.cyclonedx import CyclonedxParser

_SAMPLES = Path(__file__).resolve().parent.parent.parent / "django-DefectDojo" / "unittests" / "scans" / "cyclonedx"


def _load_json(name: str) -> dict:
    with (_SAMPLES / name).open(encoding="utf-8") as f:
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
