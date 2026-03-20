"""Tests for grype parser."""

import json
from pathlib import Path

import pytest

from app.parsers.grype import GrypeParser

_SAMPLES = Path(__file__).resolve().parent.parent.parent / "django-DefectDojo" / "unittests" / "scans" / "anchore_grype"


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

