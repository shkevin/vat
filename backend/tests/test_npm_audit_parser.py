"""Tests for npm_audit parser."""

import json
from pathlib import Path

import pytest

from app.parsers.npm_audit import NpmAuditParser

_SAMPLES = Path(__file__).resolve().parent.parent.parent / "django-DefectDojo" / "unittests" / "scans" / "npm_audit"
_NPM7 = Path(__file__).resolve().parent.parent.parent / "django-DefectDojo" / "unittests" / "scans" / "npm_audit_7_plus"


def _load(name: str) -> dict:
    sample = _SAMPLES / name
    if not sample.exists():
        pytest.skip(f"Missing external parser fixture: {sample}")
    with sample.open(encoding="utf-8") as f:
        return json.load(f)


def test_npm_audit_empty():
    parser = NpmAuditParser()
    data = _load("no_vuln.json")
    payloads = parser.parse(data)
    assert len(payloads) == 0


def test_npm_audit_v6_many():
    parser = NpmAuditParser()
    data = _load("many_vuln.json")
    payloads = parser.parse(data)
    assert len(payloads) >= 1
    p = payloads[0]
    assert p.cve_id
    assert p.component
    assert p.severity
    assert "negotiator" in p.component or "debug" in p.component or "pg" in p.component


def test_npm_audit_v7_one():
    import json
    parser = NpmAuditParser()
    sample = _NPM7 / "one_vuln.json"
    if not sample.exists():
        pytest.skip(f"Missing external parser fixture: {sample}")
    with sample.open(encoding="utf-8") as f:
        data = json.load(f)
    payloads = parser.parse(data)
    assert len(payloads) >= 1
    p = payloads[0]
    assert p.component
    assert "debug" in p.component.lower() or p.cve_id

