"""Tests for pip_audit parser."""

import json
from pathlib import Path

from app.parsers.pip_audit import PipAuditParser

_SAMPLES = (
    Path(__file__).resolve().parent.parent.parent
    / "django-DefectDojo"
    / "unittests"
    / "scans"
    / "pip_audit"
)


def _load(name: str):
    with (_SAMPLES / name).open(encoding="utf-8") as f:
        return json.load(f)


def test_pip_audit_empty():
    parser = PipAuditParser()
    data = _load("empty.json")
    payloads = parser.parse(data)
    assert len(payloads) == 0


def test_pip_audit_many_legacy():
    parser = PipAuditParser()
    data = _load("many_vulns.json")
    payloads = parser.parse(data)
    assert len(payloads) >= 1
    p = payloads[0]
    assert p.cve_id
    assert p.component
    assert (
        "aiohttp" in p.component
        or "django" in p.component
        or "lxml" in p.component
        or "twisted" in p.component
    )


def test_pip_audit_many_new():
    parser = PipAuditParser()
    data = _load("many_vulns_new.json")
    payloads = parser.parse(data)
    assert len(payloads) >= 1
    p = payloads[0]
    assert p.component
