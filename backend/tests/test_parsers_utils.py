"""Tests for app.parsers.utils."""

import pytest

from app.parsers.utils import extract_cwe_id, extract_scan_tag


def test_extract_cwe_id_list():
    """Semgrep: list format."""
    assert extract_cwe_id(["CWE-89: SQL Injection", "CWE-943: ..."]) == "CWE-89"


def test_extract_cwe_id_string_with_description():
    """Plain string with description."""
    assert extract_cwe_id("CWE-89: SQL Injection") == "CWE-89"


def test_extract_cwe_id_bare_string():
    """Bare string with no description."""
    assert extract_cwe_id("CWE-89") == "CWE-89"


def test_extract_cwe_id_integer():
    """Trivy/SARIF: integer format."""
    assert extract_cwe_id(89) == "CWE-89"
    assert extract_cwe_id(617) == "CWE-617"


def test_extract_cwe_id_none_empty():
    """None and empty return None."""
    assert extract_cwe_id(None) is None
    assert extract_cwe_id([]) is None
    assert extract_cwe_id("") is None


def test_extract_scan_tag_dict():
    """Extract scan tag from dict (injected by vat-local-scanner)."""
    assert extract_scan_tag({"_vat_scan_tag": "2026-03-08_143052"}) == "2026-03-08_143052"
    assert extract_scan_tag({"_vat_scan_tag": "v1.2.3"}) == "v1.2.3"
    assert extract_scan_tag({"Results": [], "_vat_scan_tag": "release-42"}) == "release-42"


def test_extract_scan_tag_absent_or_list():
    """Return None when tag absent or input is list."""
    assert extract_scan_tag({}) is None
    assert extract_scan_tag({"matches": []}) is None
    assert extract_scan_tag([]) is None
