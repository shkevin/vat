"""Tests for Semgrep parser."""

import pytest

from app.parsers.semgrep import SemgrepParser
from app.schemas.ingest import CanonicalFindingType, CanonicalSeverity


def test_semgrep_parser_empty():
    parser = SemgrepParser()
    assert parser.parse({"results": []}) == []


def test_semgrep_parser_results():
    semgrep = {
        "results": [
            {
                "check_id": "python.sql-injection",
                "path": "src/app.py",
                "start": {"line": 42},
                "extra": {"message": "Possible SQL injection", "severity": "ERROR"},
            },
            {
                "check_id": "python.hardcoded-secret",
                "path": "config.py",
                "start": {"line": 10},
                "extra": {"message": "Hardcoded secret", "severity": "warning"},
            },
        ]
    }
    parser = SemgrepParser()
    payloads = parser.parse(semgrep)
    assert len(payloads) == 2
    assert payloads[0].cve_id == "python.sql-injection"
    assert payloads[0].severity == CanonicalSeverity.HIGH
    assert payloads[0].file_path == "src/app.py"
    assert payloads[0].line == 42
    assert payloads[0].finding_type == CanonicalFindingType.SAST
    assert payloads[1].severity == CanonicalSeverity.MEDIUM


def test_semgrep_parser_cwe_array():
    """CWE can be array (['CWE-89: SQL Injection', 'CWE-943: ...']); extract CWE-89."""
    semgrep = {
        "results": [
            {
                "check_id": "python.sql-injection",
                "path": "src/db.py",
                "start": {"line": 5},
                "extra": {
                    "message": "SQL injection",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89: SQL Injection", "CWE-943: Improper Neutralization"]},
                },
            }
        ]
    }
    parser = SemgrepParser()
    payloads = parser.parse(semgrep)
    assert len(payloads) == 1
    assert payloads[0].cwe_id == "CWE-89"
    assert payloads[0].rule_id == "python.sql-injection"


def test_semgrep_parser_invalid():
    parser = SemgrepParser()
    with pytest.raises(ValueError, match="must be a JSON object"):
        parser.parse([])
