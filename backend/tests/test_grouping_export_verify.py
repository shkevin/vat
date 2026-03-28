"""Tests for read-only grouping export verification (multi-scanner contract)."""

import json
from pathlib import Path

import pytest

from app.services.grouping_export_verify import verify_findings_export


FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_verify_findings_export_detects_stale_group_key():
    data = json.loads((FIXTURE_DIR / "grouping_export_minimal.json").read_text())
    errors, multi = verify_findings_export(data["findings"])
    assert any("bad-1" in e for e in errors)
    assert not any("good-1" in e for e in errors)


def test_verify_findings_export_ok_when_keys_match_fixture():
    from app.services.grouping_export_verify import api_row_to_stub
    from app.services.grouping import get_finding_group_key

    data = json.loads((FIXTURE_DIR / "grouping_export_minimal.json").read_text())
    rows = []
    for row in data["findings"]:
        if row["id"] != "good-1":
            continue
        stub = api_row_to_stub(row)
        gk = get_finding_group_key(stub)  # type: ignore[arg-type]
        rows.append({**row, "groupKey": gk})
    errors, _ = verify_findings_export(rows)
    assert errors == []


def test_verify_multi_suffix_report_for_shared_prefix():
    findings = [
        {
            "id": "a",
            "findingType": "SCA",
            "cveId": "CVE-1",
            "componentBase": "openssl",
            "ecosystem": "debian",
            "component": "x",
            "image": "docker.io/containers/images/kafka",
            "tag": "latest",
            "groupKey": "sca:debian|openssl#docker.io/containers/images/kafka||latest",
        },
        {
            "id": "b",
            "findingType": "SCA",
            "cveId": "CVE-2",
            "componentBase": "openssl",
            "ecosystem": "debian",
            "component": "x",
            "image": "docker.io/containers/images/kafka",
            "tag": "3.6.1-debian-12-r12",
            "groupKey": "sca:debian|openssl#docker.io/containers/images/kafka||3.6.1-debian-12-r12",
        },
    ]
    errors, multi = verify_findings_export(findings)
    assert errors == []
    assert len(multi) == 1
    assert multi[0]["suffixCount"] == 2
