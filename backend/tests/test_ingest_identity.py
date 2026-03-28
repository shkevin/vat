"""Fingerprint strategy / ingest identity (dedup replay keys)."""

from app.schemas.vat import VatFindingSchema, VatFindingType, VatSeverity
from app.services.ingest_identity import compute_ingest_fingerprint


def test_compute_fingerprint_sarif_partial_ignores_line_shift():
    pfp = {"primaryLocationLineHash/v1": "stable-material-xyz"}
    base = dict(
        cve_id="rule-x",
        severity=VatSeverity.HIGH,
        description="d",
        finding_type=VatFindingType.SAST,
        image="pkg.json",
        rule_id="rule-x",
        file_path="pkg.json",
        line=10,
        partial_fingerprints=pfp,
    )
    p1 = VatFindingSchema(**base)
    p2 = VatFindingSchema(**{**base, "line": 99})
    a = compute_ingest_fingerprint(p1, "sarif", parser_id="sarif")
    b = compute_ingest_fingerprint(p2, "sarif", parser_id="sarif")
    assert a == b


def test_compute_fingerprint_no_partial_diff_line_diff_fp():
    base = dict(
        cve_id="rule-y",
        severity=VatSeverity.HIGH,
        description="d",
        finding_type=VatFindingType.SAST,
        image="src/a.py",
        rule_id="rule-y",
        file_path="src/a.py",
        line=10,
        snippet_masked="x",
    )
    p1 = VatFindingSchema(**base)
    p2 = VatFindingSchema(**{**base, "line": 20})
    a = compute_ingest_fingerprint(p1, "sarif", parser_id="sarif")
    b = compute_ingest_fingerprint(p2, "sarif", parser_id="sarif")
    assert a != b


def test_openscap_branch_unchanged():
    p = VatFindingSchema(
        cve_id="CVE-2020-1",
        severity=VatSeverity.HIGH,
        description="x",
        finding_type=VatFindingType.SCA,
        stable_rule_key="V-1",
        benchmark_family="RHEL_8_STIG",
        profile_scope="stig",
        image="host-1",
    )
    fp = compute_ingest_fingerprint(p, "openscap", parser_id="openscap")
    assert len(fp) == 64
