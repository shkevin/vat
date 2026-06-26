"""Golden and stability tests for Decision Subject Keys (no database)."""

import json
from pathlib import Path

from app.parsers import get_parser
from app.services.correlation import correlation_key_for_payload
from app.services.decision_subject_key import (
    DECISION_KEY_VERSION,
    decision_subject_keys_for_payload,
)

_FIXTURES = Path(__file__).resolve().parent / "integration" / "fixtures" / "correlation"


def _payload_keys(p, *, tenant_id: str = "tenant-a") -> list[str]:
    return [
        c.subject_key
        for c in decision_subject_keys_for_payload(
            tenant_id=tenant_id,
            finding_type=str(p.finding_type.value),
            canonical_asset=p.image or p.component or "",
            branch=getattr(p, "branch", None) or "",
            tag=getattr(p, "tag", None) or "",
            cve_id=p.cve_id,
            component=p.component or "",
            ecosystem=getattr(p, "ecosystem", None),
            rule_id=getattr(p, "rule_id", None),
            file_path=getattr(p, "file_path", None),
            benchmark_family=getattr(p, "benchmark_family", None),
            license_expression=getattr(p, "license_expression", None),
            stable_rule_key=getattr(p, "stable_rule_key", None),
            profile_scope=getattr(p, "profile_scope", None),
            source_name="trivy",
            source_issue_id=getattr(p, "source_issue_id", None),
        )
    ]


def test_dsk_null_tenant_uses_default_tenant_segment() -> None:
    keys = decision_subject_keys_for_payload(
        tenant_id=None,
        finding_type="SCA",
        canonical_asset="registry.example/api",
        branch="",
        tag="latest",
        cve_id="CVE-2024-1",
        component="openssl@3",
    )
    assert keys[0].subject_key.startswith(f"{DECISION_KEY_VERSION}:t-default:")


def test_trivy_and_grype_share_primary_dsk() -> None:
    trivy = get_parser("trivy").parse(
        json.loads((_FIXTURES / "trivy-e2e.json").read_text())
    )
    grype = get_parser("grype").parse(
        json.loads((_FIXTURES / "grype-e2e.json").read_text())
    )
    assert len(trivy) == 1 and len(grype) == 1
    k1 = _payload_keys(trivy[0])[0]
    k2 = _payload_keys(grype[0])[0]
    assert k1 == k2
    assert k1.startswith(f"{DECISION_KEY_VERSION}:tenant-a:sca:")


def test_dsk_differs_from_correlation_key_by_tenant_and_prefix() -> None:
    trivy = get_parser("trivy").parse(
        json.loads((_FIXTURES / "trivy-e2e.json").read_text())
    )[0]
    dsk = _payload_keys(trivy, tenant_id="acme")[0]
    corr, _ = correlation_key_for_payload(
        finding_type=str(trivy.finding_type.value),
        image=trivy.image or "",
        branch=getattr(trivy, "branch", None) or "",
        tag=getattr(trivy, "tag", None) or "",
        cve_id=trivy.cve_id,
        component=trivy.component or "",
        ecosystem=getattr(trivy, "ecosystem", None),
    )
    assert dsk != corr
    assert dsk.startswith(f"{DECISION_KEY_VERSION}:acme:")
    assert corr.startswith("v1:")


def test_dsk_stable_across_tag_change_for_sca() -> None:
    base = dict(
        tenant_id="t1",
        finding_type="SCA",
        canonical_asset="registry.example/api-server",
        branch="",
        cve_id="CVE-2024-1234",
        component="openssl@3.0.2",
        ecosystem="deb",
    )
    k_old = decision_subject_keys_for_payload(**base, tag="v1.0.0")[0].subject_key
    k_new = decision_subject_keys_for_payload(**base, tag="v2.0.0")[0].subject_key
    # Tag is part of asset segment — different tags are different decision subjects.
    assert k_old != k_new


def test_dsk_license_drops_tag_like_correlation() -> None:
    base = dict(
        tenant_id="t1",
        finding_type="License",
        canonical_asset="registry.example/api-server",
        branch="main",
        cve_id="LICENSE-AGPL-3.0-openssl",
        component="openssl",
        license_expression="AGPL-3.0",
    )
    k1 = decision_subject_keys_for_payload(**base, tag="")[0].subject_key
    k2 = decision_subject_keys_for_payload(**base, tag="latest")[0].subject_key
    assert k1 == k2


def test_source_issue_alias_candidate_present() -> None:
    keys = decision_subject_keys_for_payload(
        tenant_id="t1",
        finding_type="SCA",
        canonical_asset="img",
        cve_id="CVE-2024-1",
        component="pkg",
        source_name="Aikido",
        source_issue_id="12345",
    )
    kinds = {c.kind for c in keys}
    assert "primary" in kinds
    assert "source_issue" in kinds
    source_keys = [c for c in keys if c.kind == "source_issue"]
    assert source_keys[0].subject_key.endswith(":source:aikido:12345:img||")


def test_openscap_stable_rule_key_high_confidence() -> None:
    keys = decision_subject_keys_for_payload(
        tenant_id="t1",
        finding_type="SAST",
        canonical_asset="host.example",
        cve_id="SV-123_rule",
        stable_rule_key="SV-123_rule",
        benchmark_family="RHEL_8_STIG",
        profile_scope="xccdf_org.ssgproject.content_profile_stig",
    )
    primary = keys[0]
    assert primary.confidence == "high"
    assert ":openscap:" in primary.subject_key


def test_tenant_isolation() -> None:
    args = dict(
        finding_type="SCA",
        canonical_asset="img",
        cve_id="CVE-1",
        component="pkg",
    )
    k_a = decision_subject_keys_for_payload(tenant_id="tenant-a", **args)[0].subject_key
    k_b = decision_subject_keys_for_payload(tenant_id="tenant-b", **args)[0].subject_key
    assert k_a != k_b
