"""License findings from Aikido and CycloneDX must share a correlation key
when they describe the same SPDX risk on the same image+package, despite
incompatible source-specific cve_ids and tags.
"""

from app.services.correlation import correlation_key_for_payload


def _key(**kwargs) -> str:
    key, _ = correlation_key_for_payload(**kwargs)
    return key


def test_license_aikido_and_cyclonedx_share_correlation_key() -> None:
    aikido_key = _key(
        finding_type="License",
        image="containers/images/falkordb",
        branch="",
        tag="",
        cve_id="178564620",
        component="redis-cli-8.6@8.6.0-r0",
        license_expression="SSPL-1.0",
    )
    cdx_key = _key(
        finding_type="License",
        image="containers/images/falkordb",
        branch="",
        tag="8.6",
        cve_id="LICENSE-SSPL-1.0-redis-cli-8.6",
        component="redis-cli-8.6",
        license_expression="SSPL-1.0",
    )
    assert aikido_key == cdx_key, f"{aikido_key!r} != {cdx_key!r}"


def test_license_key_excludes_tag_so_tag_asymmetry_does_not_split_clusters() -> None:
    no_tag = _key(
        finding_type="License",
        image="containers/images/svc",
        branch="",
        tag="",
        cve_id="123",
        component="pkg",
        license_expression="GPL-3.0",
    )
    with_tag = _key(
        finding_type="License",
        image="containers/images/svc",
        branch="",
        tag="1.5.28",
        cve_id="LICENSE-GPL-3.0-pkg",
        component="pkg",
        license_expression="GPL-3.0",
    )
    assert no_tag == with_tag


def test_license_key_uses_spdx_not_cve_id() -> None:
    """Two findings with same SPDX+package collide; differing cve_id alone does not split."""
    a = _key(
        finding_type="License",
        image="containers/images/svc", branch="", tag="",
        cve_id="alpha", component="pkg", license_expression="MIT",
    )
    b = _key(
        finding_type="License",
        image="containers/images/svc", branch="", tag="",
        cve_id="beta", component="pkg", license_expression="MIT",
    )
    assert a == b


def test_sca_key_unchanged_still_includes_cve_and_tag() -> None:
    """Regression guard: SCA correlation behavior must not change."""
    same = _key(
        finding_type="SCA",
        image="containers/images/svc", branch="", tag="latest",
        cve_id="CVE-2024-1234", component="openssl", ecosystem="debian",
    )
    diff_tag = _key(
        finding_type="SCA",
        image="containers/images/svc", branch="", tag="other",
        cve_id="CVE-2024-1234", component="openssl", ecosystem="debian",
    )
    diff_cve = _key(
        finding_type="SCA",
        image="containers/images/svc", branch="", tag="latest",
        cve_id="CVE-2024-9999", component="openssl", ecosystem="debian",
    )
    assert same != diff_tag
    assert same != diff_cve
