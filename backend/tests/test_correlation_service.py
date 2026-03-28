from app.services.correlation import correlation_key_for_payload


def _base_kwargs():
    return dict(
        finding_type="SCA",
        image="ghcr.io/org/app:v1",
        branch="main",
        tag="v1",
        cve_id="CVE-2026-0001",
        component="openssl 3.0.0",
    )


def test_correlation_sca_high_and_medium():
    key, conf = correlation_key_for_payload(**_base_kwargs(), ecosystem="npm")
    assert conf == "high"
    assert key.startswith("v1:sca:")
    assert ":npm:openssl:" in key

    kwargs2 = _base_kwargs()
    kwargs2["component"] = ""
    kwargs2["ecosystem"] = None
    key2, conf2 = correlation_key_for_payload(**kwargs2)
    assert conf2 == "medium"
    assert key2.startswith("v1:sca:")
    assert key2.endswith(":cve-2026-0001")


def test_correlation_code_paths_and_other_fallback():
    kwargs_medium = _base_kwargs()
    kwargs_medium["finding_type"] = "SAST"
    kwargs_medium["rule_id"] = "RULE-1"
    kwargs_medium["file_path"] = "src/main.py"
    medium_key, medium_conf = correlation_key_for_payload(**kwargs_medium)
    assert medium_conf == "medium"
    assert medium_key.startswith("v1:sast:")
    assert ":rule-1:src/main.py" in medium_key

    kwargs_low = _base_kwargs()
    kwargs_low["finding_type"] = "IaC"
    kwargs_low["rule_id"] = "IAC-2"
    kwargs_low["file_path"] = None
    low_key, low_conf = correlation_key_for_payload(**kwargs_low)
    assert low_conf == "low"
    assert low_key.startswith("v1:iac:")
    assert low_key.endswith(":iac-2")

    kwargs_low2 = _base_kwargs()
    kwargs_low2["finding_type"] = "Secret"
    kwargs_low2["rule_id"] = None
    kwargs_low2["file_path"] = None
    low_key2, low_conf2 = correlation_key_for_payload(**kwargs_low2)
    assert low_conf2 == "low"
    assert low_key2.startswith("v1:secret:")
    assert low_key2.endswith(":cve-2026-0001")

    kwargs_other = _base_kwargs()
    kwargs_other["finding_type"] = "Custom"
    kwargs_other["component"] = "pkg 1.2.3"
    other_key, other_conf = correlation_key_for_payload(**kwargs_other)
    assert other_conf == "low"
    assert other_key.startswith("v1:other:")
    assert other_key.endswith(":pkg")


def test_correlation_sca_appends_digest_when_enabled():
    base = _base_kwargs()
    d = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    key_off, _ = correlation_key_for_payload(
        **base,
        ecosystem="npm",
        image_digest=d,
        include_digest_in_correlation=False,
    )
    key_on, _ = correlation_key_for_payload(
        **base,
        ecosystem="npm",
        image_digest=d,
        include_digest_in_correlation=True,
    )
    assert ":digest:" not in key_off
    assert f":digest:{d}" in key_on
    assert key_off != key_on


def test_correlation_sca_openscap_style_aligns_with_aikido_debian_container():
    """CPE ``ssl`` + debian tag + same CVE → same key as explicit debian/openssl."""
    img = "docker.io/containers/images/kafka"
    tag = "3.6.1-debian-12-r12"
    cve = "CVE-2024-8888"
    openscap_like, _ = correlation_key_for_payload(
        finding_type="SCA",
        image=img,
        branch="",
        tag=tag,
        cve_id=cve,
        component="ssl 3.0",
        ecosystem=None,
        benchmark_family=None,
    )
    aikido_like, _ = correlation_key_for_payload(
        finding_type="SCA",
        image=img,
        branch="",
        tag=tag,
        cve_id=cve,
        component="openssl 3.0",
        ecosystem="debian",
        benchmark_family=None,
    )
    assert openscap_like == aikido_like


def test_correlation_sast_includes_partial_fingerprint_segment():
    kwargs = _base_kwargs()
    kwargs["finding_type"] = "SAST"
    kwargs["rule_id"] = "RULE-1"
    kwargs["file_path"] = "src/main.py"
    key, conf = correlation_key_for_payload(
        **kwargs,
        sast_partial_fingerprint_hash="abc123deadbeef",
    )
    assert conf == "medium"
    assert ":fp:abc123deadbeef" in key
    assert key.startswith("v1:sast:")
