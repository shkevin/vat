"""Unit tests for SCA cross-scanner normalization."""

from app.services.sca_cross_scanner import (
    effective_sca_ecosystem,
    infer_sca_ecosystem_from_container_ref,
    normalize_sca_package_for_cross_scanner,
)


def test_normalize_ssl_to_openssl():
    assert normalize_sca_package_for_cross_scanner("ssl") == "openssl"
    assert normalize_sca_package_for_cross_scanner("libssl3") == "openssl"


def test_infer_ecosystem_from_debian_tag():
    assert (
        infer_sca_ecosystem_from_container_ref(
            "docker.io/bitnami/kafka", "3.6.1-debian-12-r12"
        )
        == "debian"
    )


def test_effective_ecosystem_prefers_explicit():
    assert effective_sca_ecosystem("pypi", "RHEL_9_STIG", image="x", tag="y") == "pypi"


def test_effective_ecosystem_benchmark_rhel():
    assert (
        effective_sca_ecosystem(None, "RHEL_9_STIG", image="img", tag="latest") == "rpm"
    )
