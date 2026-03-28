"""Tests for Aikido-style container asset normalization."""

from vat_scanner.container_identity import canonical_container_asset, split_repo_and_tag


def test_split_repo_and_tag_simple() -> None:
    assert split_repo_and_tag("ghcr.io/acme/foo/bar:v1.2.3") == ("ghcr.io/acme/foo/bar", "v1.2.3")
    assert split_repo_and_tag("redis:7") == ("redis", "7")


def test_image_digest_from_ref() -> None:
    from vat_scanner.container_identity import image_digest_from_ref

    h = "a" * 64
    assert image_digest_from_ref(f"ghcr.io/x/app@sha256:{h}") == f"sha256:{h}"
    assert image_digest_from_ref("ghcr.io/x/app:latest") is None


def test_split_repo_and_tag_digest_stripped() -> None:
    r, t = split_repo_and_tag("ghcr.io/x/app@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
    assert "@sha256" not in r
    assert t == "latest"


def test_split_repo_and_tag_registry_port() -> None:
    assert split_repo_and_tag("localhost:5000/org/img:latest") == ("localhost:5000/org/img", "latest")


def test_canonical_from_image_ref() -> None:
    img, tag = canonical_container_asset("ghcr.io/kamiwaza/metrics-server:v0.11.0", "ignored-label")
    assert img == "containers/images/metrics-server"
    assert tag == "v0.11.0"


def test_canonical_fallback_label() -> None:
    img, tag = canonical_container_asset(None, "bundle-images-minio-fips-release-1.0.0")
    assert img == "containers/images/minio-fips"
    assert tag == "latest"
