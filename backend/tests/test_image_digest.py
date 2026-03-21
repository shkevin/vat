"""Image digest normalization for container variant grouping."""

from app.parsers.image_digest import (
    effective_image_digest,
    extract_digest_from_image_ref,
    normalize_image_digest,
)


def test_normalize_accepts_sha256_prefix() -> None:
    h = "a" * 64
    assert normalize_image_digest(f"sha256:{h}") == f"sha256:{h}"


def test_normalize_rejects_short_hex() -> None:
    assert normalize_image_digest("sha256:abc") is None


def test_extract_from_image_ref() -> None:
    d = extract_digest_from_image_ref(
        "ghcr.io/org/app@sha256:"
        + "a" * 64
    )
    assert d == f"sha256:{'a' * 64}"


def test_effective_prefers_explicit() -> None:
    explicit = f"sha256:{'b' * 64}"
    from_image = f"ghcr.io/x/y@sha256:{'a' * 64}"
    assert effective_image_digest(explicit, from_image) == explicit


def test_effective_falls_back_to_image() -> None:
    h = "c" * 64
    ref = f"registry.io/foo/bar@sha256:{h}"
    assert effective_image_digest(None, ref) == f"sha256:{h}"
