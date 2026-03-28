"""Asset sidebar grouping keys — parity with correlation canonical image normalization."""

from __future__ import annotations

import pytest

from app.services.assets_service import _container_image_group_key
from app.services.container_ref_normalization import normalize_container_ref


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (
            "containers/images/metrics-server",
            "docker.io/containers/images/metrics-server:1.2.3",
        ),
        (
            "containers/images/metrics-server",
            "docker.io/containers/images/metrics-server",
        ),
    ],
)
def test_bundle_style_and_registry_path_merge(left: str, right: str) -> None:
    k0 = normalize_container_ref(left).canonical_asset_key
    k1 = normalize_container_ref(right).canonical_asset_key
    assert k0 == k1
    assert _container_image_group_key(left, None) == _container_image_group_key(right, None)


def test_group_key_matches_normalize_for_container_and_repo() -> None:
    raw = "ghcr.io/acme/svc:1.0.0"
    assert _container_image_group_key(raw, None) == normalize_container_ref(
        raw
    ).canonical_asset_key


def test_non_image_asset_id_not_canonicalized() -> None:
    """Single-token / package-scope strings stay raw (no docker.io/library/…)."""
    assert _container_image_group_key("2026-03-09_1801", None) == "2026-03-09_1801"
