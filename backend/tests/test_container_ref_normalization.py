from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.schemas.vat import VatFindingSchema
from app.services.asset_resolver import resolve_asset_for_payload
from app.services.container_ref_normalization import (
    NormalizedContainerRef,
    apply_container_asset_path_aliases,
    is_safe_tag_only_alias_variant,
    normalize_container_ref,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            "ghcr.io/kamiwaza/images/core-dev:1.2.3",
            NormalizedContainerRef(
                canonical_asset_key="ghcr.io/kamiwaza/images/core-dev",
                observed_tag="1.2.3",
                observed_digest=None,
                raw_ref="ghcr.io/kamiwaza/images/core-dev:1.2.3",
            ),
        ),
        (
            "ghcr.io/kamiwaza/images/core-dev@sha256:" + ("a" * 64),
            NormalizedContainerRef(
                canonical_asset_key="ghcr.io/kamiwaza/images/core-dev",
                observed_tag=None,
                observed_digest="sha256:" + ("a" * 64),
                raw_ref="ghcr.io/kamiwaza/images/core-dev@sha256:" + ("a" * 64),
            ),
        ),
        (
            "myregistry.example:5000/org/app:latest",
            NormalizedContainerRef(
                canonical_asset_key="myregistry.example:5000/org/app",
                observed_tag="latest",
                observed_digest=None,
                raw_ref="myregistry.example:5000/org/app:latest",
            ),
        ),
        (
            "ubuntu:22.04",
            NormalizedContainerRef(
                canonical_asset_key="docker.io/library/ubuntu",
                observed_tag="22.04",
                observed_digest=None,
                raw_ref="ubuntu:22.04",
            ),
        ),
        (
            "library/nginx:1.25",
            NormalizedContainerRef(
                canonical_asset_key="docker.io/library/nginx",
                observed_tag="1.25",
                observed_digest=None,
                raw_ref="library/nginx:1.25",
            ),
        ),
    ],
)
def test_normalize_container_ref_vectors(
    raw: str, expected: NormalizedContainerRef
) -> None:
    assert normalize_container_ref(raw) == expected


def test_apply_container_asset_path_aliases_rewrites_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "VAT_CONTAINER_ASSET_PATH_ALIASES",
        "docker.io/operators/images/=>docker.io/containers/images/",
    )
    get_settings.cache_clear()
    assert (
        apply_container_asset_path_aliases("docker.io/operators/images/etcd")
        == "docker.io/containers/images/etcd"
    )
    assert apply_container_asset_path_aliases("docker.io/other/etcd") == "docker.io/other/etcd"


def test_apply_container_asset_path_aliases_empty_dst_strips_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Part B: registry prefixes strip to bare org/path (online ↔ local scanner)."""
    monkeypatch.setenv(
        "VAT_CONTAINER_ASSET_PATH_ALIASES",
        "docker.io/=>;ghcr.io/kamiwaza-internal/=>;registry-1.docker.io/=>",
    )
    get_settings.cache_clear()
    assert (
        apply_container_asset_path_aliases("docker.io/containers/images/python")
        == "containers/images/python"
    )
    assert (
        apply_container_asset_path_aliases(
            "ghcr.io/kamiwaza-internal/containers/images/python"
        )
        == "containers/images/python"
    )
    assert (
        apply_container_asset_path_aliases(
            "registry-1.docker.io/bitnamilegacy/postgresql"
        )
        == "bitnamilegacy/postgresql"
    )
    assert (
        apply_container_asset_path_aliases(
            "docker.io/kamiwaza-extensions-kaizen/images/backend"
        )
        == "kamiwaza-extensions-kaizen/images/backend"
    )


def test_resolver_applies_container_path_aliases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "VAT_CONTAINER_ASSET_PATH_ALIASES",
        "docker.io/operators/images/=>docker.io/containers/images/",
    )
    get_settings.cache_clear()
    payload = VatFindingSchema(
        cve_id="CVE-2026-1",
        severity="High",
        description="d",
        image="docker.io/operators/images/etcd:latest",
    )
    _resolved_payload, meta = resolve_asset_for_payload(
        payload, parser_id="trivy", source_id="src"
    )
    assert meta.asset_id == "docker.io/containers/images/etcd"


def test_cross_registry_not_equal() -> None:
    left = normalize_container_ref("ghcr.io/acme/service:1.0.0")
    right = normalize_container_ref("docker.io/acme/service:1.0.0")
    assert left.canonical_asset_key != right.canonical_asset_key


def test_safe_tag_only_alias_variant_rules() -> None:
    assert is_safe_tag_only_alias_variant(
        "ghcr.io/acme/service:1.0.0",
        "ghcr.io/acme/service",
    )
    assert not is_safe_tag_only_alias_variant(
        "ghcr.io/acme/service@sha256:" + ("d" * 64),
        "ghcr.io/acme/service",
    )
    assert not is_safe_tag_only_alias_variant(
        "docker.io/acme/service:1.0.0",
        "ghcr.io/acme/service",
    )


def test_resolver_sets_canonical_image_and_observations() -> None:
    payload = VatFindingSchema(
        cve_id="CVE-2026-1234",
        severity="High",
        description="d",
        image="ghcr.io/acme/service:prod@sha256:" + ("b" * 64),
    )
    resolved_payload, meta = resolve_asset_for_payload(
        payload, parser_id="trivy", source_id="src"
    )
    assert meta.asset_id == "ghcr.io/acme/service"
    assert resolved_payload.image == "ghcr.io/acme/service"
    assert resolved_payload.tag == "prod"
    assert resolved_payload.image_digest == "sha256:" + ("b" * 64)


def test_resolver_handles_untagged_digest_ref() -> None:
    payload = VatFindingSchema(
        cve_id="CVE-2026-1234",
        severity="High",
        description="d",
        image="ghcr.io/acme/scratch@sha256:" + ("c" * 64),
    )
    resolved_payload, meta = resolve_asset_for_payload(
        payload, parser_id="trivy", source_id="src"
    )
    assert meta.asset_id == "ghcr.io/acme/scratch"
    assert resolved_payload.image == "ghcr.io/acme/scratch"
    assert resolved_payload.tag is None
    assert resolved_payload.image_digest == "sha256:" + ("c" * 64)


def test_resolver_keeps_explicit_image_digest_when_image_has_no_digest() -> None:
    """Adapters may send image_digest alongside a repo:tag ref without @sha256."""
    h = "a" * 64
    payload = VatFindingSchema(
        cve_id="CVE-2026-9999",
        severity="High",
        description="d",
        image="docker.io/operators/images/extension-operator:1.36.0",
        image_digest=f"sha256:{h}",
    )
    resolved_payload, meta = resolve_asset_for_payload(
        payload, parser_id="trivy", source_id="src"
    )
    assert "extension-operator" in meta.asset_id
    assert resolved_payload.image_digest == f"sha256:{h}"
