from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.schemas.vat import VatFindingSchema
from app.services.asset_resolver import (
    correlation_asset_image_for_ingest,
    infer_asset_kind,
    resolve_asset_for_payload,
    resolve_ingest_stub_asset_identity,
)


def _payload(**kwargs) -> VatFindingSchema:
    base = dict(cve_id="CVE-1", severity="High", description="d", image="repo/app")
    base.update(kwargs)
    return VatFindingSchema(**base)


def test_infer_asset_kind_branches():
    assert infer_asset_kind("", "x") == "unknown"
    assert infer_asset_kind("host-a", "openscap") == "host_scope"
    assert infer_asset_kind("host-a", "openscap_oval") == "host_scope"
    assert infer_asset_kind("src/main.py", "semgrep") == "path_scope"
    assert infer_asset_kind("pkg", "npm_audit") == "package_scope"
    assert infer_asset_kind("sha256:abc", "x") == "container"
    assert infer_asset_kind("containers/images/a", "x") == "container"
    assert infer_asset_kind("org/repo", "x") == "repo"
    assert infer_asset_kind("/abs/path", "x") == "path_scope"
    assert infer_asset_kind("commit:abc", "x") == "container"
    assert infer_asset_kind("a>b", "x") == "path_scope"
    assert infer_asset_kind("pkgname", "x") == "package_scope"


def test_resolve_asset_precedence_and_payload_updates():
    payload = _payload(image="repo/original", component="pkg", file_path="a/b.py")
    resolved, meta = resolve_asset_for_payload(
        payload,
        parser_id="trivy",
        source_id="src",
        asset_override="repo/override",
    )
    assert resolved.image == "repo/override"
    assert meta.reason == "explicit_override"
    assert meta.confidence == "explicit"
    assert meta.source == "src"
    assert meta.to_api_dict()["asset_id"] == "repo/override"

    payload2 = _payload(image="repo/img", component="pkg")
    resolved2, meta2 = resolve_asset_for_payload(
        payload2, parser_id="trivy", source_id="s", asset_override=None
    )
    assert resolved2.image == "repo/img"
    assert meta2.reason == "parser_image"
    assert meta2.confidence == "strong"

    payload3 = _payload(image=None, branch="main", component="openssl 3.0.0")
    resolved3, meta3 = resolve_asset_for_payload(payload3, parser_id="trivy", source_id="s")
    assert resolved3.image is None
    assert meta3.asset_id == "openssl 3.0.0"
    assert meta3.reason == "parser_component_fallback"

    payload4 = _payload(image=None, branch="main", component=None, file_path="src/app.py")
    resolved4, meta4 = resolve_asset_for_payload(payload4, parser_id="semgrep", source_id="s")
    assert resolved4.image == "path:src/app.py"
    assert meta4.reason == "parser_file_path_fallback"
    assert meta4.confidence == "weak"


def test_resolve_asset_unknown_and_strict_reject():
    payload = _payload(image=None, branch="main", component=None, file_path=None)
    resolved, meta = resolve_asset_for_payload(payload, parser_id="x", source_id="s")
    assert resolved.image is None
    assert meta.asset_id == "unknown"
    assert meta.reason == "unknown_fallback"

    with pytest.raises(ValueError, match="explicit asset required"):
        resolve_asset_for_payload(
            payload,
            parser_id="x",
            source_id="s",
            strict_mode=True,
            requires_explicit_asset=True,
        )


@pytest.mark.asyncio
async def test_correlation_asset_image_for_ingest_canonical_container_and_repo():
    """Correlation image segment: canonical ref for containers; alias chain via db.get."""
    db = AsyncMock()
    db.get = AsyncMock(return_value=None)

    out = await correlation_asset_image_for_ingest(
        db, image="GHCR.IO/Acme/App:v1.0", parser_id="trivy"
    )
    assert out == "ghcr.io/acme/app"

    out_repo = await correlation_asset_image_for_ingest(
        db, image="registry.example/corr-test", parser_id="trivy"
    )
    assert out_repo == "registry.example/corr-test"


@pytest.mark.asyncio
async def test_correlation_asset_image_for_ingest_follows_asset_alias():
    db = AsyncMock()

    async def _get(_model, key):
        if key == "raw-registry/repo":
            from types import SimpleNamespace

            return SimpleNamespace(canonical_asset_id="canonical/repo")
        return None

    db.get = _get

    out = await correlation_asset_image_for_ingest(
        db, image="raw-registry/repo", parser_id="trivy"
    )
    assert out == "canonical/repo"


@pytest.mark.asyncio
async def test_resolve_ingest_stub_asset_identity_aligns_bundle_container_with_findings():
    """Zero-finding stub uses docker.io canonical id + container type (not source package default)."""
    db = AsyncMock()
    db.get = AsyncMock(return_value=None)

    sid, stype = await resolve_ingest_stub_asset_identity(
        db,
        asset_hint="containers/images/metrics-server",
        parser_id="cyclonedx",
        source_asset_type="package",
    )
    assert sid == "docker.io/containers/images/metrics-server"
    assert stype == "container"


@pytest.mark.asyncio
async def test_resolve_ingest_stub_asset_identity_non_container_keeps_source_type():
    db = AsyncMock()
    db.get = AsyncMock(return_value=None)

    sid, stype = await resolve_ingest_stub_asset_identity(
        db,
        asset_hint="lodash",
        parser_id="npm_audit",
        source_asset_type="package",
    )
    assert sid == "lodash"
    assert stype == "package"
