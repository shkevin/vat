"""Tests for ingest asset-type transform."""

import pytest

from app.api.ingest import _apply_asset_type_transform
from app.schemas.vat import VatFindingSchema


def test_apply_asset_type_transform_package_only():
    """Package source: image moved to component."""
    p = VatFindingSchema(
        cve_id="CVE-1",
        severity="High",
        description="x",
        image="package.json>foo",
    )
    out = _apply_asset_type_transform(p, "package")
    assert out.image is None
    assert out.component == "package.json>foo"
    assert out.tag == "package.json>foo"


def test_apply_asset_type_transform_container_plus_package_preserved():
    """Container+package: preserve both so packages group under image."""
    p = VatFindingSchema(
        cve_id="CVE-2025-68121",
        severity="Critical",
        description="x",
        image="kamiwaza-bundle:kamiwaza-images",
        component="stdlib v1.25.0",
    )
    out = _apply_asset_type_transform(p, "package")
    assert out.image == "kamiwaza-bundle:kamiwaza-images"
    assert out.component == "stdlib v1.25.0"


def test_apply_asset_type_transform_skip_when_not_package():
    """Non-package source: no transform."""
    p = VatFindingSchema(
        cve_id="CVE-1",
        severity="High",
        description="x",
        image="my-image:latest",
        component="pkg 1.0",
    )
    out = _apply_asset_type_transform(p, "container")
    assert out.image == "my-image:latest"
    assert out.component == "pkg 1.0"
