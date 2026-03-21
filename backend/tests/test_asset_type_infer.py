"""Asset type inference — aligned with frontend lib/assetTypeInfer.ts."""

from app.services.asset_type_infer import (
    infer_asset_type_from_findings,
    infer_asset_type_from_one_finding,
    looks_like_container_image_ref,
)


def test_looks_like_container_image_ref() -> None:
    assert looks_like_container_image_ref("containers/images/foo")
    assert looks_like_container_image_ref("ghcr.io/a/b:v1")
    assert looks_like_container_image_ref("nginx:1.24")
    assert not looks_like_container_image_ref("2026-03-09_1801")
    assert not looks_like_container_image_ref("")


def test_secret_bundle_is_path_not_repo() -> None:
    d = {
        "findingType": "Secret",
        "image": "kamiwaza-bundle",
        "filePath": "tools/kamiwaza-tools-rpm.private.gpg",
    }
    assert infer_asset_type_from_one_finding(d) == "path"


def test_secret_with_branch_is_repo() -> None:
    d = {
        "findingType": "Secret",
        "image": "app",
        "branch": "main",
    }
    assert infer_asset_type_from_one_finding(d) == "repo"


def test_openscap_stig_is_container() -> None:
    d = {
        "findingType": "SCA",
        "image": "containers/images/metrics",
        "component": "openssl 1.1",
        "source": "openscap",
    }
    assert infer_asset_type_from_one_finding(d) == "container"


def test_merge_prefers_container() -> None:
    findings = [
        {"findingType": "SCA", "component": "x", "source": "grype"},
        {
            "findingType": "SCA",
            "image": "containers/images/foo",
            "source": "openscap",
        },
    ]
    assert infer_asset_type_from_findings(findings) == "container"
