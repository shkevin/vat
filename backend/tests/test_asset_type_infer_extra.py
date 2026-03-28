from app.services.asset_type_infer import (
    infer_asset_type_from_findings,
    infer_asset_type_from_one_finding,
    looks_like_container_image_ref,
)


def test_container_image_ref_extra_branches():
    assert looks_like_container_image_ref("repo@sha256:abc")
    assert looks_like_container_image_ref("bad$name:1") is False


def test_infer_one_finding_branch_coverage():
    assert (
        infer_asset_type_from_one_finding({"findingType": "secret", "image": "nginx:1.24"})
        == "container"
    )
    assert (
        infer_asset_type_from_one_finding({"source": "openscap_oval", "image": "host"})
        == "container"
    )
    assert infer_asset_type_from_one_finding({"image": "containers/images/x"}) == "container"
    assert infer_asset_type_from_one_finding({"image": "x", "branch": "main"}) == "repo"
    assert infer_asset_type_from_one_finding({"image": "x", "findingType": "sast"}) == "repo"
    assert infer_asset_type_from_one_finding({"image": "ghcr.io/a/b:v1"}) == "container"
    assert infer_asset_type_from_one_finding({"image": "bundle-folder"}) == "container"
    assert infer_asset_type_from_one_finding({"filePath": "a/b.txt"}) == "path"
    assert (
        infer_asset_type_from_one_finding(
            {"filePath": "a/b.py", "findingType": "iac", "component": "pkg"}
        )
        == "repo"
    )
    assert infer_asset_type_from_one_finding({"component": "pkg"}) == "package"
    assert infer_asset_type_from_one_finding({}) == "package"


def test_infer_from_findings_empty_default():
    assert infer_asset_type_from_findings([]) == "package"
