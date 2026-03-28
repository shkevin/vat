"""Tests for CycloneDX container identity extraction (SBOM metadata)."""

from app.services.cyclonedx_identity import (
    extract_container_identity_from_cyclonedx,
    unwrap_cyclonedx_document,
)


def test_unwrap_nested_sbom_key():
    inner = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {"component": {"name": "x"}},
    }
    assert unwrap_cyclonedx_document({"sbom": inner}) == inner


def test_extract_from_oci_purl_and_trivy_props():
    h = "a" * 64
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {
                "type": "container",
                "name": "alpine:3.19",
                "purl": f"pkg:oci/alpine@sha256%3A{h}?arch=amd64&repository_url=index.docker.io%2Flibrary%2Falpine",
                "properties": [
                    {"name": "aquasecurity:trivy:RepoDigest", "value": f"alpine@sha256:{h}"},
                    {"name": "aquasecurity:trivy:RepoTag", "value": "alpine:3.19"},
                ],
            }
        },
        "components": [],
    }
    ident = extract_container_identity_from_cyclonedx(doc)
    assert ident.digest == f"sha256:{h}"
    assert ident.tag == "3.19"
    assert ident.stamp_ref == f"alpine@sha256:{h}"


def test_extract_tag_from_name_only():
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {"component": {"name": "myregistry.io/app:v2"}},
        "components": [],
    }
    ident = extract_container_identity_from_cyclonedx(doc)
    assert ident.digest is None
    assert ident.tag == "v2"
    assert ident.stamp_ref == "myregistry.io/app:v2"
