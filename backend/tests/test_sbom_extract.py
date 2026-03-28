"""Tests for SBOM extraction from Trivy/Grype reports."""

from app.services.sbom_extract import (
    extract_sbom_from_grype,
    extract_sbom_from_report,
    extract_sbom_from_trivy,
)


def test_extract_sbom_from_trivy_vulnerabilities():
    """Trivy vulns yield SBOM components."""
    trivy = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Type": "npm",
                "Vulnerabilities": [
                    {"PkgName": "lib-x", "InstalledVersion": "1.2.3"},
                    {"PkgName": "pkg-y", "InstalledVersion": "2.0.0"},
                ],
            }
        ]
    }
    out = extract_sbom_from_trivy(trivy, "folder-scan")
    assert out is not None
    assert len(out["components"]) == 2
    names = {c["name"] for c in out["components"]}
    assert "lib-x" in names
    assert "pkg-y" in names
    assert all(c.get("group") == "package-lock.json" for c in out["components"])


def test_extract_sbom_from_trivy_licenses():
    """Trivy licenses yield SBOM components with license_id."""
    trivy = {
        "Results": [
            {
                "Target": "package.json",
                "Type": "npm",
                "Licenses": [
                    {"PkgName": "some-pkg", "Version": "3.0.0", "Name": "MIT"},
                ],
            }
        ]
    }
    out = extract_sbom_from_trivy(trivy, "folder-scan")
    assert out is not None
    assert len(out["components"]) == 1
    c = out["components"][0]
    assert c["name"] == "some-pkg"
    assert c["version"] == "3.0.0"
    assert c["licenses"] == [{"license": {"id": "MIT"}}]


def test_extract_sbom_from_trivy_packages():
    """Trivy Packages array yields SBOM components."""
    trivy = {
        "Results": [
            {
                "Target": "go.sum",
                "Type": "gomod",
                "Packages": [
                    {"Name": "github.com/foo/bar", "Version": "v1.0.0"},
                ],
            }
        ]
    }
    out = extract_sbom_from_trivy(trivy, "folder-scan")
    assert out is not None
    assert len(out["components"]) == 1
    c = out["components"][0]
    assert c["name"] == "github.com/foo/bar"
    assert c["version"] == "v1.0.0"
    assert c.get("language") == "go"


def test_extract_sbom_from_trivy_empty():
    """Empty Trivy returns None."""
    assert extract_sbom_from_trivy({"Results": []}, "x") is None
    assert (
        extract_sbom_from_trivy({"Results": [{"Target": "x", "Secrets": []}]}, "x")
        is None
    )


def test_extract_sbom_from_trivy_prefers_container_identity_over_temp_target():
    """When scanner injects container identity, ignore temp OCI layout paths."""
    trivy = {
        "Results": [
            {
                "Target": "/tmp/vat-wrap-abc/wrap-kamiwaza/images/deadbeef.layout (chainguard 20230214)",
                "Type": "alpine",
                "_vat_container_image": "containers/images/core",
                "_vat_container_tag": "release-0.11.0",
                "_vat_source_image": "kamiwaza-images-core-release-0.11.0",
                "Packages": [
                    {"Name": "wget", "Version": "1.2.3"},
                ],
            }
        ]
    }
    out = extract_sbom_from_trivy(trivy, "container-scan")
    assert out is not None
    assert len(out["components"]) == 1
    c = out["components"][0]
    assert c["name"] == "wget"
    assert c["group"] == "containers/images/core:release-0.11.0"
    assert "/tmp/vat-wrap-" not in c["group"]


def test_extract_sbom_from_grype():
    """Grype matches yield SBOM components."""
    grype = {
        "source": {"target": {"userInput": "my-app:latest"}},
        "matches": [
            {"artifact": {"name": "openssl", "version": "1.1.1"}},
            {"artifact": {"name": "curl", "version": "7.68.0"}},
        ],
    }
    out = extract_sbom_from_grype(grype, "grype-scan")
    assert out is not None
    assert len(out["components"]) == 2
    names = {c["name"] for c in out["components"]}
    assert "openssl" in names
    assert "curl" in names
    assert all(c.get("group") == "my-app:latest" for c in out["components"])


def test_extract_sbom_from_grype_filesystem():
    """Grype filesystem scan uses path as asset."""
    grype = {
        "source": {"target": None},
        "matches": [
            {
                "artifact": {
                    "name": "lodash",
                    "version": "4.17.21",
                    "locations": [{"path": "/app/package-lock.json"}],
                }
            }
        ],
    }
    out = extract_sbom_from_grype(grype, "grype")
    assert out is not None
    assert len(out["components"]) == 1
    assert out["components"][0]["name"] == "lodash"
    assert out["components"][0]["group"] is None  # No target in source


def test_extract_sbom_from_report_trivy():
    """extract_sbom_from_report routes Trivy."""
    trivy = {
        "Results": [
            {
                "Target": "x",
                "Vulnerabilities": [{"PkgName": "a", "InstalledVersion": "1"}],
            }
        ]
    }
    out = extract_sbom_from_report("trivy", trivy, "src")
    assert out is not None
    assert len(out["components"]) == 1


def test_extract_sbom_from_report_grype():
    """extract_sbom_from_report routes Grype."""
    grype = {"matches": [{"artifact": {"name": "b", "version": "2"}}]}
    out = extract_sbom_from_report("grype", grype, "src")
    assert out is not None
    assert len(out["components"]) == 1


def test_extract_sbom_from_report_cyclonedx():
    """extract_sbom_from_report passes through CycloneDX."""
    cdx = {"components": [{"name": "pkg", "version": "1.0"}]}
    out = extract_sbom_from_report("cyclonedx", cdx, "src")
    assert out is cdx


def test_extract_sbom_from_report_unsupported():
    """Unsupported parser returns None."""
    assert extract_sbom_from_report("sarif", {}, "x") is None
    assert extract_sbom_from_report("gitleaks", {}, "x") is None
