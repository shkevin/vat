"""Tests for Trivy parser."""

import pytest

from app.parsers.trivy import TrivyParser
from app.parsers.utils import VAT_CONTAINER_IMAGE_KEY, VAT_CONTAINER_TAG_KEY
from app.schemas.ingest import CanonicalFindingType, CanonicalSeverity


def test_trivy_parser_uses_container_identity_keys():
    """vat-local-scanner injects Aikido-style image + image tag per result."""
    trivy = {
        "Results": [
            {
                "Target": "docker.io/library/alpine:3.19",
                "Class": "os-pkgs",
                "Type": "alpine",
                VAT_CONTAINER_IMAGE_KEY: "containers/images/alpine",
                VAT_CONTAINER_TAG_KEY: "3.19",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1",
                        "PkgName": "zlib",
                        "InstalledVersion": "1.3",
                        "Severity": "LOW",
                        "Title": "zlib issue",
                        "Description": "desc",
                    }
                ],
            }
        ]
    }
    parser = TrivyParser()
    payloads = parser.parse(trivy)
    assert len(payloads) == 1
    assert payloads[0].cve_id == "CVE-2024-1"
    assert payloads[0].image == "containers/images/alpine"
    assert payloads[0].tag == "3.19"


def test_trivy_parser_empty_results():
    trivy = {"Results": []}
    parser = TrivyParser()
    payloads = parser.parse(trivy)
    assert payloads == []


def test_trivy_parser_vulnerabilities():
    trivy = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "lib-x",
                        "InstalledVersion": "1.2.3",
                        "FixedVersion": "1.2.4",
                        "Severity": "HIGH",
                        "Title": "Remote code execution",
                        "Description": "A vulnerability allows RCE.",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-5678",
                        "PkgName": "pkg-y",
                        "InstalledVersion": "2.0.0",
                        "Severity": "CRITICAL",
                        "Title": "Critical flaw",
                    },
                ],
            }
        ]
    }
    parser = TrivyParser()
    payloads = parser.parse(trivy)
    assert len(payloads) == 2
    assert payloads[0].cve_id == "CVE-2024-1234"
    assert payloads[0].severity == CanonicalSeverity.HIGH
    assert payloads[0].component == "lib-x 1.2.3"
    assert payloads[0].finding_type == CanonicalFindingType.SCA
    assert payloads[0].ecosystem == "npm"
    assert payloads[0].title == "Remote code execution"
    assert payloads[1].cve_id == "CVE-2024-5678"
    assert payloads[1].severity == CanonicalSeverity.CRITICAL


def test_trivy_parser_misconfigurations():
    trivy = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS001",
                        "Title": "Run as non-root",
                        "Severity": "HIGH",
                        "Message": "Running as root is not recommended",
                    }
                ],
            }
        ]
    }
    parser = TrivyParser()
    payloads = parser.parse(trivy)
    assert len(payloads) == 1
    assert payloads[0].cve_id == "DS001"
    assert payloads[0].severity == CanonicalSeverity.HIGH
    assert payloads[0].finding_type == CanonicalFindingType.IAC
    assert payloads[0].file_path == "Dockerfile"
    assert payloads[0].rule_id == "DS001"
    assert payloads[0].resource == "Dockerfile"


def test_trivy_parser_secrets():
    trivy = {
        "Results": [
            {
                "Target": ".env",
                "Secrets": [
                    {
                        "RuleID": "aws-access-key",
                        "Category": "AWS",
                        "Severity": "HIGH",
                        "Match": "AKIAIOSFODNN7EXAMPLE",
                    }
                ],
            }
        ]
    }
    parser = TrivyParser()
    payloads = parser.parse(trivy)
    assert len(payloads) == 1
    assert payloads[0].cve_id == "aws-access-key"
    assert payloads[0].severity == CanonicalSeverity.HIGH
    assert payloads[0].finding_type == CanonicalFindingType.SECRET
    assert payloads[0].file_path == ".env"
    assert payloads[0].rule_id == "aws-access-key"
    assert payloads[0].secret_type == "AWS"


def test_trivy_parser_licenses():
    trivy = {
        "Results": [
            {
                "Target": "package.json",
                "Licenses": [
                    {
                        "Name": "GPL-3.0",
                        "Category": "restricted",
                        "Severity": "HIGH",
                        "PkgName": "some-pkg",
                    }
                ],
            }
        ]
    }
    parser = TrivyParser()
    payloads = parser.parse(trivy)
    assert len(payloads) == 1
    assert payloads[0].cve_id == "license:GPL-3.0"
    assert payloads[0].severity == CanonicalSeverity.HIGH
    assert payloads[0].finding_type == CanonicalFindingType.LICENSE
    assert payloads[0].title == "GPL-3.0"


def test_trivy_parser_mixed():
    trivy = {
        "Results": [
            {
                "Target": "app/",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-1",
                        "PkgName": "a",
                        "Severity": "MEDIUM",
                        "Title": "T1",
                    }
                ],
                "Secrets": [{"RuleID": "secret-1", "Severity": "HIGH", "Match": "x"}],
            }
        ]
    }
    parser = TrivyParser()
    payloads = parser.parse(trivy)
    assert len(payloads) == 2
    cve_payloads = [p for p in payloads if p.finding_type == CanonicalFindingType.SCA]
    secret_payloads = [
        p for p in payloads if p.finding_type == CanonicalFindingType.SECRET
    ]
    assert len(cve_payloads) == 1
    assert len(secret_payloads) == 1


def test_trivy_parser_snake_case():
    """Trivy can output snake_case keys in some modes."""
    trivy = {
        "results": [
            {
                "target": "go.sum",
                "vulnerabilities": [
                    {
                        "vulnerabilityID": "CVE-2024-9999",
                        "pkgName": "mod-x",
                        "installedVersion": "0.1.0",
                        "severity": "low",
                        "title": "Low severity issue",
                    }
                ],
            }
        ]
    }
    parser = TrivyParser()
    payloads = parser.parse(trivy)
    assert len(payloads) == 1
    assert payloads[0].cve_id == "CVE-2024-9999"
    assert payloads[0].severity == CanonicalSeverity.LOW
    assert payloads[0].component == "mod-x 0.1.0"


def test_trivy_parser_invalid_input():
    parser = TrivyParser()
    with pytest.raises(ValueError, match="must be a JSON object"):
        parser.parse("not a dict")


def test_trivy_parser_secrets_nested_with_filepath():
    """Trivy fanal: Secret has FilePath + Findings[]. Location should include both container and path."""
    trivy = {
        "Results": [
            {
                "Target": "kamiwaza-bundle",
                "_vat_source_image": "kamiwaza-images-core-release-0.11.0",
                "Secrets": [
                    {
                        "FilePath": "/app/config/key.pem",
                        "Findings": [
                            {
                                "RuleID": "private-key",
                                "Category": "AsymmetricPrivateKey",
                                "Severity": "HIGH",
                                "Match": "-----BEGIN PGP",
                            }
                        ],
                    }
                ],
            }
        ]
    }
    parser = TrivyParser()
    payloads = parser.parse(trivy)
    assert len(payloads) == 1
    assert payloads[0].cve_id == "private-key"
    assert payloads[0].finding_type == CanonicalFindingType.SECRET
    # Location: source_image:path within image
    assert (
        payloads[0].file_path
        == "kamiwaza-images-core-release-0.11.0:/app/config/key.pem"
    )


def test_trivy_parser_secrets_flat_with_source_image():
    """Flat secret with _vat_source_image: file_path should be source_image."""
    trivy = {
        "Results": [
            {
                "Target": "kamiwaza-bundle",
                "_vat_source_image": "kamiwaza-images-core-release-0.11.0",
                "Secrets": [
                    {
                        "RuleID": "private-key",
                        "Category": "AsymmetricPrivateKey",
                        "Severity": "HIGH",
                        "Match": "-----BEGIN PGP",
                    }
                ],
            }
        ]
    }
    parser = TrivyParser()
    payloads = parser.parse(trivy)
    assert len(payloads) == 1
    assert payloads[0].file_path == "kamiwaza-images-core-release-0.11.0"


def test_trivy_parser_secrets_with_source_path():
    """FS scan: _vat_source_path preserves original path (scanner saves before overwriting Target)."""
    trivy = {
        "Results": [
            {
                "Target": "kamiwaza-bundle",
                "_vat_source_path": "extracted/wrap-abc123/images/core-release-0.11.0.layout/.env",
                "Secrets": [
                    {
                        "RuleID": "generic-api-key",
                        "Category": "Generic",
                        "Severity": "HIGH",
                        "Match": "api_key=xxx",
                    }
                ],
            }
        ]
    }
    parser = TrivyParser()
    payloads = parser.parse(trivy)
    assert len(payloads) == 1
    assert "extracted" in payloads[0].file_path
    assert (
        payloads[0].file_path
        == "extracted/wrap-abc123/images/core-release-0.11.0.layout/.env"
    )
