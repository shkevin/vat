"""Tests for Aikido adapter using respx to mock the REST API."""

from app.adapters.aikido import (
    AikidoAdapter,
    _extract_image_digest_from_issue,
    _strip_tag_from_container_name,
    aikido_container_list_item_tags,
    fetch_aikido_issues,
    fetch_aikido_code_repositories,
)

_SHA64 = "a" * 64
_SHA64B = "b" * 64
from app.schemas.ingest import CanonicalSeverity


async def test_aikido_fetch_issues(aikido_respx):
    """Fetch issues returns mocked issue list from /issues/export."""
    issues = await fetch_aikido_issues(
        credentials={
            "client_id": "test-client",
            "client_secret": "test-secret",
            "region": "eu",
        }
    )
    assert len(issues) == 1
    assert issues[0]["cve_id"] == "CVE-2024-21626"
    assert issues[0]["code_repo_name"] == "test-repo"


async def test_aikido_fetch_repositories(aikido_respx):
    """Fetch code repositories returns mocked repo list."""
    repos = await fetch_aikido_code_repositories(
        credentials={"client_id": "test", "client_secret": "test", "region": "eu"}
    )
    assert len(repos) == 1
    assert repos[0]["id"] == 1
    assert repos[0]["branch"] == "main"


async def test_aikido_adapter_ingest():
    """AikidoAdapter.ingest maps webhook payload to canonical format."""
    adapter = AikidoAdapter()
    payload = {
        "event": "issue.created",
        "issue": {
            "id": "123",
            "cve_id": "CVE-2024-21626",
            "title": "Test CVE",
            "type": "vulnerability",
            "severity": "high",
            "code_repo_name": "my-repo",
            "branch": "main",
            "first_detected_at": "2024-01-15T10:30:00Z",
        },
    }
    result = await adapter.to_vat_finding(payload)
    assert result.cve_id == "CVE-2024-21626"
    assert result.severity == CanonicalSeverity.HIGH
    assert result.image == "my-repo"
    assert result.branch == "main"
    assert result.first_detected_at == "2024-01-15T10:30:00Z"


async def test_aikido_adapter_component_base_strips_version():
    """component_base strips version from 'name version' format for SCA grouping."""
    adapter = AikidoAdapter()
    payload = {
        "issue": {
            "id": "456",
            "cve_id": "CVE-2024-9999",
            "type": "vulnerability",
            "severity": "medium",
            "component": "vllm",
            "installed_version": "0.8.5.post1+cpu",
            "code_repo_name": "ml-service",
        },
    }
    result = await adapter.to_vat_finding(payload)
    assert result.component == "vllm 0.8.5.post1+cpu"
    assert result.component_base == "vllm"


def test_extract_image_digest_from_issue_top_level():
    """Explicit image_digest on issue is normalized to sha256:<hex>."""
    assert (
        _extract_image_digest_from_issue({"image_digest": f"sha256:{_SHA64}"}, None)
        == f"sha256:{_SHA64}"
    )


def test_extract_image_digest_from_issue_nested_container():
    """Digest may live on nested container object."""
    assert (
        _extract_image_digest_from_issue(
            {"container": {"digest": f"sha256:{_SHA64}"}}, None
        )
        == f"sha256:{_SHA64}"
    )


def test_extract_image_digest_falls_back_to_image_ref():
    """When issue has no digest fields, parse @sha256 from image reference."""
    ref = f"docker.io/foo/bar@sha256:{_SHA64}"
    assert _extract_image_digest_from_issue({}, ref) == f"sha256:{_SHA64}"


def test_strip_tag_from_container_name():
    """Container asset names have :tag stripped; tag is stored separately."""
    assert (
        _strip_tag_from_container_name(
            "containers/images/cert-manager-acmesolver-fips:latest"
        )
        == "containers/images/cert-manager-acmesolver-fips"
    )
    assert (
        _strip_tag_from_container_name("containers/images/etcd")
        == "containers/images/etcd"
    )
    assert (
        _strip_tag_from_container_name("registry.io:5000/image:v1.2")
        == "registry.io:5000/image"
    )
    assert _strip_tag_from_container_name(None) is None
    assert _strip_tag_from_container_name("") == ""


async def test_aikido_adapter_populates_image_digest():
    """Aikido issues with image_digest populate VatFindingSchema.image_digest."""
    adapter = AikidoAdapter()
    payload = {
        "issue": {
            "id": "digest-ingest",
            "cve_id": "CVE-2024-1111",
            "type": "vulnerability",
            "severity": "high",
            "container_repo_name": "containers/images/etcd",
            "image_digest": f"sha256:{_SHA64}",
        },
    }
    result = await adapter.to_vat_finding(payload)
    assert result.image_digest == f"sha256:{_SHA64}"


async def test_aikido_adapter_image_digest_prefers_explicit_over_ref():
    """Explicit digest field wins over digest embedded in container_repo_name."""
    adapter = AikidoAdapter()
    payload = {
        "issue": {
            "id": "digest-pref",
            "cve_id": "CVE-2024-2222",
            "type": "vulnerability",
            "severity": "medium",
            "container_repo_name": f"containers/images/etcd@sha256:{_SHA64}",
            "image_digest": f"sha256:{_SHA64B}",
        },
    }
    result = await adapter.to_vat_finding(payload)
    assert result.image_digest == f"sha256:{_SHA64B}"


async def test_aikido_adapter_container_path_strips_tag():
    """Container paths with :tag have tag stripped from asset name, stored in tag field."""
    adapter = AikidoAdapter()
    payload = {
        "issue": {
            "id": "999",
            "cve_id": "CVE-2024-1234",
            "type": "vulnerability",
            "severity": "high",
            "container_repo_name": "containers/images/cert-manager-acmesolver-fips:latest",
        },
    }
    result = await adapter.to_vat_finding(payload)
    assert result.image == "containers/images/cert-manager-acmesolver-fips"
    assert result.tag == "latest"


async def test_aikido_adapter_collects_tags_from_instances():
    """Per-instance tags populate observed_container_tags for the asset UI."""
    adapter = AikidoAdapter()
    payload = {
        "issue": {
            "id": "inst-1",
            "cve_id": "CVE-2024-7777",
            "type": "vulnerability",
            "severity": "high",
            "container_repo_name": "containers/images/myapp",
            "instances": [
                {"type": "container_repository", "tag": "1.4.0"},
                {"type": "container_repository", "image": "registry.io/ns/myapp:v2"},
            ],
        },
    }
    result = await adapter.to_vat_finding(payload)
    assert result.tag == "1.4.0"
    assert result.observed_container_tags == ["1.4.0", "v2"]

    assert aikido_container_list_item_tags(
        {
            "name": "containers/images/foo",
            "tags": ["1.0.0", "1.1.0"],
        }
    ) == ["1.0.0", "1.1.0"]


async def test_aikido_adapter_ecosystem_inference():
    """ecosystem is inferred for SCA when Aikido does not provide it."""
    adapter = AikidoAdapter()
    payload = {
        "issue": {
            "id": "789",
            "cve_id": "CVE-2024-8888",
            "type": "vulnerability",
            "severity": "low",
            "component": "python-multipart",
            "installed_version": "0.0.6",
            "code_repo_name": "api",
        },
    }
    result = await adapter.to_vat_finding(payload)
    assert result.ecosystem == "pypi"


async def test_aikido_adapter_container_link_with_container_name_to_id():
    """Container findings with container_repo_name but no container_repo_id get correct Aikido link via container_name_to_id."""
    adapter = AikidoAdapter()
    payload = {
        "issue": {
            "id": "555",
            "group_id": "grp-123",
            "cve_id": "CVE-2024-5555",
            "type": "vulnerability",
            "severity": "high",
            "container_repo_name": "containers/images/etcd",
            "attack_surface": "docker_container",
        },
    }
    container_name_to_id = {
        "containers/images/etcd": "42",
        "containers/images/cert-manager-acmesolver-fips": "99",
    }
    result = await adapter.to_vat_finding(
        payload, container_name_to_id=container_name_to_id
    )
    assert (
        result.source_issue_url
        == "https://app.aikido.dev/containers/42?sidebarIssue=grp-123"
    )


async def test_aikido_adapter_container_link_without_id_falls_back_to_queue():
    """Container findings without container ID fall back to queue URL (no invalid path-based container URL)."""
    adapter = AikidoAdapter()
    payload = {
        "issue": {
            "id": "666",
            "group_id": "grp-456",
            "cve_id": "CVE-2024-6666",
            "type": "vulnerability",
            "severity": "medium",
            "container_repo_name": "containers/images/etcd",
            "attack_surface": "docker_container",
        },
    }
    result = await adapter.to_vat_finding(payload)
    assert (
        result.source_issue_url == "https://app.aikido.dev/queue?sidebarIssue=grp-456"
    )
