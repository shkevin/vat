from app.services.sbom import _resolve_sbom_finding_context


_DIGEST = "sha256:" + "a" * 64


def _sbom_doc() -> dict:
    return {
        "metadata": {
            "component": {
                "name": f"kamiwaza/images/core:release-0.13.5@{_DIGEST}",
                "version": "release-0.13.5",
            }
        }
    }


def test_bundle_sbom_context_prefers_release_tag_and_suppresses_digest() -> None:
    tag, digest = _resolve_sbom_finding_context(
        _sbom_doc(),
        finding_tag="v0.13.5",
        force_finding_tag_override=True,
        suppress_metadata_digest=True,
    )

    assert tag == "v0.13.5"
    assert digest is None


def test_non_bundle_sbom_context_preserves_metadata_tag_and_digest() -> None:
    tag, digest = _resolve_sbom_finding_context(
        _sbom_doc(),
        finding_tag="v0.13.5",
        force_finding_tag_override=True,
        suppress_metadata_digest=False,
    )

    assert tag == "release-0.13.5"
    assert digest == _DIGEST
