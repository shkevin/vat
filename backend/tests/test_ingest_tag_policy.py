"""Unit tests for ingest tag policy behavior."""

from app.schemas.vat import VatFindingSchema, VatFindingType, VatSeverity
from app.services.ingest_tag_policy import IngestTagPolicy


def _payload(*, tag: str | None = None) -> VatFindingSchema:
    return VatFindingSchema(
        cve_id="RULE-1",
        severity=VatSeverity.HIGH,
        description="test",
        finding_type=VatFindingType.SECRET,
        title="secret",
        image="vat-codebase",
        tag=tag,
    )


def test_policy_single_asset_is_authoritative() -> None:
    policy = IngestTagPolicy.from_headers(
        asset_override="vat-codebase",
        tag_override="2026-03-30_111855",
    )
    assert policy.force_override is True
    out = policy.apply_to_payload(_payload(tag="legacy-tag"))
    assert out.tag == "2026-03-30_111855"


def test_policy_non_authoritative_fills_only_missing_tags() -> None:
    policy = IngestTagPolicy.from_headers(
        asset_override=None,
        tag_override="header-tag",
    )
    with_tag = policy.apply_to_payload(_payload(tag="parser-tag"))
    no_tag = policy.apply_to_payload(_payload(tag=None))
    assert with_tag.tag == "parser-tag"
    assert no_tag.tag == "header-tag"
