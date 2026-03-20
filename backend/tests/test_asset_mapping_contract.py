"""Deterministic asset mapping and parser identity contract tests."""

import json
from pathlib import Path

from app.parsers import PARSER_IDENTITY_POLICY, PARSER_REGISTRY
from app.schemas.vat import VatFindingSchema
from app.services.asset_resolver import resolve_asset_for_payload
from app.services.correlation import correlation_key_for_payload


def test_parser_identity_contract_covers_all_registered_parsers() -> None:
    missing = sorted(set(PARSER_REGISTRY.keys()) - set(PARSER_IDENTITY_POLICY.keys()))
    assert missing == []


def test_asset_resolver_prefers_explicit_override() -> None:
    payload = VatFindingSchema(cve_id="CVE-1", severity="High", description="x", image="repo/a")
    resolved_payload, resolution = resolve_asset_for_payload(
        payload,
        parser_id="trivy",
        source_id="vat-local-trivy",
        asset_override="repo/override",
    )
    assert resolved_payload.image == "repo/override"
    assert resolution.asset_id == "repo/override"
    assert resolution.confidence == "explicit"
    assert resolution.reason == "explicit_override"


def test_asset_resolver_strict_mode_rejects_missing_identity() -> None:
    payload = VatFindingSchema(
        cve_id="CVE-1",
        severity="High",
        description="x",
        tag="scanner-tag-only",
    )
    try:
        resolve_asset_for_payload(
            payload,
            parser_id="sarif",
            source_id="vat-local-sarif",
            strict_mode=True,
            requires_explicit_asset=True,
        )
        assert False, "Expected strict resolver to reject missing asset identity"
    except ValueError as exc:
        assert "explicit asset required" in str(exc)


def test_typed_correlation_key_for_sca_and_sast() -> None:
    sca_key, sca_conf = correlation_key_for_payload(
        finding_type="sca",
        image="repo/app",
        branch="main",
        tag="scan-1",
        cve_id="CVE-2024-1234",
        component="openssl 3.0.0",
        ecosystem="npm",
    )
    sast_key, sast_conf = correlation_key_for_payload(
        finding_type="sast",
        image="repo/app",
        branch="main",
        tag="scan-1",
        cve_id="RULE-1",
        component="",
        rule_id="semgrep.rule.sql-injection",
        file_path="src/api.py",
    )
    assert sca_key.startswith("sca:")
    assert sca_conf in ("high", "medium")
    assert sast_key.startswith("sast:")
    assert sast_conf in ("medium", "low")


def test_acceptance_matrix_covers_all_supported_parsers() -> None:
    fixture_path = Path(__file__).parent / "fixtures" / "asset_mapping_matrix.json"
    matrix = json.loads(fixture_path.read_text())
    assert sorted(matrix.keys()) == sorted(PARSER_REGISTRY.keys())

