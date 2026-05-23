"""Tests for vulnerability feed normalization helpers."""

from io import BytesIO

import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.services.vuln_feeds import (
    SOURCE_CISA_KEV,
    SOURCE_DEBIAN,
    SOURCE_OSV,
    SOURCE_UBUNTU,
    SOURCE_VULN_FEED_MATCH,
    _apply_feed_curation,
    _checksum_for_feed_records,
    _infer_ecosystem_for_sbom,
    _match_strategy,
    _next_cursor,
    _normalize_debian,
    _normalize_cisa_kev,
    _normalize_osv_results,
    _purl_to_osv_target,
    _severity_from_details,
    _enabled_sources,
    _stream_debian_records_from_json,
    _stream_ubuntu_records_from_json,
    materialize_feed_matches_to_findings,
    prune_feed_storage,
)


def test_normalize_cisa_kev_records():
    payload = {
        "dateReleased": "2026-03-31",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1000",
                "vendorProject": "ExampleVendor",
                "vulnerabilityName": "Example vuln",
                "dateAdded": "2026-03-31",
                "knownRansomwareCampaignUse": "Known",
            }
        ],
    }
    rows = _normalize_cisa_kev(payload)
    assert len(rows) == 1
    assert rows[0]["source"] == SOURCE_CISA_KEV
    assert rows[0]["vulnerability_id"] == "CVE-2026-1000"
    assert rows[0]["record_key"] == "CVE-2026-1000"
    assert rows[0]["severity"] == "CRITICAL"


def test_normalize_osv_querybatch_results():
    payload = [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "version": "2.31.0",
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "aliases": ["CVE-2025-1234"],
                    "summary": "Example summary",
                    "modified": "2026-03-31T00:00:00Z",
                    "published": "2026-03-30T00:00:00Z",
                    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                }
            ],
        }
    ]
    rows = _normalize_osv_results(payload)
    assert len(rows) == 1
    assert rows[0]["source"] == SOURCE_OSV
    assert rows[0]["vulnerability_id"] == "GHSA-xxxx-yyyy-zzzz"
    assert rows[0]["aliases"] == ["CVE-2025-1234"]
    assert "GHSA-xxxx-yyyy-zzzz|requests|PyPI|2.31.0" == rows[0]["record_key"]
    assert rows[0]["severity"] == "CRITICAL"


def test_normalize_debian_package_to_cve_shape():
    payload = {
        "golang-github-xenolf-lego": {
            "CVE-2025-54799": {
                "description": "Let's Encrypt client vulnerability",
                "releases": {
                    "sid": {"status": "open", "urgency": "high"}
                },
            }
        }
    }
    rows = _normalize_debian(payload, limit=20)
    assert len(rows) == 1
    assert rows[0]["source"] == SOURCE_DEBIAN
    assert rows[0]["vulnerability_id"] == "CVE-2025-54799"
    assert rows[0]["package_name"] == "golang-github-xenolf-lego"
    assert rows[0]["record_key"] == "CVE-2025-54799|golang-github-xenolf-lego"
    assert rows[0]["severity"] == "HIGH"
    assert "Let's Encrypt client vulnerability" in (rows[0]["title"] or "")


def test_severity_from_details_falls_back_from_priority_and_cvss():
    assert _severity_from_details({"priority": "medium"}) == "MEDIUM"
    assert _severity_from_details({"cvss3": "9.8"}) == "CRITICAL"
    assert _severity_from_details({"cvss": {"score": 7.2}}) == "HIGH"


def test_apply_feed_curation_filters_age_and_caps():
    settings = get_settings()
    old_window_days = settings.vuln_feed_recent_window_days
    old_window_years = settings.vuln_feed_recent_window_years
    old_max = settings.vuln_feed_max_records_per_source
    old_osv_per_eco = settings.vuln_feed_osv_max_records_per_ecosystem
    try:
        settings.vuln_feed_recent_window_days = 1
        settings.vuln_feed_recent_window_years = 0
        settings.vuln_feed_max_records_per_source = 1
        settings.vuln_feed_osv_max_records_per_ecosystem = 5
        rows = [
            {
                "source": SOURCE_OSV,
                "record_key": "new-critical",
                "severity": "CRITICAL",
                "ecosystem": "PyPI",
                "published_at": None,
                "modified_at": None,
            },
            {
                "source": SOURCE_OSV,
                "record_key": "old-high",
                "severity": "HIGH",
                "ecosystem": "PyPI",
                "published_at": None,
                "modified_at": None,
            },
        ]
        from datetime import datetime, timedelta

        rows[0]["published_at"] = datetime.utcnow()
        rows[1]["published_at"] = datetime.utcnow() - timedelta(days=20)
        curated, stats = _apply_feed_curation(SOURCE_OSV, rows)
        assert len(curated) == 1
        assert curated[0]["record_key"] == "new-critical"
        assert stats["raw_fetched_items"] == 2
        assert stats["filtered_by_age"] == 1
    finally:
        settings.vuln_feed_recent_window_days = old_window_days
        settings.vuln_feed_recent_window_years = old_window_years
        settings.vuln_feed_max_records_per_source = old_max
        settings.vuln_feed_osv_max_records_per_ecosystem = old_osv_per_eco


def test_feed_record_checksum_uses_normalized_records_only():
    records = [
        {
            "source": SOURCE_DEBIAN,
            "record_key": "CVE-2026-1000|openssl",
            "vulnerability_id": "CVE-2026-1000",
            "package_name": "openssl",
        }
    ]

    assert _checksum_for_feed_records(records) == _checksum_for_feed_records(records)


def test_streamed_os_feeds_are_enabled_by_default():
    assert SOURCE_DEBIAN in _enabled_sources()
    assert SOURCE_UBUNTU in _enabled_sources()


def test_stream_debian_records_from_json_file_like():
    payload = b"""
    {
      "openssl": {
        "CVE-2026-1000": {
          "description": "OpenSSL issue",
          "releases": {"sid": {"urgency": "high"}}
        }
      },
      "curl": {
        "CVE-2026-1001": {
          "description": "Curl issue",
          "releases": {"sid": {"urgency": "medium"}}
        }
      }
    }
    """

    rows = _stream_debian_records_from_json(BytesIO(payload), limit=1)

    assert len(rows) == 1
    assert rows[0]["source"] == SOURCE_DEBIAN
    assert rows[0]["record_key"] == "CVE-2026-1000|openssl"
    assert rows[0]["severity"] == "HIGH"


def test_stream_ubuntu_records_from_json_file_like():
    payload = b"""
    {
      "cves": [
        {
          "id": "CVE-2026-2000",
          "description": "Ubuntu issue",
          "priority": "medium",
          "package": "openssl"
        },
        {
          "id": "CVE-2026-2001",
          "description": "Second issue",
          "priority": "low",
          "package": "curl"
        }
      ]
    }
    """

    rows = _stream_ubuntu_records_from_json(BytesIO(payload), limit=1)

    assert len(rows) == 1
    assert rows[0]["source"] == SOURCE_UBUNTU
    assert rows[0]["record_key"] == "CVE-2026-2000"
    assert rows[0]["severity"] == "MEDIUM"


def test_match_strategy_labels_version_and_ecosystem():
    strategy, confidence = _match_strategy(
        sbom_name="requests",
        sbom_version="2.31.0",
        sbom_language="python",
        sbom_purl=None,
        advisory_package="requests",
        advisory_ecosystem="PyPI",
        advisory_version="2.31.0",
    )
    assert strategy == "name+version+ecosystem"
    assert confidence == "high"

    strategy2, confidence2 = _match_strategy(
        sbom_name="requests",
        sbom_version="2.31.0",
        sbom_language="python",
        sbom_purl=None,
        advisory_package="requests",
        advisory_ecosystem="PyPI",
        advisory_version=None,
    )
    assert strategy2 == "name+ecosystem_no_version"
    assert confidence2 == "medium"


def test_match_strategy_downgrades_probe_derived_purl_confidence():
    strategy, confidence = _match_strategy(
        sbom_name="requests",
        sbom_version="2.31.0",
        sbom_language=None,
        sbom_purl="pkg:pypi/requests@2.31.0",
        sbom_purl_source="derived_probe",
        sbom_purl_confidence="medium",
        advisory_package="requests",
        advisory_ecosystem="PyPI",
        advisory_version="2.31.0",
    )
    assert strategy == "name+version+ecosystem+probe"
    assert confidence == "low"


def test_next_cursor_wraps_deterministically():
    assert _next_cursor(0, 10, 100) == 10
    assert _next_cursor(95, 10, 100) == 5


def test_infer_ecosystem_for_sbom_uses_language_and_fallbacks():
    assert (
        _infer_ecosystem_for_sbom(
            name="requests", version="2.31.0", language="python"
        )
        == "PyPI"
    )
    assert (
        _infer_ecosystem_for_sbom(
            name="github.com/hashicorp/go-multierror",
            version="v1.1.1",
            language=None,
        )
        == "Go"
    )
    assert (
        _infer_ecosystem_for_sbom(
            name="ca-certificates-bundle", version="20251003-r4", language=None
        )
        == "Alpine"
    )


def test_purl_to_osv_target_maps_common_types():
    assert _purl_to_osv_target(
        purl="pkg:golang/github.com/go-openapi/jsonpointer@v0.21.0",
        fallback_name="jsonpointer",
    ) == ("github.com/go-openapi/jsonpointer", "Go")
    assert _purl_to_osv_target(
        purl="pkg:apk/alpine/ca-certificates-bundle@20251003-r4",
        fallback_name="ca-certificates-bundle",
    ) == ("ca-certificates-bundle", "Alpine")
    assert _purl_to_osv_target(
        purl="pkg:npm/%40types/node@20.12.7",
        fallback_name="@types/node",
    ) == ("@types/node", "npm")


@pytest.mark.asyncio
async def test_materialize_feed_matches_creates_and_resolves_findings(db):
    await db.execute(text("DELETE FROM findings"))
    await db.execute(text("DELETE FROM vuln_feed_records"))
    await db.execute(text("DELETE FROM sbom_packages"))
    await db.execute(text("DELETE FROM asset_aliases"))
    await db.execute(
        text(
            """
            INSERT INTO sbom_packages
            (id, name, version, component, language, sources, tenant_id, created_at, updated_at)
            VALUES
            ('sbom-mf-1', 'openssl', '3.0.0', 'asset-a', 'python', '[{"name":"manual"}]'::jsonb, NULL, NOW(), NOW())
            """
        )
    )
    await db.execute(
        text(
            """
            INSERT INTO vuln_feed_records
            (source, record_key, vulnerability_id, aliases, package_name, ecosystem, version, severity, title, details, published_at, modified_at, fetched_at, run_id)
            VALUES
            ('osv', 'CVE-2026-7777|openssl|PyPI|3.0.0', 'CVE-2026-7777', '["CVE-2026-7777"]'::jsonb, 'openssl', 'PyPI', '3.0.0', 'HIGH', 'OpenSSL issue', '{}'::jsonb, NULL, NULL, NOW(), NULL)
            """
        )
    )
    await db.commit()

    result = await materialize_feed_matches_to_findings(
        db, trace_id="trace-test-1", actor_id="tester@vat.local"
    )
    assert result["created"] == 1
    assert result["matched"] == 1
    await db.commit()

    finding = (
        await db.execute(
            text(
                "SELECT source, cve_id, severity, status, image, component_base, correlation_confidence, correlation_key "
                "FROM findings WHERE source = :source LIMIT 1"
            ),
            {"source": SOURCE_VULN_FEED_MATCH},
        )
    ).first()
    assert finding is not None
    assert finding.cve_id == "CVE-2026-7777"
    assert finding.status == "Open"
    assert finding.image == "asset-a"
    assert finding.component_base == "openssl"
    assert finding.correlation_confidence == "high"
    assert "name+version+ecosystem" in (finding.correlation_key or "")

    await db.execute(text("DELETE FROM vuln_feed_records"))
    await db.commit()

    result2 = await materialize_feed_matches_to_findings(
        db, trace_id="trace-test-2", actor_id="tester@vat.local"
    )
    assert result2["resolved"] >= 1
    await db.commit()

    status = await db.scalar(
        text("SELECT status FROM findings WHERE source = :source LIMIT 1"),
        {"source": SOURCE_VULN_FEED_MATCH},
    )
    assert status == "Resolved"


@pytest.mark.asyncio
async def test_materialize_skips_low_confidence_by_default(db):
    settings = get_settings()
    prev = settings.vuln_feed_match_include_low_confidence
    settings.vuln_feed_match_include_low_confidence = False
    try:
        await db.execute(text("DELETE FROM findings"))
        await db.execute(text("DELETE FROM vuln_feed_records"))
        await db.execute(text("DELETE FROM sbom_packages"))
        await db.execute(
            text(
                """
                INSERT INTO sbom_packages
                (id, name, version, component, language, sources, tenant_id, created_at, updated_at)
                VALUES
                ('sbom-low-1', 'next', '15.5.10', 'asset-low', 'javascript', '[{"name":"manual"}]'::jsonb, NULL, NOW(), NOW())
                """
            )
        )
        await db.execute(
            text(
                """
                INSERT INTO vuln_feed_records
                (source, record_key, vulnerability_id, aliases, package_name, ecosystem, version, severity, title, details, published_at, modified_at, fetched_at, run_id)
                VALUES
                ('osv', 'GHSA-low|next|npm|', 'GHSA-low', '["GHSA-low"]'::jsonb, 'next', NULL, NULL, 'MEDIUM', 'Versionless advisory', '{}'::jsonb, NULL, NULL, NOW(), NULL),
                ('osv', 'GHSA-high|next|npm|15.5.10', 'GHSA-high', '["GHSA-high"]'::jsonb, 'next', 'npm', '15.5.10', 'HIGH', 'Versioned advisory', '{}'::jsonb, NULL, NULL, NOW(), NULL)
                """
            )
        )
        await db.commit()

        result = await materialize_feed_matches_to_findings(
            db, trace_id="trace-test-low-filter", actor_id="tester@vat.local"
        )
        await db.commit()

        assert result["matched"] == 1
        assert result["created"] == 1
        assert result["excluded_low_confidence"] >= 1

        findings = (
            await db.execute(
                text(
                    "SELECT cve_id, correlation_confidence FROM findings "
                    "WHERE source = :source ORDER BY cve_id"
                ),
                {"source": SOURCE_VULN_FEED_MATCH},
            )
        ).all()
        assert len(findings) == 1
        assert findings[0].cve_id == "GHSA-high"
        assert findings[0].correlation_confidence == "high"
    finally:
        settings.vuln_feed_match_include_low_confidence = prev


@pytest.mark.asyncio
async def test_materialize_feed_matches_honors_package_batch_size(db):
    settings = get_settings()
    prev_batch_size = settings.vuln_feed_materialize_package_batch_size
    settings.vuln_feed_materialize_package_batch_size = 1
    try:
        await db.execute(text("DELETE FROM findings"))
        await db.execute(text("DELETE FROM vuln_feed_records"))
        await db.execute(text("DELETE FROM sbom_packages"))
        await db.execute(text("DELETE FROM asset_aliases"))
        await db.execute(
            text(
                """
                INSERT INTO sbom_packages
                (id, name, version, component, language, sources, tenant_id, created_at, updated_at)
                VALUES
                ('sbom-batch-1', 'openssl', '3.0.0', 'asset-batch-a', 'python', '[{"name":"manual"}]'::jsonb, NULL, NOW(), NOW()),
                ('sbom-batch-2', 'requests', '2.31.0', 'asset-batch-b', 'python', '[{"name":"manual"}]'::jsonb, NULL, NOW(), NOW())
                """
            )
        )
        await db.execute(
            text(
                """
                INSERT INTO vuln_feed_records
                (source, record_key, vulnerability_id, aliases, package_name, ecosystem, version, severity, title, details, published_at, modified_at, fetched_at, run_id)
                VALUES
                ('osv', 'CVE-2026-8881|openssl|PyPI|3.0.0', 'CVE-2026-8881', '["CVE-2026-8881"]'::jsonb, 'openssl', 'PyPI', '3.0.0', 'HIGH', 'OpenSSL issue', '{}'::jsonb, NULL, NULL, NOW(), NULL),
                ('osv', 'CVE-2026-8882|requests|PyPI|2.31.0', 'CVE-2026-8882', '["CVE-2026-8882"]'::jsonb, 'requests', 'PyPI', '2.31.0', 'MEDIUM', 'Requests issue', '{}'::jsonb, NULL, NULL, NOW(), NULL)
                """
            )
        )
        await db.commit()

        result = await materialize_feed_matches_to_findings(
            db, trace_id="trace-test-batch", actor_id="tester@vat.local"
        )
        await db.commit()

        assert result["created"] == 2
        assert result["matched"] == 2
        finding_count = await db.scalar(
            text("SELECT COUNT(*) FROM findings WHERE source = :source"),
            {"source": SOURCE_VULN_FEED_MATCH},
        )
        assert finding_count == 2
    finally:
        settings.vuln_feed_materialize_package_batch_size = prev_batch_size


@pytest.mark.asyncio
async def test_prune_feed_storage_deletes_old_runs_and_records(db):
    settings = get_settings()
    prev_runs = settings.vuln_feed_runs_retention_days
    prev_records = settings.vuln_feed_records_retention_days
    settings.vuln_feed_runs_retention_days = 30
    settings.vuln_feed_records_retention_days = 30
    try:
        await db.execute(text("DELETE FROM vuln_feed_runs"))
        await db.execute(text("DELETE FROM vuln_feed_records"))
        await db.execute(
            text(
                """
                INSERT INTO vuln_feed_runs
                (id, source, status, trace_id, stats, error, started_at, completed_at)
                VALUES
                ('run-old', 'osv', 'completed', NULL, '{}'::jsonb, NULL, NOW() - INTERVAL '45 days', NOW() - INTERVAL '45 days'),
                ('run-new', 'osv', 'completed', NULL, '{}'::jsonb, NULL, NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days')
                """
            )
        )
        await db.execute(
            text(
                """
                INSERT INTO vuln_feed_records
                (source, record_key, vulnerability_id, aliases, package_name, ecosystem, version, severity, title, details, published_at, modified_at, fetched_at, run_id)
                VALUES
                ('osv', 'old-rec', 'CVE-2000-0001', '[]'::jsonb, 'pkg-old', 'npm', '1.0.0', 'LOW', NULL, '{}'::jsonb, NULL, NULL, NOW() - INTERVAL '40 days', NULL),
                ('osv', 'new-rec', 'CVE-2000-0002', '[]'::jsonb, 'pkg-new', 'npm', '1.0.1', 'LOW', NULL, '{}'::jsonb, NULL, NULL, NOW() - INTERVAL '2 days', NULL)
                """
            )
        )
        await db.commit()

        result = await prune_feed_storage(db, trace_id="trace-retain", actor_id="tester@vat.local")
        await db.commit()

        assert result["deleted_runs"] == 1
        assert result["deleted_records"] == 1
        remaining_runs = await db.scalar(text("SELECT COUNT(*) FROM vuln_feed_runs"))
        remaining_records = await db.scalar(
            text("SELECT COUNT(*) FROM vuln_feed_records")
        )
        assert int(remaining_runs or 0) == 1
        assert int(remaining_records or 0) == 1
    finally:
        settings.vuln_feed_runs_retention_days = prev_runs
        settings.vuln_feed_records_retention_days = prev_records
