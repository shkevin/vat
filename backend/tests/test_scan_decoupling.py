"""Phase 5 proof: vuln freshness is decoupled from image scanning.

The event-driven plan drops the blind 24h image re-scans on the premise that new
CVEs against an *unchanged* image are surfaced by the hourly SBOM<->feed re-match,
not by re-pulling/re-scanning the image. This asserts exactly that: a new feed CVE
produces a finding on an already-stored SBOM while the SBOM row itself is untouched.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from app.services.vuln_feeds import (
    SOURCE_VULN_FEED_MATCH,
    materialize_feed_matches_to_findings,
)


@pytest.mark.integration_db
@pytest.mark.asyncio
async def test_new_feed_cve_surfaces_on_existing_sbom_without_rescan(db):
    await db.execute(text("DELETE FROM findings"))
    await db.execute(text("DELETE FROM vuln_feed_records"))
    await db.execute(text("DELETE FROM sbom_packages"))
    await db.execute(text("DELETE FROM asset_aliases"))
    # An already-scanned image: its SBOM is stored, frozen well in the past.
    await db.execute(
        text(
            """
            INSERT INTO sbom_packages
            (id, name, version, component, language, sources, tenant_id, created_at, updated_at)
            VALUES
            ('sbom-decouple-1', 'openssl', '3.0.0', 'asset-decouple', 'python',
             '[{"name":"manual"}]'::jsonb, NULL, '2026-01-01 00:00:00', '2026-01-01 00:00:00')
            """
        )
    )
    await db.commit()
    before = await db.scalar(
        text("SELECT updated_at FROM sbom_packages WHERE id = 'sbom-decouple-1'")
    )

    # A NEW CVE lands in the feed store (the hourly refresh) — no scan happens.
    await db.execute(
        text(
            """
            INSERT INTO vuln_feed_records
            (source, record_key, vulnerability_id, aliases, package_name, ecosystem, version,
             severity, title, details, published_at, modified_at, fetched_at, run_id)
            VALUES
            ('osv', 'CVE-2026-9999|openssl|PyPI|3.0.0', 'CVE-2026-9999', '["CVE-2026-9999"]'::jsonb,
             'openssl', 'PyPI', '3.0.0', 'HIGH', 'New OpenSSL CVE', '{}'::jsonb, NULL, NULL, NOW(), NULL)
            """
        )
    )
    await db.commit()

    result = await materialize_feed_matches_to_findings(
        db, trace_id="trace-decouple", actor_id="tester@vat.local"
    )
    await db.commit()

    # The CVE surfaced as a finding...
    assert result["created"] == 1
    finding = (
        await db.execute(
            text(
                "SELECT cve_id, image, status FROM findings WHERE source = :s LIMIT 1"
            ),
            {"s": SOURCE_VULN_FEED_MATCH},
        )
    ).first()
    assert finding is not None and finding.cve_id == "CVE-2026-9999"
    assert finding.image == "asset-decouple"

    # ...and the SBOM was never re-written: no image pull/scan was involved.
    after = await db.scalar(
        text("SELECT updated_at FROM sbom_packages WHERE id = 'sbom-decouple-1'")
    )
    assert after == before, "SBOM row changed — a re-scan happened; coupling not broken"

    await db.execute(text("DELETE FROM findings"))
    await db.execute(text("DELETE FROM vuln_feed_records"))
    await db.execute(text("DELETE FROM sbom_packages"))
    await db.commit()
