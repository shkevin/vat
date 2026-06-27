"""Asset merge suggestions: evidence from findings + asset_observed_tags."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from app.models.asset_observed_tag import AssetObservedTag
from app.models.finding import Finding, FindingType, Severity, Status
from app.services.asset_merge_suggestions import _load_signature, suggest_asset_merge_targets


def _digest(hex64: str) -> str:
    return f"sha256:{hex64}"


@pytest.fixture
async def _merge_suggestions_cleanup(db):
    prefix = "merge-sug-test-"

    async def _clean():
        await db.execute(
            text("DELETE FROM asset_observed_tags WHERE asset_id LIKE :p").bindparams(
                p=f"{prefix}%"
            )
        )
        await db.execute(text("DELETE FROM findings WHERE id LIKE 'merge-sug-%'"))
        # Aliases would survive a digest/auto-merge and make resolve_canonical_asset_id
        # collapse merge-a/merge-b to one identity, hiding the suggestion. Clean them too.
        await db.execute(
            text(
                "DELETE FROM asset_aliases WHERE source_asset_id LIKE :p "
                "OR canonical_asset_id LIKE :p"
            ).bindparams(p=f"{prefix}%")
        )
        await db.commit()

    await _clean()
    yield
    await _clean()


@pytest.mark.anyio
async def test_load_signature_includes_observed_tag_digest(
    db, _merge_suggestions_cleanup
) -> None:
    aid = "merge-sug-test-docker.io/containers/images/obs"
    d = _digest("a1" * 32)
    db.add(
        Finding(
            id="merge-sug-f1",
            finding_type=FindingType.SCA,
            fingerprint_id="merge-sug-fp-obs-1",
            cve_id="CVE-2024-9001",
            severity=Severity.High,
            status=Status.Open,
            image=aid,
            image_digest=None,
            tag="v1",
            sources=[],
            audit=[],
            external_links=[],
        )
    )
    db.add(
        AssetObservedTag(
            asset_id=aid,
            tag="v1",
            observation_count=1,
            last_digest=d,
        )
    )
    await db.commit()

    sig = await _load_signature(db, aid)
    assert d in sig.digests


@pytest.mark.anyio
async def test_suggest_merge_digest_from_observation_only_on_target(
    db, _merge_suggestions_cleanup
) -> None:
    """Shared digest can come from findings on one asset and observations on the other."""
    d = _digest("b2" * 32)
    aid_a = "merge-sug-test-docker.io/containers/images/merge-a"
    aid_b = "merge-sug-test-docker.io/containers/images/merge-b"

    db.add(
        Finding(
            id="merge-sug-fa",
            finding_type=FindingType.SCA,
            fingerprint_id="merge-sug-fp-a",
            cve_id="CVE-2024-9002",
            severity=Severity.High,
            status=Status.Open,
            image=aid_a,
            image_digest=d,
            tag="t1",
            sources=[],
            audit=[],
            external_links=[],
        )
    )
    db.add(
        Finding(
            id="merge-sug-fb",
            finding_type=FindingType.SCA,
            fingerprint_id="merge-sug-fp-b",
            cve_id="CVE-2024-9003",
            severity=Severity.Medium,
            status=Status.Open,
            image=aid_b,
            image_digest=None,
            tag="t2",
            sources=[],
            audit=[],
            external_links=[],
        )
    )
    db.add(
        AssetObservedTag(
            asset_id=aid_b,
            tag="t2",
            observation_count=1,
            last_digest=d,
        )
    )
    await db.commit()

    out = await suggest_asset_merge_targets(db, aid_a, limit=20)
    strategies = {r["target_asset_id"]: r["strategy"] for r in out}
    assert strategies.get(aid_b) == "digest"


@pytest.mark.anyio
async def test_suggest_merge_skips_same_normalized_container_identity(
    db, _merge_suggestions_cleanup,
) -> None:
    """Registry-prefixed vs path-only keys for the same image are one identity — no self-merge."""
    d = _digest("d4" * 32)
    long_id = "docker.io/containers/images/merge-sug-same-id"
    short_id = "containers/images/merge-sug-same-id"
    for fid, img in [
        ("merge-sug-same-1", long_id),
        ("merge-sug-same-2", short_id),
    ]:
        db.add(
            Finding(
                id=fid,
                finding_type=FindingType.SCA,
                fingerprint_id=f"merge-sug-fp-{fid}",
                cve_id="CVE-2024-9100",
                severity=Severity.High,
                status=Status.Open,
                image=img,
                image_digest=d,
                tag="t1",
                sources=[],
                audit=[],
                external_links=[],
            )
        )
    await db.commit()

    out_long = await suggest_asset_merge_targets(db, long_id, limit=20)
    out_short = await suggest_asset_merge_targets(db, short_id, limit=20)
    targets_long = {r["target_asset_id"] for r in out_long}
    targets_short = {r["target_asset_id"] for r in out_short}
    assert short_id not in targets_long
    assert long_id not in targets_short
