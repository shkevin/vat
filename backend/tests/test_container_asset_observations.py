"""Container asset observation helpers."""

from __future__ import annotations

import pytest
from sqlalchemy import delete, func, select

from app.models.asset_observed_tag import AssetObservedTag
from app.services.container_asset_observations import (
    _is_container_image_asset,
    migrate_observations_for_asset_merge,
)


def test_is_container_image_asset_recognizes_vat_paths() -> None:
    assert _is_container_image_asset("docker.io/containers/images/metrics-server")
    assert _is_container_image_asset("docker.io/operators/images/extension-operator")
    assert _is_container_image_asset("containers/images/foo")
    assert _is_container_image_asset("operators/images/bar")
    assert _is_container_image_asset("ghcr.io/acme/app:latest")
    assert _is_container_image_asset("docker.io/library/nginx:latest")
    assert not _is_container_image_asset("")
    assert not _is_container_image_asset("src/github.com/foo")


@pytest.mark.anyio
async def test_migrate_observations_for_asset_merge_moves_and_merges_tags(db) -> None:
    src = "migrate-obs-unit-src"
    tgt = "migrate-obs-unit-tgt"
    await db.execute(
        delete(AssetObservedTag).where(
            AssetObservedTag.asset_id.in_([src, tgt]),
        )
    )
    await db.commit()

    db.add(
        AssetObservedTag(
            asset_id=src,
            tag="latest",
            observation_count=2,
            last_digest=None,
        )
    )
    db.add(
        AssetObservedTag(
            asset_id=tgt,
            tag="release-1",
            observation_count=1,
            last_digest="sha256:aa",
        )
    )
    await db.commit()

    out = await migrate_observations_for_asset_merge(
        db, source_asset_id=src, canonical_target=tgt
    )
    await db.commit()
    assert out["observed_tags_moved"] == 1
    assert out["observed_tags_merged"] == 0

    c1 = await db.scalar(
        select(func.count()).select_from(AssetObservedTag).where(AssetObservedTag.asset_id == src)
    )
    assert c1 == 0
    c_tgt = await db.scalar(
        select(func.count()).select_from(AssetObservedTag).where(AssetObservedTag.asset_id == tgt)
    )
    assert c_tgt == 2

    await db.execute(delete(AssetObservedTag).where(AssetObservedTag.asset_id == tgt))
    await db.commit()


@pytest.mark.anyio
async def test_migrate_observations_for_asset_merge_merges_same_tag(db) -> None:
    from datetime import datetime

    src = "migrate-obs-unit2-src"
    tgt = "migrate-obs-unit2-tgt"
    await db.execute(
        delete(AssetObservedTag).where(AssetObservedTag.asset_id.in_([src, tgt]))
    )
    await db.commit()

    older = datetime(2024, 1, 1)
    newer = datetime(2025, 6, 1)
    db.add(
        AssetObservedTag(
            asset_id=src,
            tag="v1",
            observation_count=3,
            last_digest="sha256:bbb",
            first_seen_at=newer,
            last_seen_at=newer,
        )
    )
    db.add(
        AssetObservedTag(
            asset_id=tgt,
            tag="v1",
            observation_count=1,
            last_digest="sha256:aaa",
            first_seen_at=older,
            last_seen_at=older,
        )
    )
    await db.commit()

    out = await migrate_observations_for_asset_merge(
        db, source_asset_id=src, canonical_target=tgt
    )
    await db.commit()
    assert out["observed_tags_merged"] == 1

    row = (
        await db.execute(select(AssetObservedTag).where(AssetObservedTag.asset_id == tgt))
    ).scalar_one()
    assert int(row.observation_count) == 4
    assert row.last_digest == "sha256:bbb"

    await db.execute(delete(AssetObservedTag).where(AssetObservedTag.asset_id == tgt))
    await db.commit()
