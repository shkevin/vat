"""Pure-unit tests for asset merge suggestion scoring and noise filtering.

These exercise ``_strategy_from_signatures`` and ``_is_os_noise_package``
directly so they run without a database — covering the cases that motivated
the recent fixes (vespa-class name match, Bitnami false-positive avoidance).
"""

from __future__ import annotations

from app.services.asset_merge_suggestions import (
    AssetSignature,
    _is_os_noise_package,
    _strategy_from_signatures,
)


def _sig(
    asset_id: str,
    *,
    digests: set[str] | None = None,
    refs: set[str] | None = None,
    packages: set[str] | None = None,
    name_tokens: set[str] | None = None,
) -> AssetSignature:
    return AssetSignature(
        asset_id=asset_id,
        digests=digests or set(),
        refs=refs or {asset_id},
        packages=packages or set(),
        cves=set(),
        name_tokens=name_tokens or {asset_id.split("/")[-1]},
        finding_count=0,
    )


def test_name_heuristic_picks_best_token_pair_not_longest() -> None:
    """vespa↔vespa across scanners: offline carries extra tokens but the
    shared 'vespa' must still match."""
    src = _sig(
        "localhost/vespaengine/vespa",
        name_tokens={"vespaengine", "vespa", "localhost"},
    )
    tgt = _sig("containers/images/vespa", name_tokens={"vespa", "containers", "images"})
    strategy, score, conf, details = _strategy_from_signatures(src, tgt)
    assert strategy == "name_heuristic"
    assert score >= 0.95
    assert "vespa" in details.get("sharedNameTokens", [])


def test_sbom_similarity_blocks_bitnami_false_positive() -> None:
    """bitnamilegacy/postgresql vs bitnamilegacy/kafka share Debian base
    packages but no distinctive non-OS overlap. Must NOT register as a
    duplicate."""
    debian_base = {
        "bash@5.2",
        "coreutils@9.1",
        "libc6@2.36",
        "openssl@3.0.11",
        "ca-certificates@20230311",
        "tzdata@2024a",
        "perl-base@5.36",
        "ncurses-base@6.4",
    }
    src = _sig(
        "bitnamilegacy/postgresql",
        packages=debian_base | {"postgresql@15.4"},
    )
    tgt = _sig(
        "bitnamilegacy/kafka",
        packages=debian_base | {"kafka@3.6.1"},
    )
    strategy, _, _, _ = _strategy_from_signatures(src, tgt)
    assert strategy != "sbom_similarity"


def test_sbom_similarity_still_fires_when_distinctive_overlap_exists() -> None:
    """Same product on two scanners (same component+version pkgs) should
    still surface as a high-confidence merge — Jaccard ≥0.85 with several
    distinctive non-OS packages shared."""
    common_app_packages = {
        f"my-pkg-{i}@1.0" for i in range(20)
    }  # 20 distinctive shared packages → Jaccard 20/22 ≈ 0.91
    src = _sig(
        "src-host/proj-a",
        packages=common_app_packages | {"unique-src@1"},
        name_tokens={"src-host", "proj-a"},
    )
    tgt = _sig(
        "tgt-host/proj-b",
        packages=common_app_packages | {"unique-tgt@1"},
        name_tokens={"tgt-host", "proj-b"},
    )
    strategy, score, _, _ = _strategy_from_signatures(src, tgt)
    assert strategy == "sbom_similarity"
    assert score >= 0.85


def test_digest_match_wins_over_other_strategies() -> None:
    digest = "sha256:" + "a" * 64
    src = _sig("foo", digests={digest}, packages={"x@1"})
    tgt = _sig("bar", digests={digest}, packages={"x@1"})
    strategy, score, conf, _ = _strategy_from_signatures(src, tgt)
    assert strategy == "digest"
    assert score == 1.0
    assert conf == "high"


def test_name_heuristic_matches_product_suffix_variants() -> None:
    """postgresql ↔ postgres, redis-cli ↔ redis: prefix-overlap on tokens
    ≥6 chars surfaces a suggestion even without an exact shared token."""
    src = _sig(
        "bitnamilegacy/postgresql",
        name_tokens={"bitnamilegacy", "postgresql"},
    )
    tgt = _sig(
        "containers/images/postgres",
        name_tokens={"containers", "images", "postgres"},
    )
    strategy, score, _, details = _strategy_from_signatures(src, tgt)
    assert strategy == "name_heuristic"
    assert score >= 0.85
    assert "postgres" in details.get("sharedNameTokens", [])


def test_name_heuristic_does_not_match_short_prefix_collisions() -> None:
    """kubectl (7) vs kube (4): too short to safely treat as suffix variants.
    The min-6-char gate must prevent this from firing."""
    src = _sig("kubectl", name_tokens={"kubectl"})
    tgt = _sig("kube", name_tokens={"kube"})
    strategy, _, _, _ = _strategy_from_signatures(src, tgt)
    assert strategy != "name_heuristic"


def test_name_heuristic_does_not_match_on_shared_org_token() -> None:
    """bitnamilegacy/postgresql vs bitnamilegacy/kafka share only the
    bitnamilegacy org token. Best-match picker must skip generic/registry
    tokens so this doesn't fire."""
    src = _sig("bitnamilegacy/postgresql", name_tokens={"bitnamilegacy", "postgresql"})
    tgt = _sig("bitnamilegacy/kafka", name_tokens={"bitnamilegacy", "kafka"})
    strategy, _, _, _ = _strategy_from_signatures(src, tgt)
    assert strategy != "name_heuristic"


def test_sbom_similarity_blocks_bitnami_with_only_distro_packages() -> None:
    """Real bitnami siblings carry only Debian-base packages — every
    "distinctive" Debian infrastructure package (bsdutils, debianutils,
    gcc-12-base, insserv, startpar, sysv-rc, usrmerge) must be filtered
    so identical-OS-only Jaccard collisions don't surface as merges."""
    distro_only = {
        "bash@5.2",
        "coreutils@9.1",
        "libc6@2.36",
        "openssl@3.0.11",
        "ca-certificates@20230311",
        "tzdata@2024a",
        "perl-base@5.36",
        "bsdutils@1.0",
        "debianutils@5.7",
        "gcc-12-base@12.2",
        "insserv@1.21",
        "startpar@0.64",
        "sysv-rc@2.96",
        "usrmerge@35",
        "xz-utils@5.4",
    }
    src = _sig(
        "bitnamilegacy/kafka",
        packages=distro_only,
        name_tokens={"bitnamilegacy", "kafka"},
    )
    tgt = _sig(
        "bitnamilegacy/os-shell",
        packages=distro_only,
        name_tokens={"bitnamilegacy", "os-shell", "os", "shell"},
    )
    strategy, _, _, _ = _strategy_from_signatures(src, tgt)
    assert strategy == "", f"expected no merge, got {strategy!r}"


async def test_auto_merge_respects_same_kind_guard() -> None:
    """Auto-merger must not collapse a package-type asset (e.g.
    kamiwaza-bundle) into a container-type asset (containers/images/neo4j)
    just because they share an inherited digest. Regression for an
    incident that destroyed the bundle asset and orphaned trivy/semgrep
    bundle-root findings on the live cluster.
    """
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock

    from app.models.asset import Asset
    from app.services.asset_merge_suggestions import auto_merge_assets_by_digest

    digest = "sha256:" + "a" * 64
    bundle = Asset(id="kamiwaza-bundle", name="kamiwaza-bundle", type="package", source="cyclonedx")
    container = Asset(
        id="containers/images/neo4j", name="containers/images/neo4j", type="container", source="Aikido"
    )

    # Mock session: get(Asset, id) returns one of the two; finding/observed
    # rows produce the digest-collision; select(Finding image=...) returns []
    # (no rewrite needed for this test) and aliases tables are empty.
    async def execute(stmt):
        # Distinguish stmts by returning canned data based on the column
        # signature inspected via str(); simpler: return based on call order.
        result = MagicMock()
        text = str(stmt)
        if "image_digest" in text and "image" in text and "FROM findings" in text:
            result.all = MagicMock(
                return_value=[
                    ("kamiwaza-bundle", digest),
                    ("containers/images/neo4j", digest),
                ]
            )
        elif "asset_observed_tags" in text or "AssetObservedTag" in text:
            result.all = MagicMock(return_value=[])
        else:
            scalars = MagicMock()
            scalars.all = MagicMock(return_value=[])
            result.scalars = MagicMock(return_value=scalars)
        return result

    async def get(model, key):
        if model is Asset:
            return {"kamiwaza-bundle": bundle, "containers/images/neo4j": container}.get(key)
        return None  # AssetAlias lookups return None — no aliases yet

    session = SimpleNamespace(
        execute=AsyncMock(side_effect=execute),
        get=AsyncMock(side_effect=get),
        add=MagicMock(),
        delete=AsyncMock(),
        flush=AsyncMock(),
    )

    stats = await auto_merge_assets_by_digest(session, created_by="test")
    # Must NOT have created any aliases or rewrites — different kinds.
    assert stats["aliases_created"] == 0, stats
    assert stats["findings_repointed"] == 0, stats


def test_canonical_pick_prefers_aikido_shape() -> None:
    """Within a digest cluster the canonical id should be the
    containers/images/<name> form (Aikido convention), not whatever sorts
    first lexicographically."""
    from app.services.asset_merge_suggestions import _canonical_pick

    assert (
        _canonical_pick({"localhost/vespaengine/vespa", "containers/images/vespa"})
        == "containers/images/vespa"
    )
    assert (
        _canonical_pick({"docker.io/foo", "bar/baz"}) == "bar/baz"
    )  # neither is aikido-shape — lex order


def test_is_os_noise_package_classifies_distro_basics() -> None:
    for pkg in [
        "bash@5.2",
        "coreutils@9.1",
        "libc6@2.36",
        "libssl3@3.0.11",
        "openssl@3.0.11",
        "ca-certificates@1.0",
        "tzdata@2024a",
        "ncurses@6.4",
        "perl-base@5.36",
        "musl@1.2",
        "busybox@1.36",
        "alpine-baselayout@3.4",
    ]:
        assert _is_os_noise_package(pkg), pkg

    for pkg in [
        "postgresql@15.4",
        "kafka@3.6.1",
        "redis-server@7.0",
        "neo4j@5.26",
        "milvus@2.5",
        "vespa@8.0",
    ]:
        assert not _is_os_noise_package(pkg), pkg
