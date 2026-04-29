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
