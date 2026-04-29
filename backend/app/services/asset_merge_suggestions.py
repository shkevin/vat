"""Asset merge suggestion engine (non-destructive, review-first).

Digest evidence comes from **findings** and from **asset_observed_tags** (per-tag
``last_digest`` accumulated at ingest), so merge suggestions improve as more
scans record the same image without requiring a registry tag-list API.

Priority strategy:
1) digest match
2) exact image/ref match
3) SBOM similarity
4) name heuristic
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Iterable

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.asset_observed_tag import AssetObservedTag
from app.models.finding import Finding
from app.models.sbom import SbomPackage
from app.services.asset_aliases import (
    record_merge_event,
    repoint_aliases,
    resolve_canonical_asset_id,
    upsert_asset_alias,
)
from app.services.container_ref_normalization import (
    apply_container_asset_path_aliases,
    normalize_container_ref,
)
from app.services.dedup import component_base, normalize

MIN_SBOM_JACCARD = 0.85
MIN_SHARED_PACKAGES = 5
MIN_DISTINCT_SHARED_PACKAGES = 8
MIN_NAME_SIMILARITY = 0.78
GENERIC_NAME_TOKENS = {
    "container",
    "containers",
    "image",
    "images",
    "operator",
    "operators",
    "dev",
    "prod",
    "fips",
    "latest",
    "stable",
    # Registry / org / namespace tokens — these are infrastructure, not
    # product identifiers. Two images sharing only an org segment (e.g.
    # bitnamilegacy/postgresql vs bitnamilegacy/kafka) must not match.
    "bitnami",
    "bitnamilegacy",
    "library",
    "localhost",
    "docker.io",
    "ghcr.io",
    "quay.io",
    "registry-1.docker.io",
    "registry.io",
    "kamiwaza",
    "kamiwaza-internal",
}

# OS / base-image packages that any distro-derived container will share. Two
# Bitnami images built from the same Debian base trivially overlap on these
# even when the products are unrelated, so they're excluded from the shared-
# package count used to score sbom_similarity. The list is broad on purpose
# (false-negative on a real merge is recoverable; false-positive isn't).
_OS_NOISE_PACKAGE_PREFIXES: tuple[str, ...] = (
    "lib",
    "perl-",
    "python3-",
    "python3.",
    "tzdata",
    "ncurses",
    "readline",
    "openssl",
    "ca-certificates",
    "coreutils",
    "util-linux",
    "bash",
    "dash",
    "debconf",
    "debian-archive-keyring",
    "dpkg",
    "apt",
    "adduser",
    "base-",
    "bsdutils",
    "debianutils",
    "diffutils",
    "findutils",
    "gcc-",
    "gpgv",
    "grep",
    "gzip",
    "hostname",
    "init-system-helpers",
    "insserv",
    "login",
    "logsave",
    "lsb-base",
    "mawk",
    "mount",
    "passwd",
    "sed",
    "startpar",
    "sysv-rc",
    "sysvinit-utils",
    "tar",
    "usrmerge",
    "xz-utils",
    "zlib",
    "musl",
    "alpine-baselayout",
    "alpine-keys",
    "apk-tools",
    "busybox",
    "ssl_client",
    "scanelf",
    "ssl-cert",
    "e2fsprogs",
    "tini",
)


def _is_os_noise_package(pkg_key: str) -> bool:
    """True for OS/base-image packages that ship with every distro-built container.

    pkg_key is ``<name>@<version>`` or ``<name>``; we match on the name prefix.
    """
    if not pkg_key:
        return False
    name = pkg_key.split("@", 1)[0]
    if not name:
        return False
    for prefix in _OS_NOISE_PACKAGE_PREFIXES:
        if name == prefix or name.startswith(prefix):
            return True
    return False


@dataclass
class AssetSignature:
    asset_id: str
    digests: set[str]
    refs: set[str]
    packages: set[str]
    cves: set[str]
    name_tokens: set[str]
    finding_count: int


def _norm_text(value: str | None) -> str:
    return normalize(str(value or "").strip())


def _asset_name_tokens(asset_id: str) -> set[str]:
    aid = _norm_text(asset_id)
    if not aid:
        return set()
    parts = [p for p in aid.split("/") if p]
    tokens = set(parts)
    if parts:
        tokens.add(parts[-1])
    # e.g. containers/images/foo -> foo
    if "/images/" in aid:
        tokens.add(aid.split("/images/", 1)[-1])
    return {t for t in tokens if t}


def _normalize_image_ref(value: str | None) -> str:
    ref = _norm_text(value)
    if not ref:
        return ""
    if "@sha256:" in ref:
        ref = ref.split("@sha256:", 1)[0]
    if ":" in ref:
        left, right = ref.rsplit(":", 1)
        if right and "/" not in right:
            ref = left
    return ref


def _package_key(name: str | None, version: str | None) -> str:
    n = _norm_text(name)
    v = _norm_text(version)
    if not n:
        return ""
    return f"{n}@{v}" if v else n


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    if union == 0:
        return 0.0
    return inter / union


def _sequence_similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    return SequenceMatcher(a=left, b=right).ratio()


def _meaningful_name_tokens(value: str) -> set[str]:
    raw = _norm_text(value)
    if not raw:
        return set()
    parts = (
        raw.replace("/", "-")
        .replace("_", "-")
        .replace(".", "-")
        .replace(":", "-")
        .split("-")
    )
    tokens = {p for p in parts if p and p not in GENERIC_NAME_TOKENS}
    return tokens


def _iter_signature_refs(sig: AssetSignature) -> Iterable[str]:
    for r in sig.refs:
        yield r


def _strategy_from_signatures(
    source: AssetSignature, target: AssetSignature
) -> tuple[str, float, str, dict]:
    shared_digests = sorted(source.digests & target.digests)
    if shared_digests:
        digest_preview = ", ".join(shared_digests[:2])
        return (
            "digest",
            1.0,
            "high",
            {
                "reason": (
                    f"Assets '{source.asset_id}' and '{target.asset_id}' share "
                    f"{len(shared_digests)} container digest(s) ({digest_preview})."
                ),
                "sourceAssetId": source.asset_id,
                "targetAssetId": target.asset_id,
                "sharedDigests": shared_digests[:5],
                "sharedDigestCount": len(shared_digests),
            },
        )

    source_refs = {_normalize_image_ref(r) for r in _iter_signature_refs(source)}
    target_refs = {_normalize_image_ref(r) for r in _iter_signature_refs(target)}
    source_refs.discard("")
    target_refs.discard("")
    shared_refs = sorted(source_refs & target_refs)
    if shared_refs:
        ref_preview = ", ".join(shared_refs[:2])
        return (
            "exact_ref",
            0.9,
            "high",
            {
                "reason": (
                    f"Assets '{source.asset_id}' and '{target.asset_id}' share "
                    f"{len(shared_refs)} normalized image reference(s) ({ref_preview})."
                ),
                "sourceAssetId": source.asset_id,
                "targetAssetId": target.asset_id,
                "sharedRefs": shared_refs[:5],
                "sharedRefCount": len(shared_refs),
            },
        )

    # Jaccard score uses ALL packages (so two identical images still hit ~1.0)
    # but the gate also requires enough *distinctive* shared packages — i.e.
    # ones outside the OS/base-image set. Bitnami siblings built from the same
    # Debian base score 0.9+ on Jaccard but share <3 distinctive packages, so
    # they no longer surface as merge suggestions.
    pkg_score = _jaccard(source.packages, target.packages)
    shared_packages = source.packages & target.packages
    distinctive_shared = {p for p in shared_packages if not _is_os_noise_package(p)}
    if (
        pkg_score >= MIN_SBOM_JACCARD
        and len(shared_packages) >= MIN_SHARED_PACKAGES
        and len(distinctive_shared) >= MIN_DISTINCT_SHARED_PACKAGES
    ):
        confidence = "high" if pkg_score >= 0.95 else "medium"
        return (
            "sbom_similarity",
            round(pkg_score, 4),
            confidence,
            {
                "reason": (
                    f"Assets '{source.asset_id}' and '{target.asset_id}' share "
                    f"{len(shared_packages)} SBOM package(s) "
                    f"({len(distinctive_shared)} non-OS) with Jaccard similarity "
                    f"{round(pkg_score, 4)}."
                ),
                "sourceAssetId": source.asset_id,
                "targetAssetId": target.asset_id,
                "packageJaccard": round(pkg_score, 4),
                "sourcePackageCount": len(source.packages),
                "targetPackageCount": len(target.packages),
                "sharedPackageCount": len(shared_packages),
                "distinctiveSharedCount": len(distinctive_shared),
                "sharedPackages": sorted(distinctive_shared)[:5]
                or sorted(shared_packages)[:5],
            },
        )

    # Pick the best matching token pair across both sides — but only over
    # *meaningful* tokens (registry/org segments and generic suffixes are
    # filtered) so multi-segment refs like "localhost/vespaengine/vespa"
    # match "containers/images/vespa" on the shared "vespa" while sibling
    # Bitnami images don't trigger on a shared "bitnamilegacy" org token.
    source_name = ""
    target_name = ""
    name_score = 0.0
    source_meaningful_set = {
        t for t in source.name_tokens if _meaningful_name_tokens(t)
    }
    target_meaningful_set = {
        t for t in target.name_tokens if _meaningful_name_tokens(t)
    }
    if source_meaningful_set and target_meaningful_set:
        for s_tok in source_meaningful_set:
            for t_tok in target_meaningful_set:
                score = _sequence_similarity(s_tok, t_tok)
                if score > name_score:
                    name_score = score
                    source_name = s_tok
                    target_name = t_tok
    source_meaningful = _meaningful_name_tokens(source_name)
    target_meaningful = _meaningful_name_tokens(target_name)
    shared_name_tokens = sorted(source_meaningful & target_meaningful)
    if name_score >= MIN_NAME_SIMILARITY and shared_name_tokens:
        confidence = "medium" if name_score >= 0.75 else "low"
        exact_name_match = source_name == target_name and bool(source_name)
        return (
            "name_heuristic",
            round(name_score, 4),
            confidence,
            {
                "reason": (
                    f"Assets '{source.asset_id}' and '{target.asset_id}' have "
                    f"{'identical' if exact_name_match else 'highly similar'} normalized "
                    f"image names ('{source_name}' vs '{target_name}') with similarity "
                    f"{round(name_score, 4)}."
                ),
                "sourceAssetId": source.asset_id,
                "targetAssetId": target.asset_id,
                "exactNormalizedNameMatch": exact_name_match,
                "nameSimilarity": round(name_score, 4),
                "sourceName": source_name,
                "targetName": target_name,
                "sharedNameTokens": shared_name_tokens[:5],
            },
        )

    return "", 0.0, "low", {}


async def _load_asset_ids(db: AsyncSession) -> list[str]:
    asset_rows = (await db.execute(select(Asset.id))).scalars().all()
    image_rows = (
        await db.execute(select(Finding.image).where(Finding.image.is_not(None)))
    ).scalars().all()

    merged: set[str] = set()
    for r in asset_rows:
        v = str(r).strip()
        if v:
            merged.add(v)
    for r in image_rows:
        v = str(r).strip()
        if v:
            merged.add(v)

    observed_asset_ids = (
        await db.execute(select(AssetObservedTag.asset_id).distinct())
    ).scalars().all()
    for r in observed_asset_ids:
        v = str(r).strip()
        if v:
            merged.add(v)
    return sorted(merged)


async def _load_signature(db: AsyncSession, asset_id: str) -> AssetSignature:
    aid = str(asset_id or "").strip()
    if not aid:
        return AssetSignature(
            asset_id="",
            digests=set(),
            refs=set(),
            packages=set(),
            cves=set(),
            name_tokens=set(),
            finding_count=0,
        )

    findings = (
        await db.execute(
            select(Finding).where(
                or_(
                    Finding.image == aid,
                    Finding.component == aid,
                    Finding.tag == aid,
                )
            )
        )
    ).scalars().all()

    digests = {
        _norm_text(f.image_digest)
        for f in findings
        if _norm_text(f.image_digest).startswith("sha256:")
    }

    observed_rows = (
        await db.execute(
            select(AssetObservedTag).where(AssetObservedTag.asset_id == aid)
        )
    ).scalars().all()
    for row in observed_rows:
        d = _norm_text(row.last_digest)
        if d.startswith("sha256:"):
            digests.add(d)

    refs = {_norm_text(aid), _normalize_image_ref(aid)}
    refs.update(_norm_text(f.image) for f in findings if _norm_text(f.image))
    refs.update(
        _normalize_image_ref(f.image) for f in findings if _normalize_image_ref(f.image)
    )
    for row in observed_rows:
        t = _norm_text(row.tag)
        if t and aid:
            refs.add(_normalize_image_ref(f"{aid}:{t}"))

    packages = set()
    for f in findings:
        p = _package_key(component_base(f.component or ""), None)
        if p:
            packages.add(p)

    cves = {_norm_text(f.cve_id) for f in findings if _norm_text(f.cve_id)}

    # Pull SBOM components linked directly to this asset_id.
    sbom_rows = (
        await db.execute(select(SbomPackage).where(SbomPackage.component == aid))
    ).scalars().all()
    for pkg in sbom_rows:
        p = _package_key(pkg.name, pkg.version)
        if p:
            packages.add(p)

    return AssetSignature(
        asset_id=aid,
        digests=digests,
        refs={r for r in refs if r},
        packages=packages,
        cves=cves,
        name_tokens=_asset_name_tokens(aid),
        finding_count=len(findings),
    )


async def _merge_identity_key(db: AsyncSession, asset_id: str) -> str:
    """Stable key for the same logical container (registry vs path-only, aliases)."""
    aid = str(asset_id or "").strip()
    if not aid:
        return ""
    canon = await resolve_canonical_asset_id(db, aid)
    n = normalize_container_ref(canon)
    return apply_container_asset_path_aliases(n.canonical_asset_key).lower()


async def suggest_asset_merge_targets(
    db: AsyncSession, asset_id: str, *, limit: int = 10
) -> list[dict]:
    source_sig = await _load_signature(db, asset_id)
    if not source_sig.asset_id:
        return []

    source_identity = await _merge_identity_key(db, source_sig.asset_id)

    all_ids = await _load_asset_ids(db)
    candidates = [a for a in all_ids if a != source_sig.asset_id]

    scored: list[dict] = []
    for candidate_id in candidates:
        if await _merge_identity_key(db, candidate_id) == source_identity:
            # Same normalized image as source (e.g. docker.io/foo vs foo path) — not a merge target.
            continue
        target_sig = await _load_signature(db, candidate_id)
        strategy, score, confidence, details = _strategy_from_signatures(
            source_sig, target_sig
        )
        if not strategy:
            continue
        scored.append(
            {
                "source_asset_id": source_sig.asset_id,
                "target_asset_id": target_sig.asset_id,
                "strategy": strategy,
                "score": score,
                "confidence": confidence,
                "requires_review": True,
                "auto_merge_eligible": strategy == "digest" and score >= 1.0,
                "details": details,
            }
        )

    scored = [
        r
        for r in scored
        if r.get("target_asset_id") != r.get("source_asset_id")
    ]
    rank = {"digest": 0, "exact_ref": 1, "sbom_similarity": 2, "name_heuristic": 3}
    scored.sort(key=lambda r: (rank.get(r["strategy"], 99), -float(r["score"]), r["target_asset_id"]))
    return scored[: max(1, int(limit))]


def _canonical_pick(asset_ids: set[str]) -> str:
    """Deterministic canonical asset id within a digest-equivalence cluster.

    Prefer the ``containers/images/<name>`` shape (Aikido-style, registry-stripped)
    so cross-source merges land on the form already used in the report. Tiebreak
    by lexicographic order for stability across runs.
    """
    if not asset_ids:
        return ""
    cleaned = {a for a in asset_ids if a}
    if not cleaned:
        return ""
    aikido_shaped = sorted(a for a in cleaned if a.lower().startswith("containers/images/"))
    if aikido_shaped:
        return aikido_shaped[0]
    return sorted(cleaned)[0]


async def auto_merge_assets_by_digest(
    db: AsyncSession,
    *,
    created_by: str = "system",
) -> dict[str, int]:
    """Auto-apply digest-strategy merges across all assets.

    Two assets sharing a sha256 manifest digest are the same image — there is
    no false-positive risk from a digest collision. Group by digest, pick a
    canonical asset id per group (Aikido-shape preferred), and create
    persistent aliases for the rest. Future ingests will land on the canonical
    automatically via ``resolve_canonical_asset_id``.

    Idempotent: rows already aliased to the canonical are skipped.
    Conservative: only ``digest`` strategy is auto-applied — never
    ``sbom_similarity`` (Bitnami trap) or ``name_heuristic`` (too noisy).

    Returns a small stats dict suitable for logging at the end of an ingest.
    """
    # Build digest -> {asset_ids} index from findings AND observed tags.
    digest_to_assets: dict[str, set[str]] = {}

    finding_rows = (
        await db.execute(
            select(Finding.image, Finding.image_digest).where(
                Finding.image_digest.is_not(None),
                Finding.image.is_not(None),
            )
        )
    ).all()
    for image, digest in finding_rows:
        d = _norm_text(digest)
        a = _norm_text(image)
        if not d.startswith("sha256:") or not a:
            continue
        digest_to_assets.setdefault(d, set()).add(a)

    observed_rows = (
        await db.execute(
            select(AssetObservedTag.asset_id, AssetObservedTag.last_digest).where(
                AssetObservedTag.last_digest.is_not(None)
            )
        )
    ).all()
    for asset_id, digest in observed_rows:
        d = _norm_text(digest)
        a = _norm_text(asset_id)
        if not d.startswith("sha256:") or not a:
            continue
        digest_to_assets.setdefault(d, set()).add(a)

    aliases_created = 0
    findings_repointed = 0
    digests_examined = len(digest_to_assets)
    canonical_assets_visited: set[str] = set()

    for digest, asset_ids in digest_to_assets.items():
        # Resolve each asset id to its current canonical so we don't re-merge
        # already-aliased rows. After resolution we may end up with a single
        # asset id — nothing to merge.
        canonicals: set[str] = set()
        for aid in asset_ids:
            canonicals.add(await resolve_canonical_asset_id(db, aid) or aid)
        if len(canonicals) <= 1:
            continue

        canonical = _canonical_pick(canonicals)
        if not canonical:
            continue
        canonical_assets_visited.add(canonical)

        for source_id in canonicals:
            if source_id == canonical:
                continue
            # Persist alias so future ingests on the source land on canonical.
            await upsert_asset_alias(
                db,
                source_asset_id=source_id,
                canonical_asset_id=canonical,
                created_by=created_by,
            )
            await repoint_aliases(
                db, old_canonical_id=source_id, new_canonical_id=canonical
            )
            aliases_created += 1

            # Rewrite existing findings whose image still points at the source
            # so they show under the canonical asset in the UI.
            existing = (
                await db.execute(
                    select(Finding).where(Finding.image == source_id)
                )
            ).scalars().all()
            for f in existing:
                prev = {"image": f.image}
                f.image = canonical
                findings_repointed += 1
                await record_merge_event(
                    db,
                    source_asset_id=source_id,
                    target_asset_id=canonical,
                    finding_id=f.id,
                    prev_values=prev,
                    next_values={"image": canonical},
                    created_by=created_by,
                )

            # Drop the now-empty source asset row so the assets list stays
            # de-duplicated; future ingests on source_id resolve via alias.
            src_asset = await db.get(Asset, source_id)
            if src_asset is not None:
                await db.delete(src_asset)

    await db.flush()

    return {
        "digests_examined": digests_examined,
        "aliases_created": aliases_created,
        "findings_repointed": findings_repointed,
        "canonical_assets": len(canonical_assets_visited),
    }
