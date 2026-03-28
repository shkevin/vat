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
from app.services.asset_aliases import resolve_canonical_asset_id
from app.services.container_ref_normalization import (
    apply_container_asset_path_aliases,
    normalize_container_ref,
)
from app.services.dedup import component_base, normalize

MIN_SBOM_JACCARD = 0.4
MIN_SHARED_PACKAGES = 2
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
}


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

    pkg_score = _jaccard(source.packages, target.packages)
    shared_packages = source.packages & target.packages
    if pkg_score >= MIN_SBOM_JACCARD and len(shared_packages) >= MIN_SHARED_PACKAGES:
        confidence = "high" if pkg_score >= 0.75 else "medium"
        return (
            "sbom_similarity",
            round(pkg_score, 4),
            confidence,
            {
                "reason": (
                    f"Assets '{source.asset_id}' and '{target.asset_id}' share "
                    f"{len(shared_packages)} SBOM package(s) with Jaccard similarity "
                    f"{round(pkg_score, 4)}."
                ),
                "sourceAssetId": source.asset_id,
                "targetAssetId": target.asset_id,
                "packageJaccard": round(pkg_score, 4),
                "sourcePackageCount": len(source.packages),
                "targetPackageCount": len(target.packages),
                "sharedPackageCount": len(shared_packages),
                "sharedPackages": sorted(shared_packages)[:5],
            },
        )

    source_name = (
        sorted(source.name_tokens, key=len, reverse=True)[0] if source.name_tokens else ""
    )
    target_name = (
        sorted(target.name_tokens, key=len, reverse=True)[0] if target.name_tokens else ""
    )
    name_score = _sequence_similarity(source_name, target_name)
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
