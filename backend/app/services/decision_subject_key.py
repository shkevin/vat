"""Decision Subject Key (DSK) — durable identity for triage decisions.

DSKs survive finding UUID changes, asset delete/re-import, and fingerprint
override. They are tenant-scoped and use canonical asset normalization
(provided by the caller via ``correlation_asset_image_for_ingest`` or
``resolve_canonical_asset_id``).

DSKs intentionally differ from ``correlation_key``:
- Include tenant scope
- Never include image digest (decisions outlive tag/digest churn)
- Add OpenSCAP and source-issue alias candidates
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.tenancy import normalize_tenant_id
from app.services.dedup import component_base, normalize
from app.services.identity_normalization import normalize_cve_id
from app.services.openscap_identity import normalize_profile_scope
from app.services.sca_cross_scanner import (
    effective_sca_ecosystem,
    normalize_sca_package_for_cross_scanner,
)

DECISION_KEY_VERSION = "decision:v1"


@dataclass(frozen=True)
class DecisionSubjectCandidate:
    """One lookup key for the decision ledger, with match metadata."""

    subject_key: str
    confidence: str  # high | medium | low
    kind: str  # primary | source_issue | openscap


def _tenant_segment(tenant_id: str | None) -> str:
    return normalize_tenant_id(tenant_id)


def _asset_segment(image: str, branch: str, tag: str, *, drop_tag: bool = False) -> str:
    if drop_tag:
        return f"{normalize(image)}|{normalize(branch)}"
    return f"{normalize(image)}|{normalize(branch)}|{normalize(tag)}"


def _wrap_key(tenant_id: str | None, inner: str) -> str:
    return f"{DECISION_KEY_VERSION}:{_tenant_segment(tenant_id)}:{inner}"


def _primary_inner_key(
    *,
    finding_type: str,
    canonical_asset: str,
    branch: str,
    tag: str,
    cve_id: str,
    component: str,
    ecosystem: str | None = None,
    rule_id: str | None = None,
    file_path: str | None = None,
    sast_partial_fingerprint_hash: str | None = None,
    benchmark_family: str | None = None,
    license_expression: str | None = None,
    stable_rule_key: str | None = None,
    profile_scope: str | None = None,
) -> tuple[str, str]:
    """Return (inner_key, confidence) for the primary DSK candidate."""
    ft = normalize(finding_type or "")
    asset = _asset_segment(canonical_asset, branch, tag)
    comp_raw = component_base(component or "")
    eco = ""
    if ft in ("sca", "license"):
        eco = effective_sca_ecosystem(
            ecosystem,
            benchmark_family,
            image=canonical_asset,
            tag=tag,
        )
        comp = normalize_sca_package_for_cross_scanner(comp_raw) if comp_raw else ""
    else:
        eco = normalize(ecosystem or "")
        comp = comp_raw
    rid = normalize(rule_id or "")
    fpath = normalize(file_path or "")
    cve = normalize_cve_id(cve_id or "")

    stable = normalize(stable_rule_key or "")
    if stable:
        family = normalize(benchmark_family or "unknown_benchmark")
        profile = normalize_profile_scope(profile_scope)
        return f"openscap:{asset}:{stable}:{family}:{profile}", "high"

    if ft == "license":
        license_asset = _asset_segment(canonical_asset, branch, tag, drop_tag=True)
        spdx = normalize(license_expression or "")
        if spdx and comp:
            return f"license:{license_asset}:{spdx}:{comp}", "high"
        if spdx:
            return f"license:{license_asset}:{spdx}", "medium"
        if comp:
            return f"license:{license_asset}::{comp}", "medium"
        return f"license:{license_asset}:{cve}", "low"

    if ft == "sca":
        if comp:
            return f"sca:{asset}:{eco}:{comp}:{cve}", "high"
        return f"sca:{asset}:{cve}", "medium"

    if ft in ("sast", "iac", "secret"):
        if rid and fpath:
            if sast_partial_fingerprint_hash and str(sast_partial_fingerprint_hash).strip():
                fp = normalize(str(sast_partial_fingerprint_hash).strip())
                return f"{ft}:{asset}:{rid}:{fpath}:fp:{fp}", "high"
            return f"{ft}:{asset}:{rid}:{fpath}", "medium"
        if rid:
            return f"{ft}:{asset}:{rid}", "low"
        return f"{ft}:{asset}:{cve}", "low"

    return f"other:{asset}:{cve}:{comp}", "low"


def decision_subject_keys_for_payload(
    *,
    tenant_id: str | None,
    finding_type: str,
    canonical_asset: str,
    branch: str = "",
    tag: str = "",
    cve_id: str,
    component: str = "",
    ecosystem: str | None = None,
    rule_id: str | None = None,
    file_path: str | None = None,
    sast_partial_fingerprint_hash: str | None = None,
    benchmark_family: str | None = None,
    license_expression: str | None = None,
    stable_rule_key: str | None = None,
    profile_scope: str | None = None,
    source_name: str | None = None,
    source_issue_id: str | None = None,
) -> list[DecisionSubjectCandidate]:
    """
    Ordered DSK candidates for ingest-time lookup. First match wins.

    Callers must pass ``canonical_asset`` already resolved through
    ``correlation_asset_image_for_ingest`` / ``resolve_canonical_asset_id``.
    """
    inner, conf = _primary_inner_key(
        finding_type=finding_type,
        canonical_asset=canonical_asset,
        branch=branch,
        tag=tag,
        cve_id=cve_id,
        component=component,
        ecosystem=ecosystem,
        rule_id=rule_id,
        file_path=file_path,
        sast_partial_fingerprint_hash=sast_partial_fingerprint_hash,
        benchmark_family=benchmark_family,
        license_expression=license_expression,
        stable_rule_key=stable_rule_key,
        profile_scope=profile_scope,
    )
    candidates: list[DecisionSubjectCandidate] = [
        DecisionSubjectCandidate(
            subject_key=_wrap_key(tenant_id, inner),
            confidence=conf,
            kind="primary",
        )
    ]

    stable = normalize(stable_rule_key or "")
    if stable and not inner.startswith("openscap:"):
        family = normalize(benchmark_family or "unknown_benchmark")
        profile = normalize_profile_scope(profile_scope)
        asset = _asset_segment(canonical_asset, branch, tag)
        openscap_inner = f"openscap:{asset}:{stable}:{family}:{profile}"
        candidates.append(
            DecisionSubjectCandidate(
                subject_key=_wrap_key(tenant_id, openscap_inner),
                confidence="high",
                kind="openscap",
            )
        )

    sid = str(source_issue_id or "").strip()
    src = normalize(source_name or "")
    if sid and src:
        scope = _asset_segment(canonical_asset, branch, tag)
        alias_inner = f"source:{src}:{sid}:{scope}"
        candidates.append(
            DecisionSubjectCandidate(
                subject_key=_wrap_key(tenant_id, alias_inner),
                confidence="high",
                kind="source_issue",
            )
        )

    return candidates


def decision_subject_keys_for_finding(
    finding: object,
    *,
    canonical_asset: str,
    source_name: str | None = None,
    source_issue_id: str | None = None,
    sast_partial_fingerprint_hash: str | None = None,
    license_expression: str | None = None,
) -> list[DecisionSubjectCandidate]:
    """Build DSK candidates from a persisted Finding ORM instance."""
    ft = getattr(getattr(finding, "finding_type", None), "value", None) or str(
        getattr(finding, "finding_type", "") or ""
    )
    tenant_id = getattr(finding, "tenant_id", None)
    return decision_subject_keys_for_payload(
        tenant_id=tenant_id,
        finding_type=ft,
        canonical_asset=canonical_asset,
        branch=getattr(finding, "branch", None) or "",
        tag=getattr(finding, "tag", None) or "",
        cve_id=getattr(finding, "cve_id", None) or "",
        component=(getattr(finding, "component", None) or "")
        or (getattr(finding, "component_base", None) or ""),
        ecosystem=getattr(finding, "ecosystem", None),
        rule_id=getattr(finding, "rule_id", None),
        file_path=getattr(finding, "file_path", None),
        sast_partial_fingerprint_hash=sast_partial_fingerprint_hash,
        benchmark_family=getattr(finding, "benchmark_family", None),
        license_expression=license_expression
        or getattr(finding, "license_expression", None),
        stable_rule_key=getattr(finding, "stable_rule_key", None),
        profile_scope=getattr(finding, "profile_scope", None),
        source_name=source_name,
        source_issue_id=source_issue_id,
    )
