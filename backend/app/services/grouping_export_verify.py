"""
Read-only verification of VAT export / API findings against grouping rules.

Used by scripts/verify_grouping_vat_export.py and tests. Does not connect to DB.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.models.finding import FindingType
from app.services.assets_service import _asset_key_from_dict
from app.services.grouping import get_finding_group_key


class _FindingStub:
    """Minimal attribute surface for get_finding_group_key."""

    __slots__ = (
        "id",
        "image",
        "branch",
        "tag",
        "component",
        "component_base",
        "cve_id",
        "title",
        "finding_type",
        "ecosystem",
        "benchmark_family",
        "rule_id",
        "cwe_id",
        "secret_type",
    )

    def __init__(self, **kwargs: Any) -> None:
        for name in self.__slots__:
            setattr(self, name, kwargs.get(name))


_FT_MAP = {
    "SCA": FindingType.SCA,
    "SAST": FindingType.SAST,
    "IaC": FindingType.IaC,
    "Secret": FindingType.Secret,
    "License": FindingType.License,
}


def api_row_to_stub(row: dict[str, Any]) -> _FindingStub:
    """Map camelCase API finding dict to stub for get_finding_group_key."""
    ft_raw = (row.get("findingType") or "SCA").strip()
    ft = _FT_MAP.get(ft_raw, FindingType.SCA)
    return _FindingStub(
        id=row.get("id"),
        image=row.get("image"),
        branch=row.get("branch"),
        tag=row.get("tag"),
        component=row.get("component"),
        component_base=row.get("componentBase"),
        cve_id=row.get("cveId"),
        title=row.get("title"),
        finding_type=ft,
        ecosystem=row.get("ecosystem"),
        benchmark_family=row.get("benchmarkFamily"),
        rule_id=row.get("ruleId"),
        cwe_id=row.get("cweId"),
        secret_type=row.get("secretType"),
    )


def verify_findings_export(
    findings: list[dict[str, Any]],
    *,
    report_multi_suffix: bool = True,
) -> tuple[list[str], list[dict[str, Any]]]:
    """
    Returns (errors, multi_suffix_reports).

    errors: human-readable lines for rows where recomputed groupKey != API groupKey.
    multi_suffix_reports: one entry per (list_asset_bucket, group_prefix) with >1 distinct suffix
    (informational; common when container tag differs, e.g. latest vs pinned).
    """
    errors: list[str] = []
    by_bucket_prefix: dict[tuple[str, str], set[str]] = defaultdict(set)

    for row in findings:
        if not isinstance(row, dict):
            continue
        fid = row.get("id") or "?"
        api_gk = (row.get("groupKey") or "").strip()
        stub = api_row_to_stub(row)
        try:
            expected = get_finding_group_key(stub)  # type: ignore[arg-type]
        except Exception as e:
            errors.append(f"{fid}: recomputation raised {e!r}")
            continue
        if expected != api_gk:
            errors.append(
                f"{fid}: groupKey mismatch api={api_gk!r} recomputed={expected!r}"
            )

        if report_multi_suffix and api_gk and "#" in api_gk:
            prefix, suffix = api_gk.rsplit("#", 1)
            bucket = _asset_key_from_dict(row)
            by_bucket_prefix[(bucket, prefix)].add(suffix)

    multi_reports: list[dict[str, Any]] = []
    if report_multi_suffix:
        for (bucket, prefix), sufs in by_bucket_prefix.items():
            if len(sufs) <= 1:
                continue
            multi_reports.append(
                {
                    "listAssetBucket": bucket,
                    "groupPrefix": prefix,
                    "suffixCount": len(sufs),
                    "suffixes": sorted(sufs),
                }
            )
        multi_reports.sort(key=lambda r: (-r["suffixCount"], r["listAssetBucket"]))

    return errors, multi_reports
