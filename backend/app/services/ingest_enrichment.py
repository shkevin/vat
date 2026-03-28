"""Backend-owned enrichment pass for ingest payloads."""

from __future__ import annotations

import re
from typing import Any

from app.schemas.vat import VatFindingSchema
from app.services.openscap_identity import (
    extract_content_version,
    normalize_benchmark_family,
    stable_rule_key,
)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _norm_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def enrich_payload_for_correlation(
    payload: VatFindingSchema, *, parser_id: str, source_id: str
) -> VatFindingSchema:
    updates: dict[str, Any] = {}
    provided: dict[str, str] = {}
    derived: dict[str, str] = {}

    cve_id = _norm_str(getattr(payload, "cve_id", None))
    if cve_id and _CVE_RE.match(cve_id):
        updates["cve_id"] = cve_id.upper()
        provided["cve_id"] = cve_id.upper()

    for field in ("rule_id", "control_ref", "stable_rule_key"):
        value = _norm_str(getattr(payload, field, None))
        if value:
            provided[field] = value

    if parser_id in {"openscap", "openscap_oval"}:
        if not _norm_str(getattr(payload, "stable_rule_key", None)):
            refs = [str(r) for r in (getattr(payload, "references", None) or []) if r]
            derived_key = stable_rule_key(
                rule_id=getattr(payload, "rule_id", None),
                cve_id=getattr(payload, "cve_id", None),
                reference_tokens=refs,
            )
            if derived_key:
                updates["stable_rule_key"] = derived_key
                derived["stable_rule_key"] = derived_key

        bench_id = _norm_str(getattr(payload, "benchmark_id", None))
        if bench_id and not _norm_str(getattr(payload, "benchmark_family", None)):
            family, needs_manual = normalize_benchmark_family(bench_id)
            updates["benchmark_family"] = family
            updates["needs_family_classification"] = bool(needs_manual)
            derived["benchmark_family"] = family
        if bench_id and not _norm_str(getattr(payload, "content_version", None)):
            content_version = extract_content_version(bench_id)
            if content_version:
                updates["content_version"] = content_version
                derived["content_version"] = content_version

    if provided:
        updates["provided_identifiers"] = {
            **(getattr(payload, "provided_identifiers", None) or {}),
            **provided,
        }
    if derived:
        updates["derived_identifiers"] = {
            **(getattr(payload, "derived_identifiers", None) or {}),
            **derived,
        }
    if provided or derived:
        updates["enrichment_meta"] = {
            **(getattr(payload, "enrichment_meta", None) or {}),
            "backend_enriched": True,
            "parser_id": parser_id,
            "source_id": source_id,
        }

    if not updates:
        return payload
    return payload.model_copy(update=updates, deep=True)

