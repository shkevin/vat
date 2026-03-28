"""Fingerprint strategies for ingest — replaces branching in ingest_finding.

Precedence matches implementation-plan-dedup-correlation-hardening.md §4.6,
with OpenSCAP branch ordered before source_issue_id to preserve legacy behavior.
"""

from __future__ import annotations

import hashlib
from typing import Protocol, runtime_checkable

from app.schemas.vat import VatFindingSchema, VatFindingType
from app.services.dedup import make_fingerprint, make_fingerprint_for_source_issue, normalize
from app.services.openscap_identity import make_openscap_fingerprint
from app.services.sarif_fingerprints import resolve_partial_fingerprints


def _fingerprint_material_sha256(material: str) -> str:
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@runtime_checkable
class FingerprintStrategy(Protocol):
    """Compute replay-dedup fingerprint from canonical payload."""

    def compute_fingerprint(
        self, payload: VatFindingSchema, source_name: str
    ) -> str: ...


class OpenSCAPFingerprintStrategy:
    """Phase 1 OpenSCAP identity (result_state excluded from key)."""

    def compute_fingerprint(
        self, payload: VatFindingSchema, source_name: str
    ) -> str:
        image = payload.image or ""
        branch = getattr(payload, "branch", None) or ""
        tag = getattr(payload, "tag", None) or ""
        component = payload.component or payload.component_base or ""
        asset_for_identity = image or component or tag
        return make_openscap_fingerprint(
            canonical_asset_id=asset_for_identity,
            stable_rule_key_value=str(payload.stable_rule_key),
            benchmark_family=str(
                payload.benchmark_family or payload.benchmark_id or "unknown_benchmark"
            ),
            profile_scope=getattr(payload, "profile_scope", None),
        )


class DefaultFingerprintStrategy:
    """
    Default fingerprint chain (legacy-compatible ordering):

    1. OpenSCAP — when source is openscap and stable_rule_key + asset present
       (handled by resolver calling OpenSCAPFingerprintStrategy first).
    2. source_issue_id — 1:1 vendor mapping
    3. partial_fingerprints — SARIF §4.5 resolved hash
    4. scanner_identity — opaque tool stable id
    5. Static fallback — SAST/IaC/Secret rule + path + line + snippet
    6. CVE + component + asset + source_name — SCA and general
    """

    def compute_fingerprint(
        self, payload: VatFindingSchema, source_name: str
    ) -> str:
        sid = getattr(payload, "source_issue_id", None)
        if sid and str(sid).strip():
            image = payload.image or ""
            branch = getattr(payload, "branch", None) or ""
            tag = getattr(payload, "tag", None) or ""
            return make_fingerprint_for_source_issue(
                source_name,
                str(sid).strip(),
                image=image,
                branch=branch,
                tag=tag,
            )

        pfp_raw = getattr(payload, "partial_fingerprints", None)
        if isinstance(pfp_raw, dict) and pfp_raw:
            digest, _branch = resolve_partial_fingerprints(
                {str(k): str(v) for k, v in pfp_raw.items()}
            )
            if digest:
                return _fingerprint_material_sha256(
                    f"vat:sarif:pfp:{digest}:{normalize(source_name)}"
                )

        scanner_identity = getattr(payload, "scanner_identity", None)
        if scanner_identity and str(scanner_identity).strip():
            return _fingerprint_material_sha256(
                f"vat:scanner_id:{normalize(str(scanner_identity).strip())}:"
                f"{normalize(source_name)}"
            )

        ft = payload.finding_type
        if ft in (
            VatFindingType.SAST,
            VatFindingType.IAC,
            VatFindingType.SECRET,
        ):
            rule = normalize(getattr(payload, "rule_id", None) or payload.cve_id or "")
            path = normalize(getattr(payload, "file_path", None) or "")
            line = getattr(payload, "line", None)
            line_s = str(int(line)) if line is not None else ""
            snip = normalize(getattr(payload, "snippet_masked", None) or "")
            return _fingerprint_material_sha256(
                f"vat:static:{rule}|{path}|{line_s}|{snip}|{normalize(source_name)}"
            )

        cve_id = payload.cve_id
        component = payload.component or payload.component_base or ""
        image = payload.image or ""
        branch = getattr(payload, "branch", None) or ""
        tag = getattr(payload, "tag", None) or ""
        return make_fingerprint(
            cve_id,
            component,
            image=image,
            branch=branch,
            tag=tag,
            source_name=source_name,
        )


def resolve_fingerprint_strategy(
    source_name: str, parser_id: str | None
) -> FingerprintStrategy:
    """
    Select strategy for the default chain (after OpenSCAP-with-stable-key branch in
    ``compute_ingest_fingerprint``). Extend with ``parser_id`` when a parser needs a custom chain.
    """
    _ = source_name, parser_id  # reserved for registry
    return DefaultFingerprintStrategy()


def compute_ingest_fingerprint(
    payload: VatFindingSchema,
    source_name: str,
    *,
    parser_id: str | None = None,
) -> str:
    """
    Full fingerprint selection including OpenSCAP-first branch (preserves ingest.py order).

    Legacy order: OpenSCAP wins when stable_rule_key + asset, else DefaultFingerprintStrategy
    (which starts with source_issue_id).
    """
    image = payload.image or ""
    branch = getattr(payload, "branch", None) or ""
    tag = getattr(payload, "tag", None) or ""
    component = payload.component or payload.component_base or ""

    if (
        source_name in ("openscap", "openscap_oval")
        and getattr(payload, "stable_rule_key", None)
        and (image or component or tag)
    ):
        return OpenSCAPFingerprintStrategy().compute_fingerprint(
            payload, source_name
        )

    return resolve_fingerprint_strategy(source_name, parser_id).compute_fingerprint(
        payload, source_name
    )
