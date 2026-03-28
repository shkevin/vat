"""Typed cross-source correlation key computation."""

from __future__ import annotations

from app.services.dedup import component_base, normalize
from app.services.identity_normalization import normalize_cve_id
from app.services.sca_cross_scanner import (
    effective_sca_ecosystem,
    normalize_sca_package_for_cross_scanner,
)

CORRELATION_KEY_VERSION = "v1"


def correlation_key_for_payload(
    *,
    finding_type: str,
    image: str,
    branch: str,
    tag: str,
    cve_id: str,
    component: str,
    ecosystem: str | None = None,
    rule_id: str | None = None,
    file_path: str | None = None,
    sast_partial_fingerprint_hash: str | None = None,
    image_digest: str | None = None,
    include_digest_in_correlation: bool = False,
    benchmark_family: str | None = None,
) -> tuple[str, str]:
    """
    Returns (correlation_key, confidence).
    Keys are prefixed with ``v1:`` (see implementation-plan-dedup-correlation-hardening.md §4.4).

    Confidence:
      - high: robust typed identifiers (SCA/license)
      - medium: rule + path based
      - low: fallback title/id only
    """
    ft = normalize(finding_type or "")
    asset = f"{normalize(image)}|{normalize(branch)}|{normalize(tag)}"
    eco = ""
    comp_raw = component_base(component or "")
    if ft in ("sca", "license"):
        eco = effective_sca_ecosystem(
            ecosystem,
            benchmark_family,
            image=image,
            tag=tag,
        )
        comp = normalize_sca_package_for_cross_scanner(comp_raw) if comp_raw else ""
    else:
        eco = normalize(ecosystem or "")
        comp = comp_raw
    rid = normalize(rule_id or "")
    fpath = normalize(file_path or "")
    cve = normalize_cve_id(cve_id or "")

    inner: str
    conf: str

    if ft in ("sca", "license"):
        if comp:
            inner = f"{ft}:{asset}:{eco}:{comp}:{cve}"
            conf = "high"
        else:
            inner = f"{ft}:{asset}:{cve}"
            conf = "medium"
        if include_digest_in_correlation:
            dig = normalize(image_digest or "")
            if dig:
                inner = f"{inner}:digest:{dig}"
    elif ft in ("sast", "iac", "secret"):
        if rid and fpath:
            if (
                sast_partial_fingerprint_hash
                and str(sast_partial_fingerprint_hash).strip()
            ):
                fp = normalize(str(sast_partial_fingerprint_hash).strip())
                inner = f"{ft}:{asset}:{rid}:{fpath}:fp:{fp}"
            else:
                inner = f"{ft}:{asset}:{rid}:{fpath}"
            conf = "medium"
        elif rid:
            inner = f"{ft}:{asset}:{rid}"
            conf = "low"
        else:
            inner = f"{ft}:{asset}:{cve}"
            conf = "low"
    else:
        inner = f"other:{asset}:{cve}:{comp}"
        conf = "low"

    key = f"{CORRELATION_KEY_VERSION}:{inner}"
    return key, conf
