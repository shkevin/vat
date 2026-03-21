"""Typed cross-source correlation key computation."""

from __future__ import annotations

from app.services.dedup import component_base, normalize


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
) -> tuple[str, str]:
    """
    Returns (correlation_key, confidence).
    Confidence:
      - high: robust typed identifiers (SCA/license)
      - medium: rule + path based
      - low: fallback title/id only
    """
    ft = normalize(finding_type or "")
    asset = f"{normalize(image)}|{normalize(branch)}|{normalize(tag)}"
    eco = normalize(ecosystem or "")
    comp = component_base(component or "")
    rid = normalize(rule_id or "")
    fpath = normalize(file_path or "")
    cve = normalize(cve_id or "")

    if ft in ("sca", "license"):
        if comp:
            return f"{ft}:{asset}:{eco}:{comp}:{cve}", "high"
        return f"{ft}:{asset}:{cve}", "medium"
    if ft in ("sast", "iac", "secret"):
        if rid and fpath:
            return f"{ft}:{asset}:{rid}:{fpath}", "medium"
        if rid:
            return f"{ft}:{asset}:{rid}", "low"
        return f"{ft}:{asset}:{cve}", "low"
    return f"other:{asset}:{cve}:{comp}", "low"
