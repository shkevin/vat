"""OpenSCAP identity normalization helpers (Phase 1)."""

from __future__ import annotations

import hashlib
import re

from app.services.dedup import normalize

# Bootstrap mapping table: distributor/datastream naming -> benchmark family.
_BENCHMARK_FAMILY_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"ssg[-_]?rhel[-_]?8", re.IGNORECASE), "RHEL_8_STIG"),
    (re.compile(r"ssg[-_]?rhel[-_]?9", re.IGNORECASE), "RHEL_9_STIG"),
    (re.compile(r"u[_-]?rhel[_-]?8[_-]?stig", re.IGNORECASE), "RHEL_8_STIG"),
    (re.compile(r"u[_-]?rhel[_-]?9[_-]?stig", re.IGNORECASE), "RHEL_9_STIG"),
    (re.compile(r"windows[_-]?10.*stig", re.IGNORECASE), "WINDOWS_10_STIG"),
)

_SV_WITH_REV_RE = re.compile(r"^(SV-\d+)r\d+(_rule)$", re.IGNORECASE)
_VULN_ID_RE = re.compile(r"\bV-\d+\b", re.IGNORECASE)
_SV_ID_RE = re.compile(r"\bSV-\d+(?:r\d+)?_rule\b", re.IGNORECASE)


def normalize_profile_scope(profile_scope: str | None) -> str:
    """Profile scope is identity-significant for compliance findings."""
    return normalize(profile_scope or "")


def extract_content_version(value: str | None) -> str | None:
    """Extract STIG style content version (e.g. V1R14) from benchmark identifiers."""
    text = str(value or "").strip()
    if not text:
        return None
    m = re.search(r"\bV(\d+)R(\d+)\b", text, re.IGNORECASE)
    if not m:
        return None
    return f"V{m.group(1)}R{m.group(2)}"


def normalize_benchmark_family(benchmark_id: str | None) -> tuple[str, bool]:
    """
    Normalize benchmark id to a family.

    Returns (family, needs_family_classification). If no mapping is found,
    family falls back to normalized benchmark_id.
    """
    raw = str(benchmark_id or "").strip()
    norm = normalize(raw)
    if not norm:
        return "unknown_benchmark", True
    for pattern, family in _BENCHMARK_FAMILY_PATTERNS:
        if pattern.search(raw):
            return family, False
    return norm, True


def _strip_sv_revision(rule_id: str) -> str:
    """
    Normalize version-stamped DISA Rule-ID:
    SV-230294r627750_rule -> SV-230294_rule
    """
    m = _SV_WITH_REV_RE.match(rule_id)
    if m:
        return f"{m.group(1)}{m.group(2)}"
    return rule_id


def stable_rule_key(
    *,
    rule_id: str | None,
    cve_id: str | None = None,
    reference_tokens: list[str] | None = None,
) -> str:
    """
    Stable rule key precedence:
    1) Vuln-ID (V-...) when available
    2) Rule-ID (SV-... normalized by stripping revision suffix)
    3) normalized rule_id
    4) normalized cve_id fallback
    """
    refs = " ".join(reference_tokens or [])
    v_match = _VULN_ID_RE.search(refs)
    if v_match:
        return v_match.group(0).upper()

    sv_match = _SV_ID_RE.search(refs)
    if sv_match:
        return _strip_sv_revision(sv_match.group(0).upper())

    rid = normalize(rule_id or "")
    if rid:
        # Preserve canonical DISA style if present.
        upper = (rule_id or "").strip().upper()
        if upper.startswith("SV-"):
            return _strip_sv_revision(upper)
        if upper.startswith("V-"):
            return upper
        return rid

    return normalize(cve_id or "") or "unknown_rule"


def make_openscap_fingerprint(
    *,
    canonical_asset_id: str,
    stable_rule_key_value: str,
    benchmark_family: str,
    profile_scope: str | None,
) -> str:
    """Deterministic Phase 1 identity key for OpenSCAP findings."""
    asset = normalize(canonical_asset_id)
    rule = normalize(stable_rule_key_value)
    family = normalize(benchmark_family)
    profile = normalize_profile_scope(profile_scope)
    payload = f"openscap|{asset}|{rule}|{family}|{profile}"
    return hashlib.sha256(payload.encode()).hexdigest()

