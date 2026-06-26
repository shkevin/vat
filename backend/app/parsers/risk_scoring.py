"""Parser helpers for structured risk scoring metadata."""

from __future__ import annotations

from typing import Any


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _title_severity(value: Any) -> str | None:
    text = _clean(value)
    return text[:1].upper() + text[1:].lower() if text else None


def cvss_version_from_vector(vector: str | None) -> str | None:
    if not vector:
        return None
    prefix = "CVSS:"
    if not vector.startswith(prefix):
        return None
    version = vector[len(prefix) :].split("/", 1)[0].strip()
    return version or None


def fixed_version_text(value: Any) -> str | None:
    if isinstance(value, list):
        parts = [_clean(v) for v in value]
        return ", ".join(p for p in parts if p) or None
    return _clean(value)


def fix_available(fixed_version: str | None, *, recommendation: str | None = None) -> bool:
    fixed = (fixed_version or "").strip().lower()
    if fixed and fixed not in ("none", "n/a", "not fixed", "no fix"):
        return True
    rec = (recommendation or "").strip().lower()
    if "no fixed version" in rec or "no fix" in rec:
        return False
    return False


def build_source_risk_scoring(
    *,
    source: str,
    score: Any = None,
    vector: str | None = None,
    cvss_version: str | None = None,
    severity: Any = None,
    scanner_title: str | None = None,
    fixed_version: Any = None,
    recommendation: str | None = None,
) -> dict | None:
    source_block: dict[str, Any] = {"source": source}
    version = cvss_version or cvss_version_from_vector(vector)
    fixed_text = fixed_version_text(fixed_version)
    for key, value in (
        ("cvssVersion", version),
        ("vector", vector),
        ("score", _clean(score)),
        ("severity", _title_severity(severity)),
        ("scannerTitle", scanner_title),
        ("fixedVersion", fixed_text),
    ):
        if value not in (None, "", {}, []):
            source_block[key] = value
    if len(source_block) == 1:
        return None
    return {
        "source": source_block,
        "context": {"fixAvailable": fix_available(fixed_text, recommendation=recommendation)},
    }
