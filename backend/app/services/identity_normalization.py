"""Pure identity normalization for CVE, packages, and correlation inputs.

No database, network, or settings reads — see implementation-plan-dedup-correlation-hardening.md §4.3.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.dedup import component_base, normalize


def normalize_cve_id(value: str | None) -> str:
    """Normalize CVE / weakness id string for keys and fingerprints (trim, lowercase)."""
    return normalize(value or "")


@dataclass(frozen=True)
class PackageKey:
    """Normalized package identity fragment (optional enrichment later, e.g. OSV)."""

    ecosystem: str
    name: str

    @classmethod
    def from_component(
        cls, ecosystem: str | None, component: str | None
    ) -> PackageKey | None:
        if not (component or "").strip():
            return None
        eco = normalize(ecosystem or "")
        base = component_base(component or "")
        if not base:
            return None
        return cls(ecosystem=eco, name=base)
