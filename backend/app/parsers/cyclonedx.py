"""CycloneDX SBOM parser — JSON format with vulnerabilities (1.4+)."""

import logging

from app.schemas.ingest import CanonicalFindingPayload, CanonicalFindingType, CanonicalSeverity
from app.parsers.base import IngestParser

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": CanonicalSeverity.CRITICAL,
    "high": CanonicalSeverity.HIGH,
    "medium": CanonicalSeverity.MEDIUM,
    "low": CanonicalSeverity.LOW,
    "info": CanonicalSeverity.INFORMATIONAL,
    "informational": CanonicalSeverity.INFORMATIONAL,
    "none": CanonicalSeverity.INFORMATIONAL,
    "unknown": CanonicalSeverity.INFORMATIONAL,
}


def _severity(s: str | None) -> CanonicalSeverity:
    if not s or s.lower() in ("none", "unknown"):
        return CanonicalSeverity.MEDIUM
    return _SEVERITY_MAP.get((s or "").lower(), CanonicalSeverity.MEDIUM)


def _flatten_components(components: list, out: dict) -> None:
    for c in components or []:
        if not isinstance(c, dict):
            continue
        for sub in c.get("components") or []:
            _flatten_components([sub], out)
        bom_ref = c.get("bom-ref")
        if bom_ref:
            out[bom_ref] = c


def _parse_purl_version(purl: str) -> str:
    """Extract version from purl e.g. pkg:npm/lodash@4.17.21 -> 4.17.21."""
    if not purl or "@" not in purl:
        return ""
    try:
        return purl.split("@")[-1].split("?")[0]
    except Exception:
        return ""


class CyclonedxParser(IngestParser):
    """Parse CycloneDX JSON SBOM with vulnerabilities (spec 1.4+)."""

    format_name = "cyclonedx"

    def parse(self, raw: dict | list) -> list[CanonicalFindingPayload]:
        if isinstance(raw, list):
            raw = {"components": [], "vulnerabilities": []}
        if not isinstance(raw, dict):
            raise ValueError("CycloneDX input must be a JSON object")
        components: dict = {}
        _flatten_components(raw.get("components") or [], components)
        vulns = raw.get("vulnerabilities") or []

        # Asset context: CycloneDX metadata.component.name or first component
        meta = raw.get("metadata") or {}
        comp_meta = meta.get("component") or {}
        asset = (comp_meta.get("name") or "").strip()
        if not asset and components:
            first = next(iter(components.values()), {})
            asset = (first.get("name") or "").strip()
        if not asset:
            return []  # No asset context — ingest validation would fail

        payloads: list[CanonicalFindingPayload] = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            for p in self._vuln_to_payloads(v, components, asset):
                if p:
                    payloads.append(p)
        return payloads

    def _vuln_to_payloads(self, v: dict, components: dict, asset: str) -> list[CanonicalFindingPayload]:
        payloads: list[CanonicalFindingPayload] = []
        vuln_id = v.get("id") or "unknown"
        desc = v.get("description") or ""
        if v.get("detail"):
            desc = f"{desc}\n{v['detail']}".strip()
        ratings = v.get("ratings") or []
        sev = CanonicalSeverity.MEDIUM
        if ratings and isinstance(ratings[0], dict):
            sev = _severity(ratings[0].get("severity"))
        cvss = None
        for r in ratings:
            if isinstance(r, dict) and r.get("method", "").startswith("CVSSv3"):
                cvss = str(r.get("score") or r.get("vector", "").split("/")[-1] or "")
                break
        recommendation = v.get("recommendation") or ""
        if recommendation:
            desc = f"{desc}\nRecommendation: {recommendation}".strip()
        cve_ids = [ref.get("id") for ref in (v.get("references") or []) if isinstance(ref, dict) and ref.get("id")]
        if vuln_id and vuln_id.startswith("CVE-"):
            cve_ids.insert(0, vuln_id)
        cve_id = cve_ids[0] if cve_ids else vuln_id
        for affect in v.get("affects") or []:
            if not isinstance(affect, dict):
                continue
            ref = affect.get("ref")
            if not ref:
                continue
            comp = components.get(ref, {})
            name = comp.get("name") or ref.split("@")[0].split("/")[-1] if "@" in ref else ref
            version = comp.get("version") or _parse_purl_version(comp.get("purl", ""))
            component = f"{name} {version}".strip()
            if not component:
                component = ref
            payloads.append(
                self._create_payload(
                    {
                        "cve_id": str(cve_id),
                        "severity": sev,
                        "description": str(desc or vuln_id)[:10000],
                        "component": component,
                        "title": f"{name}:{version} | {vuln_id}",
                        "finding_type": CanonicalFindingType.SCA,
                        "cvss": cvss,
                    },
                    asset=asset,
                )
            )
        if not payloads and vuln_id:
            payloads.append(
                self._create_payload(
                    {
                        "cve_id": str(vuln_id),
                        "severity": sev,
                        "description": str(desc or vuln_id)[:10000],
                        "component": vuln_id,
                        "title": vuln_id,
                        "finding_type": CanonicalFindingType.SCA,
                        "cvss": cvss,
                    },
                    asset=asset,
                )
            )
        return payloads
