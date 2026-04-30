"""CycloneDX SBOM parser — JSON format with vulnerabilities (1.4+)."""

import logging

from app.schemas.ingest import (
    CanonicalFindingPayload,
    CanonicalFindingType,
    CanonicalSeverity,
)
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
        logger.debug("cyclonedx: purl version parse failed for %r", purl, exc_info=True)
        return ""


def _split_image_ref_tag(value: str) -> tuple[str, str | None, str | None]:
    """Split ``registry/repo:tag@sha256:...`` into (image_without_tag_or_digest, tag, digest).

    Defensive against ports (``host:5000/repo``) — only treats trailing ``:X``
    as a tag when X has no ``/`` after it.
    """
    s = (value or "").strip()
    if not s:
        return "", None, None
    digest: str | None = None
    if "@sha256:" in s:
        s, _, dig = s.partition("@sha256:")
        digest = f"sha256:{dig.strip()}" if dig else None
    tag: str | None = None
    if ":" in s:
        last_slash = s.rfind("/")
        last_colon = s.rfind(":")
        if last_colon > last_slash:
            cand = s[last_colon + 1 :].strip()
            if cand and "/" not in cand:
                tag = cand
                s = s[:last_colon]
    return s.strip(), tag, digest


def _extract_sbom_tag_digest(comp_meta: dict, components: dict) -> tuple[str | None, str | None]:
    """Pull (tag, digest) for the asset described by a CycloneDX SBOM.

    Tries (in order): metadata.component.name suffix, metadata.component.version,
    PURL ``?tag=``/``@sha256:`` on metadata, first component's purl. Defensive
    against varying SBOM emitters (Trivy/Syft/CycloneDX-cli).
    """
    if not isinstance(comp_meta, dict):
        return None, None
    name = (comp_meta.get("name") or "").strip()
    _, name_tag, name_digest = _split_image_ref_tag(name)
    version = (comp_meta.get("version") or "").strip() or None
    purl = (comp_meta.get("purl") or "").strip()
    purl_version = _parse_purl_version(purl) or None
    purl_tag: str | None = None
    if "?" in purl:
        for kv in purl.split("?", 1)[1].split("&"):
            if kv.startswith("tag="):
                purl_tag = kv[4:].strip() or None
                break
    purl_digest: str | None = None
    if "@sha256:" in purl:
        purl_digest = f"sha256:{purl.split('@sha256:', 1)[1].split('?', 1)[0].strip()}"
    tag = name_tag or version or purl_tag or purl_version
    digest = name_digest or purl_digest
    return tag, digest


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

        # Per-image tag/digest from SBOM metadata — wins over scanner-supplied
        # X-VAT-Tag (which carries the bundle release tag, not per-image).
        sbom_tag, sbom_digest = _extract_sbom_tag_digest(comp_meta, components)

        payloads: list[CanonicalFindingPayload] = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            for p in self._vuln_to_payloads(
                v, components, asset, sbom_tag=sbom_tag, sbom_digest=sbom_digest
            ):
                if p:
                    payloads.append(p)
        return payloads

    def _vuln_to_payloads(
        self,
        v: dict,
        components: dict,
        asset: str,
        *,
        sbom_tag: str | None = None,
        sbom_digest: str | None = None,
    ) -> list[CanonicalFindingPayload]:
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
        cve_ids = [
            ref.get("id")
            for ref in (v.get("references") or [])
            if isinstance(ref, dict) and ref.get("id")
        ]
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
            name = (
                comp.get("name") or ref.split("@")[0].split("/")[-1]
                if "@" in ref
                else ref
            )
            version = comp.get("version") or _parse_purl_version(comp.get("purl", ""))
            component = f"{name} {version}".strip()
            if not component:
                component = ref
            fields = {
                "cve_id": str(cve_id),
                "severity": sev,
                "description": str(desc or vuln_id)[:10000],
                "component": component,
                "title": f"{name}:{version} | {vuln_id}",
                "finding_type": CanonicalFindingType.SCA,
                "cvss": cvss,
            }
            if sbom_tag:
                fields["tag"] = sbom_tag
            if sbom_digest:
                fields["image_digest"] = sbom_digest
            payloads.append(self._create_payload(fields, asset=asset))
        if not payloads and vuln_id:
            fields = {
                "cve_id": str(vuln_id),
                "severity": sev,
                "description": str(desc or vuln_id)[:10000],
                "component": vuln_id,
                "title": vuln_id,
                "finding_type": CanonicalFindingType.SCA,
                "cvss": cvss,
            }
            if sbom_tag:
                fields["tag"] = sbom_tag
            if sbom_digest:
                fields["image_digest"] = sbom_digest
            payloads.append(self._create_payload(fields, asset=asset))
        return payloads
