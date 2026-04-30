"""Ingest parsers — transform external formats to canonical.

This module centralizes parser registration and parser-specific capabilities so new
scanner integrations can be added in one place with minimal ingest branching.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

from app.parsers.base import IngestParser

logger = logging.getLogger(__name__)
from app.parsers.canonical import CanonicalParser
from app.parsers.cyclonedx import CyclonedxParser
from app.parsers.gitleaks import GitleaksParser
from app.parsers.grype import GrypeParser
from app.parsers.npm_audit import NpmAuditParser
from app.parsers.openscap import OpenSCAPParser
from app.parsers.openscap_oval import OpenSCAPOvalParser
from app.parsers.pip_audit import PipAuditParser
from app.parsers.sarif import SarifParser
from app.parsers.semgrep import SemgrepParser
from app.parsers.snyk import SnykParser
from app.parsers.trivy import TrivyParser

RawAssetExtractor = Callable[[Any], str | None]


@dataclass(frozen=True)
class ParserDescriptor:
    parser_cls: type[IngestParser]
    description: str
    input_kinds: tuple[str, ...] = ("json",)
    requires_explicit_asset: bool = False
    supports_deterministic_derived_asset: bool = True
    strong_fields: tuple[str, ...] = ()
    extract_asset_hint: RawAssetExtractor | None = None


def _extract_trivy_asset(raw: Any) -> str | None:
    if not isinstance(raw, dict):
        return None
    results = raw.get("Results") or raw.get("results") or []
    if results and isinstance(results[0], dict):
        return (
            results[0].get("Target") or results[0].get("target") or ""
        ).strip() or None
    return None


def _extract_grype_asset(raw: Any) -> str | None:
    if not isinstance(raw, dict):
        return None
    src = raw.get("source") or {}
    if not isinstance(src, dict):
        return None
    t = src.get("target")
    if isinstance(t, dict):
        return (t.get("userInput") or t.get("target") or "").strip() or None
    return str(t or "").strip() or None


def _extract_gitleaks_asset(raw: Any) -> str | None:
    if not isinstance(raw, dict):
        return None
    return (raw.get("target") or raw.get("asset") or "").strip() or None


def _extract_openscap_asset(raw: Any) -> str | None:
    if not isinstance(raw, bytes):
        return None
    try:
        from defusedxml import ElementTree

        root = ElementTree.fromstring(raw)
        for ns in (
            "{http://checklists.nist.gov/xccdf/1.1}",
            "{http://checklists.nist.gov/xccdf/1.2}",
        ):
            tr = root.find(f".//{ns}TestResult")
            if tr is None:
                continue
            t = tr.find(f"{ns}target")
            if t is not None and t.text:
                return t.text.strip() or None
            for addr in tr.findall(f"{ns}target-address"):
                if addr.text:
                    return addr.text.strip() or None
    except Exception:
        logger.debug("openscap: asset extraction failed", exc_info=True)
        return None
    return None


def _extract_openscap_oval_asset(raw: Any) -> str | None:
    if not isinstance(raw, bytes):
        return None
    try:
        from defusedxml import ElementTree

        root = ElementTree.fromstring(raw)
        for el in root.iter():
            tag = (el.tag or "").split("}")[-1]
            if tag == "hostname":
                text = "".join(el.itertext()).strip()
                if text:
                    return text
    except Exception:
        logger.debug("openscap_oval: asset extraction failed", exc_info=True)
        return None
    return None


PARSER_DESCRIPTORS: dict[str, ParserDescriptor] = {
    "sarif": ParserDescriptor(
        parser_cls=SarifParser,
        description="SARIF 2.1.0 — any tool that outputs SARIF",
        strong_fields=("locations[].physicalLocation.artifactLocation.uri",),
    ),
    "canonical": ParserDescriptor(
        parser_cls=CanonicalParser,
        description="Direct VAT format pass-through { findings: [...] }",
        strong_fields=("image|branch|tag",),
    ),
    "trivy": ParserDescriptor(
        parser_cls=TrivyParser,
        description="Container, filesystem, SBOM — vulns, secrets, licenses, misconfig",
        strong_fields=("Results[].Target", "_vat_source_image"),
        extract_asset_hint=_extract_trivy_asset,
    ),
    "snyk": ParserDescriptor(
        parser_cls=SnykParser,
        description="Dependency and container vulnerabilities (snyk test --json)",
        strong_fields=("targetFile", "projectName"),
    ),
    "semgrep": ParserDescriptor(
        parser_cls=SemgrepParser,
        description="SAST — semgrep scan --json",
        strong_fields=("result.path",),
    ),
    "gitleaks": ParserDescriptor(
        parser_cls=GitleaksParser,
        description="Secrets detection in repos",
        strong_fields=("target", "findings[].File"),
        extract_asset_hint=_extract_gitleaks_asset,
    ),
    "npm_audit": ParserDescriptor(
        parser_cls=NpmAuditParser,
        description="npm audit --json (Node.js dependencies)",
        strong_fields=("vulnerabilities[].nodes", "advisories[].findings.paths"),
    ),
    "pip_audit": ParserDescriptor(
        parser_cls=PipAuditParser,
        description="pip-audit --format json (Python dependencies)",
        strong_fields=("dependencies[].name",),
    ),
    "grype": ParserDescriptor(
        parser_cls=GrypeParser,
        description="grype -o json (container, filesystem, SBOM)",
        strong_fields=("source.target.userInput", "source.target"),
        extract_asset_hint=_extract_grype_asset,
    ),
    "cyclonedx": ParserDescriptor(
        parser_cls=CyclonedxParser,
        description="CycloneDX SBOM with vulnerabilities (Trivy, Syft, etc.)",
        strong_fields=("metadata.component", "components[].properties"),
    ),
    "openscap": ParserDescriptor(
        parser_cls=OpenSCAPParser,
        description="OpenSCAP XCCDF 1.1 XML (oscap xccdf eval, compliance scans)",
        input_kinds=("json", "xml"),
        strong_fields=("TestResult.target", "TestResult.target-address"),
        extract_asset_hint=_extract_openscap_asset,
    ),
    "openscap_oval": ParserDescriptor(
        parser_cls=OpenSCAPOvalParser,
        description="OpenSCAP OVAL Results XML (oscap oval eval, oscap-docker image-cve)",
        input_kinds=("json", "xml"),
        strong_fields=("oval_results.results.system.hostname",),
        extract_asset_hint=_extract_openscap_oval_asset,
    ),
}

# Compatibility exports during migration to descriptor-first architecture.
PARSER_REGISTRY: dict[str, type[IngestParser]] = {
    pid: d.parser_cls for pid, d in PARSER_DESCRIPTORS.items()
}
PARSER_IDENTITY_POLICY: dict[str, dict[str, object]] = {
    pid: {
        "requires_explicit_asset": d.requires_explicit_asset,
        "supports_deterministic_derived_asset": d.supports_deterministic_derived_asset,
        "strong_fields": list(d.strong_fields),
    }
    for pid, d in PARSER_DESCRIPTORS.items()
}


def get_parser(parser_id: str) -> IngestParser:
    """Return parser instance by id. Raises ValueError if unknown."""
    parser_id = (parser_id or "").strip().lower()
    if not parser_id:
        raise ValueError("Parser id is required")
    desc = PARSER_DESCRIPTORS.get(parser_id)
    if not desc:
        raise ValueError(
            f"Unknown parser: {parser_id}. Available: {list(PARSER_DESCRIPTORS.keys())}"
        )
    return desc.parser_cls()


def get_parser_descriptor(parser_id: str) -> ParserDescriptor:
    parser_id = (parser_id or "").strip().lower()
    if not parser_id:
        raise ValueError("Parser id is required")
    desc = PARSER_DESCRIPTORS.get(parser_id)
    if desc is None:
        raise ValueError(
            f"Unknown parser: {parser_id}. Available: {list(PARSER_DESCRIPTORS.keys())}"
        )
    return desc


def parser_accepts_input_kind(parser_id: str, kind: str) -> bool:
    desc = get_parser_descriptor(parser_id)
    return str(kind).strip().lower() in set(desc.input_kinds)


def extract_asset_hint(parser_id: str, raw: Any) -> str | None:
    desc = get_parser_descriptor(parser_id)
    if desc.extract_asset_hint is None:
        return None
    return desc.extract_asset_hint(raw)


def list_parsers() -> list[dict[str, str]]:
    """Return available parsers for UI dropdown."""
    return [
        {
            "id": pid,
            "name": desc.parser_cls.format_name,
            "label": desc.parser_cls.format_name.replace("_", " ").title(),
            "description": desc.description,
        }
        for pid, desc in PARSER_DESCRIPTORS.items()
    ]


__all__ = [
    "IngestParser",
    "SarifParser",
    "CanonicalParser",
    "TrivyParser",
    "SnykParser",
    "SemgrepParser",
    "GitleaksParser",
    "NpmAuditParser",
    "PipAuditParser",
    "GrypeParser",
    "CyclonedxParser",
    "OpenSCAPParser",
    "OpenSCAPOvalParser",
    "get_parser",
    "get_parser_descriptor",
    "parser_accepts_input_kind",
    "extract_asset_hint",
    "list_parsers",
    "PARSER_REGISTRY",
    "PARSER_DESCRIPTORS",
    "ParserDescriptor",
    "PARSER_IDENTITY_POLICY",
]
