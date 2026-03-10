"""Ingest parsers — transform external formats to canonical."""

from app.parsers.base import IngestParser
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

# Parser registry: parser_id -> Parser class
PARSER_REGISTRY: dict[str, type[IngestParser]] = {
    "sarif": SarifParser,
    "canonical": CanonicalParser,
    "trivy": TrivyParser,
    "snyk": SnykParser,
    "semgrep": SemgrepParser,
    "gitleaks": GitleaksParser,
    "npm_audit": NpmAuditParser,
    "pip_audit": PipAuditParser,
    "grype": GrypeParser,
    "cyclonedx": CyclonedxParser,
    "openscap": OpenSCAPParser,
    "openscap_oval": OpenSCAPOvalParser,
}


def get_parser(parser_id: str) -> IngestParser:
    """Return parser instance by id. Raises ValueError if unknown."""
    parser_id = (parser_id or "").strip().lower()
    if not parser_id:
        raise ValueError("Parser id is required")
    cls = PARSER_REGISTRY.get(parser_id)
    if not cls:
        raise ValueError(f"Unknown parser: {parser_id}. Available: {list(PARSER_REGISTRY.keys())}")
    return cls()


PARSER_DESCRIPTIONS: dict[str, str] = {
    "trivy": "Container, filesystem, SBOM — vulns, secrets, licenses, misconfig",
    "snyk": "Dependency and container vulnerabilities (snyk test --json)",
    "semgrep": "SAST — semgrep scan --json",
    "gitleaks": "Secrets detection in repos",
    "sarif": "SARIF 2.1.0 — any tool that outputs SARIF",
    "canonical": "Direct VAT format pass-through { findings: [...] }",
    "npm_audit": "npm audit --json (Node.js dependencies)",
    "pip_audit": "pip-audit --format json (Python dependencies)",
    "grype": "grype -o json (container, filesystem, SBOM)",
    "cyclonedx": "CycloneDX SBOM with vulnerabilities (Trivy, Syft, etc.)",
    "openscap": "OpenSCAP XCCDF 1.1 XML (oscap xccdf eval, compliance scans)",
    "openscap_oval": "OpenSCAP OVAL Results XML (oscap oval eval, oscap-docker image-cve)",
}


def list_parsers() -> list[dict[str, str]]:
    """Return available parsers for UI dropdown."""
    return [
        {
            "id": pid,
            "name": cls.format_name,
            "label": cls.format_name.replace("_", " ").title(),
            "description": PARSER_DESCRIPTIONS.get(pid, ""),
        }
        for pid, cls in PARSER_REGISTRY.items()
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
    "list_parsers",
    "PARSER_REGISTRY",
]
