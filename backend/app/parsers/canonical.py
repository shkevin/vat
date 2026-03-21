"""Canonical parser — direct VAT format pass-through."""

from app.schemas.ingest import CanonicalFindingPayload, CanonicalIngestRequest
from app.parsers.base import IngestParser


class CanonicalParser(IngestParser):
    """Parse direct VAT format { findings: [...] }. Validates and passes through."""

    format_name = "canonical"

    def parse(self, raw: dict) -> list[CanonicalFindingPayload]:
        if not isinstance(raw, dict):
            raise ValueError("Canonical input must be a JSON object")
        findings = raw.get("findings")
        if not isinstance(findings, list):
            raise ValueError("Canonical input must have 'findings' array")
        try:
            req = CanonicalIngestRequest(
                findings=findings, source=raw.get("source", "api")
            )
        except Exception as e:
            raise ValueError(f"Invalid canonical findings: {e}") from e
        return [f for f in req.findings]
