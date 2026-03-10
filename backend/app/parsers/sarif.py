"""SARIF 2.1.0 parser — OASIS Static Analysis Results Interchange Format."""

import logging
from typing import Any

from app.schemas.ingest import CanonicalFindingPayload, CanonicalFindingType, CanonicalSeverity
from app.parsers.base import IngestParser
from app.parsers.utils import normalize_snippet

logger = logging.getLogger(__name__)


class SarifParser(IngestParser):
    """Parse SARIF 2.1.0 to canonical format."""

    format_name = "sarif"

    SUPPORTED_VERSIONS = ("2.1.0", "2.1.0-errata01", "2.1.0-errata01-csd01")

    def parse(self, raw: dict) -> list[CanonicalFindingPayload]:
        if not isinstance(raw, dict):
            raise ValueError("SARIF input must be a JSON object")
        schema = str(raw.get("$schema", ""))
        if "sarif" not in schema.lower():
            raise ValueError("Invalid SARIF: missing or invalid $schema")
        version = raw.get("version", "")
        if version not in self.SUPPORTED_VERSIONS:
            raise ValueError(f"Unsupported SARIF version: {version}")

        payloads: list[CanonicalFindingPayload] = []
        runs = raw.get("runs") or []

        for run in runs:
            tool_name = self._tool_name(run)
            results = run.get("results") or []
            rules = self._index_rules(run.get("tool", {}).get("driver", {}).get("rules") or [])

            for result in results:
                try:
                    payload = self._result_to_payload(result, rules, tool_name)
                    if payload:
                        payloads.append(payload)
                except (KeyError, TypeError, ValueError) as e:
                    logger.debug("Skipping malformed SARIF result: %s", e)
                    continue

        return payloads

    def _result_to_payload(
        self, result: dict, rules: dict[str, dict], tool_name: str
    ) -> CanonicalFindingPayload | None:
        rule_id = result.get("ruleId") or result.get("rule", {}).get("id") or "unknown"
        rule_index = result.get("ruleIndex")
        rule_def = rules.get(rule_id) or (rules.get(str(rule_index)) if rule_index is not None else {})

        message = self._get_message(result)
        if not message and rule_def:
            message = (
                rule_def.get("fullDescription", {}).get("text")
                or rule_def.get("shortDescription", {}).get("text")
                or rule_def.get("help", {}).get("text")
                or rule_id
            )
        message = message or rule_id

        level = self._map_level(result.get("level"), rule_def.get("defaultConfiguration", {}))
        loc = (result.get("locations") or [{}])[0]
        phys = loc.get("physicalLocation", {})
        artifact_loc = phys.get("artifactLocation", {})
        artifact_uri = artifact_loc.get("uri", "")
        region = phys.get("region", {})
        props = result.get("properties") or {}

        component = props.get("packageName") or props.get("PackageName")
        version = props.get("installedVersion") or props.get("InstalledVersion")
        if component and version:
            component = f"{component} {version}"
        elif component:
            component = str(component)

        asset = artifact_uri or None
        if not asset:
            return None
        # SARIF region.snippet: { "text": "..." } or { "rendered": { "text": "..." } }
        snippet_raw = None
        snip = region.get("snippet") or {}
        if isinstance(snip, dict):
            snippet_raw = snip.get("text") or (snip.get("rendered") or {}).get("text")
        snippet_masked = normalize_snippet(snippet_raw) if snippet_raw else None
        return self._create_payload(
            {
                "cve_id": rule_id,
                "severity": level,
                "description": message,
                "component": component or None,
                "file_path": artifact_uri or None,
                "line": region.get("startLine"),
                "title": props.get("title") or rule_def.get("shortDescription", {}).get("text") or rule_id,
                "cvss": str(props.get("security-severity")) if props.get("security-severity") is not None else None,
                "snippet_masked": snippet_masked,
            },
            asset=asset,
        )

    def _map_level(self, level: str | None, default_config: dict) -> CanonicalSeverity:
        if level:
            m = {
                "error": CanonicalSeverity.HIGH,
                "warning": CanonicalSeverity.MEDIUM,
                "note": CanonicalSeverity.LOW,
                "none": CanonicalSeverity.INFORMATIONAL,
            }
            mapped = m.get((level or "").lower())
            if mapped:
                return mapped
        default_level = default_config.get("level", "warning")
        m = {
            "error": CanonicalSeverity.HIGH,
            "warning": CanonicalSeverity.MEDIUM,
            "note": CanonicalSeverity.LOW,
            "none": CanonicalSeverity.INFORMATIONAL,
        }
        return m.get(str(default_level).lower(), CanonicalSeverity.MEDIUM)

    def _get_message(self, result: dict) -> str:
        msg = result.get("message") or {}
        if isinstance(msg, str):
            return msg
        return msg.get("text") or msg.get("markdown") or ""

    def _tool_name(self, run: dict) -> str:
        driver = run.get("tool", {}).get("driver", {})
        return driver.get("name", "unknown")

    def _index_rules(self, rules: list) -> dict[str | int, dict]:
        """Index rules by id and by index for lookup."""
        indexed: dict[str | int, dict] = {}
        for i, r in enumerate(rules):
            rid = r.get("id")
            if rid:
                indexed[rid] = r
            indexed[i] = r
        return indexed
