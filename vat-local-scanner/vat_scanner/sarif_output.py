"""Convert scanner reports to SARIF 2.1.0 format."""

from __future__ import annotations

import hashlib
from typing import Any

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SEVERITY_TO_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "unknown": "note"}


def partial_fingerprints_for_static_result(
    rule_id: str, artifact_uri: str, start_line: int | None
) -> dict[str, str]:
    """
    Emit SARIF partialFingerprints aligned with VAT backend resolution (primaryLocationLineHash/v1
    first; see backend ``app/services/sarif_fingerprints.py``). Stable across runs for the same
    rule + path + line so exported SARIF can be re-ingested with parser ``sarif`` without
    identity drift.
    """
    u = (artifact_uri or "").strip().replace("\\", "/").lower()
    line = int(start_line) if start_line is not None else 1
    rid = (rule_id or "").strip()
    material = f"{rid}|{u}|{line}"
    fp_val = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return {"primaryLocationLineHash/v1": fp_val}


def _level(sev: str) -> str:
    return SEVERITY_TO_LEVEL.get((sev or "").lower(), "warning")


def _trivy_to_sarif_results(report: dict, asset_name: str) -> tuple[list[dict], list[dict]]:
    """Convert Trivy report to SARIF results and rules."""
    results: list[dict] = []
    rules: dict[str, dict] = {}
    sarif_results: list[dict] = []
    raw_rules: list[dict] = []

    for r in report.get("Results") or report.get("results") or []:
        if not isinstance(r, dict):
            continue
        target = str(r.get("Target") or r.get("target") or asset_name)
        for vuln in r.get("Vulnerabilities") or r.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            rid = vuln.get("VulnerabilityID") or vuln.get("vulnerabilityID") or vuln.get("ID") or "trivy-vuln"
            sev = (vuln.get("Severity") or vuln.get("severity") or "medium").lower()
            pkg = vuln.get("PkgName") or vuln.get("pkgName") or ""
            ver = vuln.get("InstalledVersion") or vuln.get("installedVersion") or ""
            desc = vuln.get("Title") or vuln.get("title") or vuln.get("Description") or vuln.get("description") or rid
            if isinstance(desc, dict):
                desc = desc.get("text", str(desc))
            rules[rid] = {"id": rid, "shortDescription": {"text": str(desc)[:200]}}
            sarif_results.append({
                "ruleId": rid,
                "message": {"text": str(desc)[:1000]},
                "level": _level(sev),
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": target},
                        "region": {"startLine": 1},
                    }
                }],
                "partialFingerprints": partial_fingerprints_for_static_result(rid, target, 1),
                "properties": {
                    "packageName": pkg,
                    "installedVersion": ver,
                    "security-severity": str(vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", "") or vuln.get("CVSS", {}).get("redhat", {}).get("V3Score", "") or ""),
                },
            })
        for mis in r.get("Misconfigurations") or r.get("misconfigurations") or []:
            if not isinstance(mis, dict):
                continue
            rid = mis.get("ID") or mis.get("id") or "trivy-misconfig"
            sev = (mis.get("Severity") or mis.get("severity") or "medium").lower()
            desc = mis.get("Title") or mis.get("title") or mis.get("Description") or rid
            if isinstance(desc, dict):
                desc = desc.get("text", str(desc))
            rules[rid] = {"id": rid, "shortDescription": {"text": str(desc)[:200]}}
            mis_line = mis.get("StartLine") or mis.get("startLine") or 1
            sarif_results.append({
                "ruleId": rid,
                "message": {"text": str(desc)[:1000]},
                "level": _level(sev),
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": target},
                        "region": {"startLine": mis_line},
                    }
                }],
                "partialFingerprints": partial_fingerprints_for_static_result(rid, target, mis_line),
            })
        for sec in r.get("Secrets") or r.get("secrets") or []:
            if not isinstance(sec, dict):
                continue
            rid = sec.get("RuleID") or sec.get("ruleID") or "trivy-secret"
            rules[rid] = {"id": rid, "shortDescription": {"text": "Secret detected"}}
            sec_line = sec.get("StartLine") or 1
            sarif_results.append({
                "ruleId": rid,
                "message": {"text": sec.get("Title") or "Secret detected"},
                "level": "error",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": target},
                        "region": {"startLine": sec_line},
                    }
                }],
                "partialFingerprints": partial_fingerprints_for_static_result(rid, target, sec_line),
            })

    raw_rules = list(rules.values())
    return sarif_results, raw_rules


def _grype_to_sarif_results(report: dict, asset_name: str) -> tuple[list[dict], list[dict]]:
    """Convert Grype report to SARIF results and rules."""
    results: list[dict] = []
    rules: dict[str, dict] = {}
    for m in report.get("matches") or []:
        if not isinstance(m, dict):
            continue
        vuln = m.get("vulnerability") or {}
        artifact = m.get("artifact") or {}
        rid = vuln.get("id") or artifact.get("name", "grype-vuln")
        sev = (vuln.get("severity") or "medium").lower()
        desc = vuln.get("description") or rid
        locs = artifact.get("locations") or []
        uri = locs[0].get("path") if locs and isinstance(locs[0], dict) else asset_name
        pkg = artifact.get("name", "")
        ver = artifact.get("version", "")
        rules[rid] = {"id": rid, "shortDescription": {"text": str(desc)[:200]}}
        results.append({
            "ruleId": rid,
            "message": {"text": str(desc)[:1000]},
            "level": _level(sev),
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                }
            }],
            "partialFingerprints": partial_fingerprints_for_static_result(rid, uri, 1),
            "properties": {"packageName": pkg, "installedVersion": ver},
        })
    return results, list(rules.values())


def _npm_to_sarif_results(report: dict, asset_name: str) -> tuple[list[dict], list[dict]]:
    """Convert npm audit report to SARIF results and rules."""
    results: list[dict] = []
    rules: dict[str, dict] = {}
    vulns = report.get("vulnerabilities") or report.get("advisories") or {}
    if not isinstance(vulns, dict):
        return [], []
    for pkg_name, v in vulns.items():
        if not isinstance(v, dict):
            continue
        rid = v.get("id") or v.get("cve") or pkg_name
        sev = (v.get("severity") or "medium").lower()
        desc = v.get("title") or v.get("overview") or str(rid)
        rules[rid] = {"id": rid, "shortDescription": {"text": str(desc)[:200]}}
        results.append({
            "ruleId": rid,
            "message": {"text": str(desc)[:1000]},
            "level": _level(sev),
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "package.json"},
                    "region": {"startLine": 1},
                }
            }],
            "partialFingerprints": partial_fingerprints_for_static_result(rid, "package.json", 1),
            "properties": {"packageName": pkg_name},
        })
    return results, list(rules.values())


def _pip_to_sarif_results(report: dict | list, asset_name: str) -> tuple[list[dict], list[dict]]:
    """Convert pip-audit report to SARIF results and rules."""
    results: list[dict] = []
    rules: dict[str, dict] = {}
    deps = report if isinstance(report, list) else (report.get("dependencies") or [])
    for d in deps:
        if not isinstance(d, dict):
            continue
        pkg = d.get("name", "unknown")
        for v in d.get("vulns") or d.get("vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            rid = v.get("id") or f"pip-{pkg}"
            desc = v.get("description") or rid
            rules[rid] = {"id": rid, "shortDescription": {"text": str(desc)[:200]}}
            results.append({
                "ruleId": rid,
                "message": {"text": str(desc)[:1000]},
                "level": "warning",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "requirements.txt"},
                        "region": {"startLine": 1},
                    }
                }],
                "partialFingerprints": partial_fingerprints_for_static_result(rid, "requirements.txt", 1),
                "properties": {"packageName": pkg},
            })
    return results, list(rules.values())


def _semgrep_to_sarif_results(report: dict, asset_name: str) -> tuple[list[dict], list[dict]]:
    """Convert Semgrep report to SARIF results. Semgrep already has SARIF-like structure."""
    results: list[dict] = []
    rules: dict[str, dict] = {}
    for r in report.get("results") or []:
        if not isinstance(r, dict):
            continue
        rid = r.get("check_id") or r.get("rule_id") or "semgrep-rule"
        extra = r.get("extra") or {}
        sev = (extra.get("severity") or "warning").lower()
        msg = extra.get("message") or rid
        path = r.get("path", "")
        start = (r.get("start") or {}).get("line") or (extra.get("line") or 1)
        rules[rid] = {"id": rid, "shortDescription": {"text": str(msg)[:200]}}
        results.append({
            "ruleId": rid,
            "message": {"text": str(msg)[:1000]},
            "level": _level(sev),
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": start},
                }
            }],
            "partialFingerprints": partial_fingerprints_for_static_result(rid, path, start),
        })
    return results, list(rules.values())


def _gitleaks_to_sarif_results(report: dict | list, asset_name: str) -> tuple[list[dict], list[dict]]:
    """Convert Gitleaks report to SARIF results and rules."""
    results: list[dict] = []
    rules: dict[str, dict] = {}
    findings = report if isinstance(report, list) else (report.get("findings") or report.get("Findings") or [])
    for f in findings:
        if not isinstance(f, dict):
            continue
        rid = f.get("RuleID") or f.get("ruleId") or "gitleaks-secret"
        path = f.get("File") or f.get("file") or ""
        line = f.get("StartLine") or f.get("start_line") or 1
        desc = f.get("Description") or f.get("description") or "Secret detected"
        rules[rid] = {"id": rid, "shortDescription": {"text": str(desc)[:200]}}
        results.append({
            "ruleId": rid,
            "message": {"text": str(desc)[:1000]},
            "level": "error",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": line},
                }
            }],
            "partialFingerprints": partial_fingerprints_for_static_result(rid, path, line),
        })
    return results, list(rules.values())


def reports_to_sarif(reports: dict[str, dict | list], asset_name: str) -> dict[str, Any]:
    """Convert all scanner reports to a single SARIF 2.1.0 document."""
    runs: list[dict] = []
    converters = {
        "trivy": _trivy_to_sarif_results,
        "grype": _grype_to_sarif_results,
        "npm_audit": _npm_to_sarif_results,
        "pip_audit": _pip_to_sarif_results,
        "semgrep": _semgrep_to_sarif_results,
        "gitleaks": _gitleaks_to_sarif_results,
    }
    tool_names = {
        "trivy": "Trivy",
        "grype": "Grype",
        "npm_audit": "npm audit",
        "pip_audit": "pip-audit",
        "semgrep": "Semgrep",
        "gitleaks": "Gitleaks",
    }
    for parser, report in reports.items():
        conv = converters.get(parser)
        if not conv:
            continue
        try:
            sarif_results, sarif_rules = conv(report, asset_name)
        except Exception:
            continue
        if sarif_results:
            runs.append({
                "tool": {
                    "driver": {
                        "name": tool_names.get(parser, parser),
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
            })
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": runs,
    }
