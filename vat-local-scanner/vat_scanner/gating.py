"""Gating logic: extract findings, severity, diff-aware filtering, fail evaluation."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

# Severity order: critical > high > medium > low
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _normalize_severity(s: str | None) -> str:
    """Normalize severity to lowercase critical|high|medium|low."""
    if not s:
        return "unknown"
    v = str(s).strip().lower()
    for known in ("critical", "high", "medium", "low"):
        if known in v or v == known:
            return known
    return "unknown"


def _severity_level(sev: str) -> int:
    """Return numeric level for comparison."""
    return SEVERITY_ORDER.get(_normalize_severity(sev), 0)


def get_changed_files(repo_root: Path, base: str, head: str) -> set[str]:
    """Return set of file paths changed between base and head commits (relative to repo)."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", base, head],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=repo_root,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return set()
    if result.returncode != 0:
        return set()
    return {p.strip() for p in result.stdout.splitlines() if p.strip()}


def _extract_trivy_findings(report: dict, repo_root: Path) -> list[dict[str, Any]]:
    """Extract findings with path and severity from Trivy report."""
    out: list[dict[str, Any]] = []
    results = report.get("Results") or report.get("results") or []
    for r in results:
        if not isinstance(r, dict):
            continue
        target = str(r.get("Target") or r.get("target") or "")
        vulns = r.get("Vulnerabilities") or r.get("vulnerabilities") or []
        misconfigs = r.get("Misconfigurations") or r.get("misconfigurations") or []
        secrets = r.get("Secrets") or r.get("secrets") or []
        for v in vulns + misconfigs + secrets:
            if not isinstance(v, dict):
                continue
            sev = _normalize_severity(v.get("Severity") or v.get("severity"))
            path = v.get("Target") or v.get("File") or v.get("file") or target
            if not path:
                path = target
            out.append({"path": str(path), "severity": sev, "parser": "trivy", "raw": v})
    return out


def _extract_grype_findings(report: dict, repo_root: Path) -> list[dict[str, Any]]:
    """Extract findings from Grype report."""
    out: list[dict[str, Any]] = []
    matches = report.get("matches") or []
    for m in matches:
        if not isinstance(m, dict):
            continue
        vuln = m.get("vulnerability") or {}
        artifact = m.get("artifact") or {}
        sev = _normalize_severity(vuln.get("severity"))
        path = artifact.get("locations") or []
        loc = path[0] if path else {}
        file_path = loc.get("path") if isinstance(loc, dict) else str(artifact.get("name", ""))
        out.append({"path": file_path or "package", "severity": sev, "parser": "grype", "raw": m})
    return out


def _extract_npm_findings(report: dict, repo_root: Path) -> list[dict[str, Any]]:
    """Extract findings from npm audit report."""
    out: list[dict[str, Any]] = []
    vulns = report.get("vulnerabilities") or report.get("advisories") or {}
    if isinstance(vulns, dict):
        for _k, v in vulns.items():
            if not isinstance(v, dict):
                continue
            sev = _normalize_severity(v.get("severity"))
            out.append({"path": "package.json", "severity": sev, "parser": "npm_audit", "raw": v})
    return out


def _extract_pip_findings(report: dict | list, repo_root: Path) -> list[dict[str, Any]]:
    """Extract findings from pip-audit report (dependencies or legacy array format)."""
    out: list[dict[str, Any]] = []
    deps = report if isinstance(report, list) else (report.get("dependencies") or [])
    for d in deps:
        if not isinstance(d, dict):
            continue
        vulns = d.get("vulns") or d.get("vulnerabilities") or []
        pkg_name = d.get("name", "requirements")
        for v in vulns:
            if not isinstance(v, dict):
                continue
            # pip-audit vulns typically lack severity; treat as medium for gating
            sev = _normalize_severity(v.get("severity")) or "medium"
            out.append({"path": pkg_name, "severity": sev, "parser": "pip_audit", "raw": v})
    return out


def _extract_semgrep_findings(report: dict, repo_root: Path) -> list[dict[str, Any]]:
    """Extract findings from Semgrep report."""
    out: list[dict[str, Any]] = []
    results = report.get("results") or []
    for r in results:
        if not isinstance(r, dict):
            continue
        path = r.get("path") or ""
        extra = r.get("extra") or {}
        sev = _normalize_severity(extra.get("severity"))
        out.append({"path": path, "severity": sev, "parser": "semgrep", "raw": r})
    return out


def _extract_gitleaks_findings(report: dict | list, repo_root: Path) -> list[dict[str, Any]]:
    """Extract findings from Gitleaks report."""
    out: list[dict[str, Any]] = []
    findings = report if isinstance(report, list) else (report.get("findings") or report.get("Findings") or [])
    for f in findings:
        if not isinstance(f, dict):
            continue
        path = f.get("File") or f.get("file") or ""
        out.append({"path": path, "severity": "high", "parser": "gitleaks", "raw": f})
    return out


def extract_gating_findings(
    reports: dict[str, dict | list],
    repo_root: Path,
) -> list[dict[str, Any]]:
    """Extract all findings with path and severity from reports."""
    all_findings: list[dict[str, Any]] = []
    for parser, report in reports.items():
        if parser == "trivy":
            all_findings.extend(_extract_trivy_findings(report, repo_root))
        elif parser == "grype":
            all_findings.extend(_extract_grype_findings(report, repo_root))
        elif parser == "npm_audit":
            all_findings.extend(_extract_npm_findings(report, repo_root))
        elif parser == "pip_audit":
            all_findings.extend(_extract_pip_findings(report, repo_root))
        elif parser == "semgrep":
            all_findings.extend(_extract_semgrep_findings(report, repo_root))
        elif parser == "gitleaks":
            all_findings.extend(_extract_gitleaks_findings(report, repo_root))
    return all_findings


def filter_findings_in_diff(
    findings: list[dict[str, Any]],
    changed_files: set[str],
) -> list[dict[str, Any]]:
    """Keep only findings whose path is in changed_files (or path starts with a changed dir)."""
    if not changed_files:
        return findings
    out: list[dict[str, Any]] = []
    for f in findings:
        path = f.get("path", "")
        if not path:
            continue
        # Normalize path separators
        path_norm = path.replace("\\", "/")
        for cf in changed_files:
            cf_norm = cf.replace("\\", "/")
            if path_norm == cf_norm or path_norm.startswith(cf_norm + "/"):
                out.append(f)
                break
    return out


def evaluate_gating(
    findings: list[dict[str, Any]],
    fail_on: str,
) -> tuple[bool, list[dict[str, Any]]]:
    """
    Evaluate if gating should fail.
    Returns (should_fail, list of findings that exceed threshold).
    fail_on: low|medium|high|critical — fail if any finding >= this severity.
    """
    threshold = _severity_level(fail_on)
    if threshold == 0:
        return False, []
    exceeding: list[dict[str, Any]] = []
    for f in findings:
        if _severity_level(f.get("severity", "")) >= threshold:
            exceeding.append(f)
    return len(exceeding) > 0, exceeding
