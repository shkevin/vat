/**
 * Finding grouping — groups same vulnerability within asset (image|branch|tag).
 * Aligns with backend grouping service (app/services/grouping.py).
 *
 * Grouping is scoped within asset — findings in different repos/branches/tags do not group.
 * - SCA/CVE: ecosystem + package (componentBase) — one group per package per asset
 * - SAST: ruleId or cweId or normalized title — per asset
 * - IaC: ruleId or normalized title — per asset
 * - Secret: secretType or ruleId or normalized title — per asset
 * - License: ecosystem + package — per asset
 */

import type { Finding } from "@/types";
import { parseFileLocation } from "@/lib/repoFileUrl";

function componentBase(comp: string | undefined): string {
  if (!comp || typeof comp !== "string") return "";
  const base = comp.split("@")[0].trim();
  return base.toLowerCase() || "";
}

/** Normalize ecosystem for grouping. npm/yarn/pnpm share registry → same group key. */
function normalizeEcosystemForGrouping(eco: string | null | undefined): string {
  const e = (eco ?? "").toLowerCase().trim();
  if (e === "npm" || e === "yarn" || e === "pnpm") return "npm";
  return e;
}

/** Extract package from component when componentBase is missing. Handles "name version" format. */
function extractComponentBaseForGrouping(component: string | null | undefined): string {
  if (!component || typeof component !== "string") return "";
  const base = componentBase(component);
  if (!base) return "";
  const parts = base.split(/\s+/, 2);
  if (parts.length >= 2 && parts[1] && /^\d/.test(parts[1])) return parts[0].trim();
  return base;
}

/** Normalize package name per ecosystem. Must match backend (PEP 503 for PyPI). */
function normalizePackageName(ecosystem: string | null | undefined, name: string | null | undefined): string {
  if (!name || typeof name !== "string") return "";
  const n = name.trim();
  if (!n) return "";
  const eco = (ecosystem ?? "").toLowerCase().trim();
  if (eco === "npm" || eco === "yarn" || eco === "pnpm") return n.toLowerCase();
  if (eco === "pypi" || eco === "pip" || eco === "pipenv" || eco === "poetry")
    return n.toLowerCase().replace(/[-_.]+/g, "-");
  if (eco === "maven" || eco === "gradle") {
    // Prefer groupId:artifactId when present; else fall back to generic (Aikido may have malformed data)
    return n.toLowerCase();
  }
  return n.toLowerCase();
}

/** Normalize path for grouping: lowercase, forward slashes, no leading slash. */
function normalizePath(path: string): string {
  return path.replace(/\\/g, "/").replace(/^\/+/, "").toLowerCase().trim() || "";
}

/**
 * Returns a stable location key for grouping when the finding has file/line context.
 * Uses filePath and line from Finding when present, else parses from description/component.
 * Returns null when no location can be derived.
 */
export function getLocationKey(f: Finding): string | null {
  // Prefer explicit filePath/line when available (from backend)
  const explicitPath = f.filePath;
  const explicitLine = f.line;
  if (explicitPath?.trim()) {
    const path = normalizePath(explicitPath);
    return explicitLine != null && explicitLine > 0 ? `${path}@${explicitLine}` : path;
  }

  // Fallback: parse from description or component (Aikido, SARIF, etc.)
  const loc = parseFileLocation(f);
  if (!loc?.filePath) return null;
  const path = normalizePath(loc.filePath);
  return loc.line != null && loc.line > 0 ? `${path}@${loc.line}` : path;
}

/**
 * Normalize rule title for grouping by stripping location suffixes.
 * Same rule at different locations should group together (SAST/IaC).
 * Patterns: " in file.py", ", file and N others", " at line N in file".
 * @param stripLocations - when false (Secret), keep location so each file = separate group
 */
function normalizeRuleTitleForGrouping(title: string, stripLocations = true): string {
  if (!title || typeof title !== "string") return title;
  let t = title.trim();
  if (!stripLocations) return t.toLowerCase();
  // ", path and N others" or ", path, path and N others"
  t = t.replace(/, [^,]+(, [^,]+)? and \d+ others?$/i, "");
  // " in <path>" when path has extension (py, ts, etc.)
  t = t.replace(/\s+in\s+[\w./-]+\.(py|ts|tsx|js|jsx|json|yml|yaml|md|txt|xml|html|css|sh|go|rs|java|kt|env|tf|hcl|toml|lock)(\s*,\s*[\w./-]+)?$/i, "");
  // " in <path>" when path is extensionless (Dockerfile, Makefile, .dockerignore, .gitignore)
  t = t.replace(/\s+in\s+[\w./-]*(Dockerfile|Makefile|\.dockerignore|\.gitignore)(\s*,\s*[\w./-]+)?$/i, "");
  // " at line N in <path>" or " at line N-N in <path>"
  t = t.replace(/\s+at\s+line\s+\d+(-\d+)?\s+in\s+[\w./-]+$/i, "");
  return t.trim().toLowerCase();
}

/** Asset key for grouping — image|branch|tag. Grouping is within asset only. */
function assetKey(f: Finding): string {
  const img = (f.image ?? "").toLowerCase().trim();
  const br = (f.branch ?? "").toLowerCase().trim();
  const tg = (f.tag ?? "").toLowerCase().trim();
  return `${img}|${br}|${tg}`;
}

/**
 * Returns a stable group key for a finding. Findings with the same key are
 * considered the same logical issue. Aligns with backend get_finding_group_key.
 * Grouping is scoped within asset (image|branch|tag).
 */
export function getFindingGroupKey(f: Finding): string {
  const cveId = (f.cveId ?? "").toLowerCase().trim();
  const t = (f.findingType ?? "").toLowerCase();
  const rawTitle = (f.title ?? f.cveId ?? "").trim();
  const title = normalizeRuleTitleForGrouping(rawTitle, true);
  const rawPkg = f.componentBase ?? extractComponentBaseForGrouping(f.component);
  const eco = normalizeEcosystemForGrouping(f.ecosystem);
  const pkg = rawPkg ? normalizePackageName(eco || null, rawPkg) : "";
  const rid = (f.ruleId ?? "").toLowerCase().trim();
  const cwe = (f.cweId ?? "").toLowerCase().trim();
  const st = (f.secretType ?? "").toLowerCase().trim();
  const asset = assetKey(f);

  // SCA: ecosystem + package — one group per package per asset
  if (t === "sca") {
    if (pkg) return `sca:${eco}|${pkg}#${asset}`;
    return `cve:${cveId}#${asset}`;
  }

  // SAST: ruleId or cweId or normalized title
  if (t === "sast") {
    const key = rid || cwe || title || f.id;
    return `sast:${key}#${asset}`;
  }

  // IaC: ruleId or normalized title
  if (t === "iac") {
    const key = rid || title || f.id;
    return `iac:${key}#${asset}`;
  }

  // Secret: secretType or ruleId or title — normalize so "private-key" and "private key"
  // from different scanners (Gitleaks vs Trivy) group together
  if (t === "secret") {
    const secretTitle = normalizeRuleTitleForGrouping(rawTitle, false);
    const rawKey = st || rid || secretTitle || f.id;
    // Collapse spaces/dashes/underscores for simple rule ids only; skip path patterns
    const key =
      !rawKey.includes(" in ") && rawKey.length < 80
        ? (rawKey.replace(/[-_\s]+/g, "-").replace(/^-|-$/g, "") || rawKey)
        : rawKey;
    return `secret:${key}#${asset}`;
  }

  // License: ecosystem + package
  if (t === "license") {
    if (pkg) return `license:${eco}|${pkg}#${asset}`;
    return `license:${f.id}#${asset}`;
  }

  return `other:${f.id}#${asset}`;
}

/**
 * Groups findings by key. Returns Map<groupKey, Finding[]>.
 */
export function groupFindingsByKey(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = getFindingGroupKey(f);
    const list = map.get(key) ?? [];
    list.push(f);
    map.set(key, list);
  }
  return map;
}

function worstSeverityIndex(finding: Finding, sevOrder: readonly string[]): number {
  const i = sevOrder.indexOf(finding.severity);
  return i >= 0 ? i : 999;
}

/**
 * Returns grouped entries as [groupKey, findings[]], sorted by worst severity.
 */
export function getGroupedFindings(
  findings: Finding[],
  sevOrder: readonly string[]
): Array<{ key: string; findings: Finding[] }> {
  const map = groupFindingsByKey(findings);
  return Array.from(map.entries())
    .map(([key, list]) => ({ key, findings: list }))
    .sort((a, b) => {
      const worstA = a.findings.reduce((w, f) =>
        worstSeverityIndex(f, sevOrder) < worstSeverityIndex(w, sevOrder) ? f : w
      );
      const worstB = b.findings.reduce((w, f) =>
        worstSeverityIndex(f, sevOrder) < worstSeverityIndex(w, sevOrder) ? f : w
      );
      return worstSeverityIndex(worstA, sevOrder) - worstSeverityIndex(worstB, sevOrder);
    });
}
