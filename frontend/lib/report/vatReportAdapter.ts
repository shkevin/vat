/**
 * VAT report data adapter — maps Finding[] and Asset[] to DashboardData-like
 * structure for the report engine (compatible with AikidoIssue/AikidoIssueGroup shape).
 */

import type { Finding, Asset } from "@/types";
import { getAssetTypeFromAsset } from "@/lib/assetUtils";
import { isOpenRisk } from "@/lib/metricSemantics";
import { displaySourceName } from "@/lib/utils";
import { effectiveGroupKey, groupFindingsByKey } from "@/lib/findingGroupUtils";

/** VAT-compatible issue shape for report engine (matches AikidoIssue fields used by metrics/report-engine) */
export interface VATReportIssue {
  issue_id: number;
  issue_group_id: number;
  first_detected_at: string;
  last_detected_at: string;
  repository?: string;
  branch?: string;
  severity: string;
  severity_score: number;
  status: string;
  title: string;
  cve_id?: string;
  cwe_id?: string;
  scanner_type?: string;
  closed_at?: string;
  /** CVE published date (for ABC CVE age tolerance). Optional; first_detected_at used as fallback. */
  cve_published_at?: string | null;
  description?: string;
  affected_package?: string;
  affected_version?: string;
  fixed_version?: string;
  /** External source platform link for this finding (e.g. Aikido). */
  source_url?: string;
  /** Optional source-provided group severity (Aikido issue group severity). */
  source_group_severity?: string;
}

/** VAT-compatible issue group (for repo/container risk, top vulns) */
export interface VATReportIssueGroup {
  group_id: number;
  title: string;
  severity: string;
  severity_score: number;
  status: string;
  first_detected_at: string;
  issue_count: number;
  affected_repos: string[];
  scanner_type: string;
  cve_id?: string;
  has_task: boolean;
  source_url: string;
}

/** VAT-compatible repo/container shape */
export interface VATReportRepo {
  id: number;
  name: string;
  provider: string;
  issue_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  mitigated_critical_count?: number;
  mitigated_high_count?: number;
  mitigated_medium_count?: number;
  mitigated_low_count?: number;
}

export interface VATDashboardData {
  issues: VATReportIssue[];
  issueGroups: VATReportIssueGroup[];
  /** Code repos (type repo, path) — for repo risk bars and Code in asset mix */
  repos: VATReportRepo[];
  /** Package assets — for Package classification in asset mix (avoids heuristic false positives) */
  packageRepos: VATReportRepo[];
  containers: VATReportRepo[];
  vms: VATReportRepo[];
  teams: Array<{ id: string; name: string }>;
  workspace: { id: string; name: string; plan: string };
  fetchedAt: string;
  /** Optional - for report engine compatibility */
  activityLog?: unknown[];
  soc2Compliance?: unknown;
  nis2Compliance?: unknown;
  iso27001Compliance?: unknown;
  ciScans?: unknown[];
  taskProjects?: unknown[];
  tasksByGroupId?: Record<number, unknown[]>;
  cveDetailsByCveId?: Record<string, { epss_score?: number; in_kev?: boolean }>;
  /** Aikido authoritative counts (GET /issues/counts). Used when no filters for accurate totals. */
  issueCounts?: {
    open: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  } | null;
}

function sevToScore(sev: string): number {
  const s = (sev ?? "").toLowerCase();
  if (s === "critical") return 10;
  if (s === "high") return 8;
  if (s === "medium" || s === "moderate") return 5;
  if (s === "low") return 3;
  return 1;
}

export interface FindingGroupOptions {
  /** When true, use Aikido-style grouping (cveId+component for CVE, findingType+title for non-CVE). Default true. */
  groupFindings?: boolean;
}

function groupByLegacy(findings: Finding[]): Map<string, Finding[]> {
  const byCve = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = f.cveId || f.id;
    const list = byCve.get(key) ?? [];
    list.push(f);
    byCve.set(key, list);
  }
  return byCve;
}

export function findingsToVATReportIssues(
  findings: Finding[],
  options: FindingGroupOptions = {},
): VATReportIssue[] {
  const { groupFindings = true } = options;
  const byKey = groupFindings
    ? groupFindingsByKey(findings)
    : groupByLegacy(findings);

  const groupMap = new Map<string, number>();
  let groupId = 1;
  for (const key of byKey.keys()) {
    groupMap.set(key, groupId++);
  }
  const result: VATReportIssue[] = [];
  let issueId = 1;
  for (const f of findings) {
    const key = groupFindings ? effectiveGroupKey(f) : f.cveId || f.id;
    const gid = groupMap.get(key) ?? 0;
    const detected =
      f.firstDetectedAt ??
      f.created ??
      f.audit?.[0]?.ts ??
      new Date().toISOString();
    // Use closed_at only when from source (Aikido). Never invent from audit — vulnerability-dashboard
    // matches Aikido by requiring real closed_at for "resolved this week"; invented dates inflate counts.
    const closedAt = f.closedAt ?? undefined;
    const sourceUrl =
      (f.externalLinks ?? []).find((l) => l.kind === "source" && l.url)?.url ??
      undefined;
    // Use the persisted finding severity as the single source of truth.
    const issueSeverity = f.severity ?? "info";
    result.push({
      issue_id: issueId++,
      issue_group_id: gid,
      first_detected_at: detected,
      last_detected_at: detected,
      repository: f.image ?? f.component ?? undefined,
      branch: f.branch ?? undefined,
      severity: issueSeverity,
      severity_score: sevToScore(issueSeverity),
      status: (f.status ?? "open").toLowerCase(),
      title: f.title ?? f.cveId ?? "Unknown",
      cve_id: f.cveId,
      description: f.description,
      affected_package: f.component,
      scanner_type: displaySourceName(f.source) || "VAT",
      closed_at: closedAt,
      source_url: sourceUrl,
      source_group_severity: f.sourceGroupSeverity ?? undefined,
    });
  }
  return result;
}

export function findingsToVATReportIssueGroups(
  findings: Finding[],
  options: FindingGroupOptions = {},
): VATReportIssueGroup[] {
  const { groupFindings = true } = options;
  const byKey = groupFindings
    ? groupFindingsByKey(findings)
    : groupByLegacy(findings);

  return Array.from(byKey.entries()).map(([, list], i) => {
    const worst = list.reduce((a, b) =>
      sevToScore(a.severity) >= sevToScore(b.severity) ? a : b,
    );
    const groupSeverity = worst.severity ?? "info";
    const repos = Array.from(
      new Set(
        list.map((f) => f.image ?? f.component ?? "unknown").filter(Boolean),
      ),
    );
    const sourceUrl =
      list
        .map(
          (f) =>
            (f.externalLinks ?? []).find((l) => l.kind === "source" && l.url)
              ?.url,
        )
        .find(Boolean) ?? "";
    return {
      group_id: i + 1,
      title: worst.title ?? worst.cveId ?? "Unknown",
      severity: groupSeverity,
      severity_score: sevToScore(groupSeverity),
      status: (worst.status ?? "open").toLowerCase(),
      first_detected_at:
        worst.firstDetectedAt ??
        worst.created ??
        worst.audit?.[0]?.ts ??
        new Date().toISOString(),
      issue_count: list.length,
      affected_repos: repos,
      scanner_type: displaySourceName(worst.source) || "VAT",
      cve_id: worst.cveId,
      has_task: Boolean(worst.trackerId),
      source_url: sourceUrl,
    };
  });
}

function isMitigated(f: Finding): boolean {
  return (f.status ?? "").toLowerCase() === "mitigated";
}

function severityKey(f: Finding): "critical" | "high" | "medium" | "low" {
  const s = (f.severity ?? "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium" || s === "moderate") return "medium";
  return "low";
}

export function assetsToVATReportRepos(assets: Asset[]): VATReportRepo[] {
  return assets.map((a, i) => {
    const openFindings = a.findings.filter((f) => isOpenRisk(f.status));
    const critical: Finding[] = [];
    const high: Finding[] = [];
    const medium: Finding[] = [];
    const low: Finding[] = [];
    for (const f of openFindings) {
      const key = severityKey(f);
      if (key === "critical") critical.push(f);
      else if (key === "high") high.push(f);
      else if (key === "medium") medium.push(f);
      else low.push(f);
    }
    return {
      id: i + 1,
      name: a.name,
      provider: "vat",
      issue_count: openFindings.length,
      critical_count: critical.length,
      high_count: high.length,
      medium_count: medium.length,
      low_count: low.length,
      mitigated_critical_count: critical.filter(isMitigated).length,
      mitigated_high_count: high.filter(isMitigated).length,
      mitigated_medium_count: medium.filter(isMitigated).length,
      mitigated_low_count: low.filter(isMitigated).length,
    };
  });
}

export function toVATDashboardData(
  findings: Finding[],
  assets: Asset[],
  workspaceName = "VAT",
  options: FindingGroupOptions = {},
): VATDashboardData {
  const issues = findingsToVATReportIssues(findings, options);
  const issueGroups = findingsToVATReportIssueGroups(findings, options);
  const codeAssets: Asset[] = [];
  const packageAssets: Asset[] = [];
  const containerAssets: Asset[] = [];
  for (const a of assets) {
    const t = getAssetTypeFromAsset(a);
    if (t === "container") containerAssets.push(a);
    else if (t === "package") packageAssets.push(a);
    else codeAssets.push(a); // repo, path
  }
  const repos = assetsToVATReportRepos(codeAssets);
  const packageRepos = assetsToVATReportRepos(packageAssets);
  const containers = assetsToVATReportRepos(containerAssets);
  return {
    issues,
    issueGroups,
    repos,
    packageRepos,
    containers,
    vms: [],
    teams: [],
    workspace: { id: "vat", name: workspaceName, plan: "default" },
    fetchedAt: new Date().toISOString(),
  };
}
