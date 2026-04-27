/**
 * Report metrics — works with VATReportIssue / VATReportRepo shapes.
 */

import {
  computeORAScore,
  toDisplayORA,
  getORARiskLevel,
  computeORAPenalty,
  computeABCCompliance,
  type ABCCriteriaResult,
  type ABCIssueInput,
} from "./ora";
import type {
  VATReportIssue,
  VATReportIssueGroup,
  VATReportRepo,
} from "./vatReportAdapter";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface TrendDataPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface ScannerBreakdown {
  scanner: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface RepoRiskScore {
  repo: string;
  score: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface ContainerRiskScore {
  repo: string;
  score: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface AssetMix {
  code: number;
  container: number;
  vm: number;
  package: number;
  other: number;
}

export interface ReachabilityMatrixRow {
  severity: string;
  exploitable: number;
  notExploitable: number;
  unknown: number;
}

export interface MTTRData {
  severity: string;
  avgDays: number;
  medianDays: number;
  count: number;
}

export interface AgingBucket {
  range: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface TopVulnerability {
  id: number;
  title: string;
  severity: string;
  cve: string;
  repo: string;
  age: number;
  score: number;
  hasTask: boolean;
  sourceUrl?: string;
}

function safeAge(dateStr: string): number {
  const ts = new Date(dateStr).getTime();
  if (Number.isNaN(ts)) return 0;
  const days = (Date.now() - ts) / (1000 * 60 * 60 * 24);
  return Number.isFinite(days) && days >= 0 ? Math.round(days) : 0;
}

function safeDate(dateStr: string): Date | null {
  const d = new Date(dateStr);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function normalizeSeverity(
  severity: string,
  score?: number,
): keyof SeverityCounts {
  const s = (severity ?? "").toLowerCase().trim();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium" || s === "moderate") return "medium";
  if (s === "low") return "low";
  if (s === "info" || s === "informational" || s === "none") return "info";
  if (score !== undefined && score > 0) {
    if (score >= 9) return "critical";
    if (score >= 7) return "high";
    if (score >= 4) return "medium";
    if (score >= 0.1) return "low";
  }
  return "info";
}

/** Statuses treated as closed (not open). Includes Aikido + VAT-specific (false positive, suppressed, approved, duplicate, not applicable, rejected). */
const EXCLUDED_OPEN_STATUSES = [
  "closed",
  "resolved",
  "ignored",
  "auto_ignored",
  "false positive",
  "suppressed",
  "approved",
  "duplicate",
  "not applicable",
  "rejected",
] as const;

export function isOpen(issue: VATReportIssue): boolean {
  const st = (issue.status ?? "").toLowerCase();
  return !EXCLUDED_OPEN_STATUSES.includes(
    st as (typeof EXCLUDED_OPEN_STATUSES)[number],
  );
}

/** A finding is "closed" for reporting purposes when it has a closure timestamp
 * and a status that removes it from the open queue — remediated, suppressed,
 * false-positive, ignored, etc. Used by both MTTR (for time-to-close) and the
 * trend "Closed this week" KPI so both speak the same language about "off the
 * board this period". */
export function isClosedIssue(issue: VATReportIssue): boolean {
  if (!issue.closed_at) return false;
  const st = (issue.status ?? "").toLowerCase();
  return EXCLUDED_OPEN_STATUSES.includes(
    st as (typeof EXCLUDED_OPEN_STATUSES)[number],
  );
}

function isMitigated(issue: VATReportIssue): boolean {
  return (issue.status ?? "").toLowerCase() === "mitigated";
}

function issuesForTrend(issues: VATReportIssue[]): VATReportIssue[] {
  return issues.filter((i) => {
    const st = (i.status ?? "").toLowerCase();
    const isExcluded = EXCLUDED_OPEN_STATUSES.includes(
      st as (typeof EXCLUDED_OPEN_STATUSES)[number],
    );
    if (isExcluded && !i.closed_at) return false;
    return true;
  });
}

export function computeSeverityCounts(
  issues: VATReportIssue[],
): SeverityCounts {
  return issues.reduce(
    (acc, issue) => {
      acc[normalizeSeverity(issue.severity, issue.severity_score)]++;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as SeverityCounts,
  );
}

/** Severity rank for comparing worst (higher = more severe). Group severity = max across instances. */
function severityRank(sev: keyof SeverityCounts): number {
  const order: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  return order[sev] ?? 0;
}

export function computeSeverityCountsByGroups(
  issues: VATReportIssue[],
): SeverityCounts {
  const byGroup = new Map<number, keyof SeverityCounts>();
  for (const issue of issues) {
    const gid = issue.issue_group_id ?? 0;
    const sev = normalizeSeverity(issue.severity, issue.severity_score);
    const existing = byGroup.get(gid);
    if (!existing || severityRank(sev) > severityRank(existing)) {
      byGroup.set(gid, sev);
    }
  }
  const counts: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const sev of Array.from(byGroup.values()))
    counts[sev as keyof SeverityCounts]++;
  return counts;
}

export type CountMode = "groups" | "instances";

export interface ResolvedOpenCounts {
  totalOpen: number;
  counts: SeverityCounts;
  source:
    | "issueCounts"
    | "computed-groups"
    | "computed-instances"
    | "computed-groups-from-groups";
}

/** Compute severity counts from issueGroups. Use when the data provider supplies canonical group metadata. */
export function computeSeverityCountsFromGroups(
  issueGroups: VATReportIssueGroup[],
): SeverityCounts {
  const counts: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const g of issueGroups) {
    const sev = normalizeSeverity(g.severity, g.severity_score);
    counts[sev]++;
  }
  return counts;
}

export function resolveOpenCounts(
  openIssues: VATReportIssue[],
  options: {
    countMode: CountMode;
    issueCounts?: {
      open: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
    } | null;
    issueGroups?: VATReportIssueGroup[];
    hasFilters?: boolean;
  },
): ResolvedOpenCounts {
  const { countMode, issueCounts, issueGroups, hasFilters } = options;
  if (
    !hasFilters &&
    countMode === "groups" &&
    issueCounts &&
    issueCounts.open > 0
  ) {
    return {
      totalOpen: issueCounts.open,
      counts: {
        critical: issueCounts.critical,
        high: issueCounts.high,
        medium: issueCounts.medium,
        low: issueCounts.low,
        info: 0,
      },
      source: "issueCounts",
    };
  }
  if (countMode === "groups" && issueGroups && issueGroups.length > 0) {
    const groupIdsInOpenIssues = new Set(
      openIssues.map((i) => i.issue_group_id ?? 0),
    );
    const groupSev = new Map<number, keyof SeverityCounts>();
    for (const g of issueGroups) {
      const gid = g.group_id ?? 0;
      if (groupIdsInOpenIssues.has(gid)) {
        groupSev.set(gid, normalizeSeverity(g.severity, g.severity_score));
      }
    }
    const counts: SeverityCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const sev of groupSev.values()) counts[sev]++;
    const total =
      counts.critical + counts.high + counts.medium + counts.low + counts.info;
    return { totalOpen: total, counts, source: "computed-groups-from-groups" };
  }
  if (countMode === "groups") {
    const counts = computeSeverityCountsByGroups(openIssues);
    return {
      totalOpen:
        counts.critical +
        counts.high +
        counts.medium +
        counts.low +
        counts.info,
      counts,
      source: "computed-groups",
    };
  }
  const counts = computeSeverityCounts(openIssues);
  return { totalOpen: openIssues.length, counts, source: "computed-instances" };
}

export function countTotalIssues(
  issues: VATReportIssue[],
  countMode: CountMode = "groups",
): number {
  if (countMode === "instances") return issues.length;
  const seen = new Set<number>();
  for (const i of issues) seen.add(i.issue_group_id ?? 0);
  return seen.size;
}

export function computeTrendData(
  issues: VATReportIssue[],
  countMode: CountMode = "groups",
): TrendDataPoint[] {
  const trendIssues = issuesForTrend(issues);
  const now = new Date();
  const months: TrendDataPoint[] = [];
  for (let i = 11; i >= 0; i--) {
    const monthEnd = new Date(
      Date.UTC(
        now.getUTCFullYear(),
        now.getUTCMonth() - i + 1,
        0,
        23,
        59,
        59,
        999,
      ),
    );
    const label = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1),
    ).toLocaleDateString("en-US", {
      month: "short",
      year: "2-digit",
    });
    const openAtMonth = trendIssues.filter((issue) => {
      const det = safeDate(issue.first_detected_at);
      if (!det || det.getTime() > monthEnd.getTime()) return false;
      const cls = issue.closed_at ? safeDate(issue.closed_at) : null;
      return !cls || cls.getTime() > monthEnd.getTime();
    });
    const counts =
      countMode === "groups"
        ? computeSeverityCountsByGroups(openAtMonth)
        : computeSeverityCounts(openAtMonth);
    const total =
      countMode === "groups"
        ? counts.critical +
          counts.high +
          counts.medium +
          counts.low +
          counts.info
        : openAtMonth.length;
    months.push({ date: label, ...counts, total });
  }
  return months;
}

export interface PeriodChange {
  current: number;
  previous: number;
  pctChange: number;
  direction: "up" | "down" | "flat";
}

function openAtDate(
  issues: VATReportIssue[],
  atDate: Date,
): { total: number; criticalHigh: number; issues: VATReportIssue[] } {
  const ts = atDate.getTime();
  const open: VATReportIssue[] = [];
  let criticalHigh = 0;
  for (const i of issues) {
    const det = safeDate(i.first_detected_at);
    if (!det || det.getTime() > ts) continue;
    const cls = i.closed_at ? safeDate(i.closed_at) : null;
    if (cls && cls.getTime() <= ts) continue;
    open.push(i);
    const sev = normalizeSeverity(i.severity, i.severity_score);
    if (sev === "critical" || sev === "high") criticalHigh++;
  }
  return { total: open.length, criticalHigh, issues: open };
}

function avgMttrInRange(
  issues: VATReportIssue[],
  start: Date,
  end: Date,
): number | undefined {
  const days: number[] = [];
  const startTs = start.getTime();
  const endTs = end.getTime();
  for (const i of issues) {
    if (!isClosedIssue(i) || !i.first_detected_at) continue;
    const closed = safeDate(i.closed_at!);
    const detected = safeDate(i.first_detected_at);
    if (!closed || !detected || closed < detected) continue;
    const closedTs = closed.getTime();
    if (closedTs < startTs || closedTs > endTs) continue;
    const d = (closedTs - detected.getTime()) / (1000 * 60 * 60 * 24);
    if (Number.isFinite(d) && d >= 0) days.push(d);
  }
  if (days.length === 0) return undefined;
  return days.reduce((s, d) => s + d, 0) / days.length;
}

export function computePeriodOverPeriodChange(
  issues: VATReportIssue[],
  dateFrom: string | null,
  dateTo: string | null,
  countMode: CountMode = "groups",
): {
  openIssues: PeriodChange;
  criticalHigh: PeriodChange;
  riskScore: PeriodChange | null;
  mttr: PeriodChange | null;
} | null {
  if (!dateFrom || !dateTo) return null;
  const from = new Date(dateFrom);
  const to = new Date(dateTo);
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) return null;
  const current = openAtDate(issues, to);
  const previous = openAtDate(issues, from);
  const currentCounts =
    countMode === "groups"
      ? computeSeverityCountsByGroups(current.issues)
      : computeSeverityCounts(current.issues);
  const previousCounts =
    countMode === "groups"
      ? computeSeverityCountsByGroups(previous.issues)
      : computeSeverityCounts(previous.issues);
  const currentTotal =
    countMode === "groups"
      ? currentCounts.critical +
        currentCounts.high +
        currentCounts.medium +
        currentCounts.low +
        currentCounts.info
      : current.total;
  const previousTotal =
    countMode === "groups"
      ? previousCounts.critical +
        previousCounts.high +
        previousCounts.medium +
        previousCounts.low +
        previousCounts.info
      : previous.total;
  const currentCriticalHigh = currentCounts.critical + currentCounts.high;
  const previousCriticalHigh = previousCounts.critical + previousCounts.high;
  const pct = (curr: number, prev: number) =>
    prev === 0
      ? curr > 0
        ? 100
        : 0
      : Math.round(((curr - prev) / prev) * 100);
  const dir = (curr: number, prev: number): "up" | "down" | "flat" =>
    curr > prev ? "up" : curr < prev ? "down" : "flat";
  const periodDays = Math.round(
    (to.getTime() - from.getTime()) / (1000 * 60 * 60 * 24),
  );
  const prevStart = new Date(from);
  prevStart.setDate(prevStart.getDate() - periodDays);
  const currentRisk = computeReportRiskScore(currentCounts);
  const previousRisk = computeReportRiskScore(previousCounts);
  const riskScore =
    currentTotal > 0 || previousTotal > 0
      ? {
          current: currentRisk,
          previous: previousRisk,
          pctChange:
            previousRisk === 0
              ? currentRisk > 0
                ? 100
                : 0
              : Math.round(((currentRisk - previousRisk) / previousRisk) * 100),
          direction: dir(currentRisk, previousRisk),
        }
      : null;
  const currentMttr = avgMttrInRange(issues, from, to);
  const previousMttr = avgMttrInRange(issues, prevStart, from);
  const mttr =
    currentMttr !== undefined && previousMttr !== undefined
      ? {
          current: currentMttr,
          previous: previousMttr,
          pctChange:
            previousMttr === 0
              ? currentMttr > 0
                ? 100
                : 0
              : Math.round(((currentMttr - previousMttr) / previousMttr) * 100),
          direction: dir(currentMttr, previousMttr),
        }
      : null;
  return {
    openIssues: {
      current: currentTotal,
      previous: previousTotal,
      pctChange: pct(currentTotal, previousTotal),
      direction: dir(currentTotal, previousTotal),
    },
    criticalHigh: {
      current: currentCriticalHigh,
      previous: previousCriticalHigh,
      pctChange: pct(currentCriticalHigh, previousCriticalHigh),
      direction: dir(currentCriticalHigh, previousCriticalHigh),
    },
    riskScore,
    mttr,
  };
}

/** Trend data for the last N days, bucketed by rolling 7-day windows to match vulnerability-dashboard. */
export function computeTrendDataLastDays(
  issues: VATReportIssue[],
  days: number,
  countMode: CountMode = "groups",
): TrendDataPoint[] {
  const trendIssues = issuesForTrend(issues);
  const now = new Date();
  const buckets: TrendDataPoint[] = [];
  const numWeeks = Math.max(1, Math.ceil(days / 7));
  for (let w = numWeeks - 1; w >= 0; w--) {
    const weekEnd = new Date(now);
    weekEnd.setDate(weekEnd.getDate() - w * 7);
    weekEnd.setHours(23, 59, 59, 999);
    const weekStart = new Date(weekEnd);
    weekStart.setDate(weekStart.getDate() - 6);
    weekStart.setHours(0, 0, 0, 0);
    const label = weekStart.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
    });
    const openAtWeek = trendIssues.filter((issue) => {
      const det = safeDate(issue.first_detected_at);
      if (!det || det > weekEnd) return false;
      const cls = issue.closed_at ? safeDate(issue.closed_at) : null;
      return !cls || cls > weekEnd;
    });
    const counts =
      countMode === "groups"
        ? computeSeverityCountsByGroups(openAtWeek)
        : computeSeverityCounts(openAtWeek);
    const total =
      countMode === "groups"
        ? counts.critical +
          counts.high +
          counts.medium +
          counts.low +
          counts.info
        : openAtWeek.length;
    buckets.push({ date: label, ...counts, total });
  }
  return buckets;
}

export function computeScannerBreakdown(
  issues: VATReportIssue[],
  countMode: CountMode = "groups",
): ScannerBreakdown[] {
  const map = new Map<string, ScannerBreakdown>();
  const ensure = (scanner: string) => {
    if (!map.has(scanner))
      map.set(scanner, {
        scanner,
        count: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      });
    return map.get(scanner)!;
  };
  if (countMode === "groups") {
    // Pick the max-severity instance per group as the representative; attribute
    // the group's count + severity to that representative's scanner. Matches
    // the max-sev-per-group invariant of computeSeverityCountsByGroups so the
    // donut totals agree with the executive summary KPIs.
    const byGroup = new Map<number, VATReportIssue>();
    for (const i of issues) {
      const gid = i.issue_group_id ?? 0;
      const prev = byGroup.get(gid);
      const iSev = severityRank(
        normalizeSeverity(i.severity, i.severity_score),
      );
      const pSev = prev
        ? severityRank(normalizeSeverity(prev.severity, prev.severity_score))
        : -1;
      if (!prev || iSev > pSev) byGroup.set(gid, i);
    }
    for (const issue of Array.from(byGroup.values())) {
      const scanner = issue.scanner_type || "Unknown";
      const e = ensure(scanner);
      e.count++;
      const sev = normalizeSeverity(issue.severity, issue.severity_score);
      if (sev !== "info") e[sev]++;
    }
  } else {
    for (const issue of issues) {
      const scanner = issue.scanner_type || "Unknown";
      const e = ensure(scanner);
      e.count++;
      const sev = normalizeSeverity(issue.severity, issue.severity_score);
      if (sev !== "info") e[sev]++;
    }
  }
  return Array.from(map.values()).sort((a, b) => b.count - a.count);
}

function issueMatchesRepo(issueRepo: string, repoName: string): boolean {
  const a = (issueRepo ?? "").trim().toLowerCase();
  const b = (repoName ?? "").trim().toLowerCase();
  if (!a || !b) return false;
  if (a === b) return true;
  if (a.endsWith("/" + b)) return true;
  if (b.endsWith("/" + a)) return true;
  return false;
}

function resolveToTrackedRepoName(
  issueRepo: string,
  repos: VATReportRepo[],
): string | null {
  if (!repos.length || !issueRepo?.trim()) return null;
  const match = repos.find((r) => issueMatchesRepo(issueRepo, r.name));
  return match ? match.name : null;
}

function filterIssuesToTrackedRepos(
  issues: VATReportIssue[],
  repos: VATReportRepo[],
): VATReportIssue[] {
  if (repos.length === 0) return issues;
  return issues.filter(
    (i) => resolveToTrackedRepoName(i.repository ?? "", repos) !== null,
  );
}

export function issueMatchesContainer(
  issueRepo: string,
  containerName: string,
): boolean {
  const a = (issueRepo ?? "").trim().toLowerCase();
  const b = (containerName ?? "").trim().toLowerCase();
  if (!a || !b) return false;
  if (a === b) return true;
  if (a.endsWith("/" + b)) return true;
  if (b.endsWith("/" + a)) return true;
  return false;
}

export function getEffectiveContainers(
  containers: VATReportRepo[],
  issues: VATReportIssue[],
  codeRepos: VATReportRepo[] = [],
): VATReportRepo[] {
  const openIssues = issues.filter(isOpen);
  const apiNames = new Set(containers.map((c) => c.name.toLowerCase()));
  const derived: VATReportRepo[] = [];
  const emptyContainer = (name: string): VATReportRepo => ({
    id: 0,
    name,
    provider: "",
    issue_count: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
  });
  for (const issue of openIssues) {
    const r = (issue.repository ?? "").trim();
    if (!r) continue;
    if (codeRepos.some((repo) => issueMatchesRepo(r, repo.name))) continue;
    const key = r.toLowerCase();
    if (apiNames.has(key)) continue;
    if (containers.some((c) => issueMatchesContainer(r, c.name))) continue;
    if (derived.some((c) => issueMatchesContainer(r, c.name))) continue;
    apiNames.add(key);
    derived.push(emptyContainer(r));
  }
  return containers.length === 0 && derived.length > 0
    ? derived
    : [...containers, ...derived];
}

export function computeRepoRiskScores(
  issues: VATReportIssue[],
  repos: VATReportRepo[],
  issueGroups: VATReportIssueGroup[] = [],
  countMode: CountMode = "instances",
): RepoRiskScore[] {
  const groupedSeverity = (issue: VATReportIssue) =>
    normalizeSeverity(
      (issue.source_group_severity ?? issue.severity) as string,
      issue.severity_score,
    );
  const repoMap = new Map<string, RepoRiskScore>();
  const openIssues = issues.filter(isOpen);
  const trackedOpenIssues =
    repos.length > 0
      ? filterIssuesToTrackedRepos(openIssues, repos)
      : openIssues;
  const ensureRepo = (name: string) => {
    if (!repoMap.has(name)) {
      repoMap.set(name, {
        repo: name,
        score: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        total: 0,
      });
    }
    return repoMap.get(name)!;
  };
  const repoMitigated = new Map<string, SeverityCounts>();
  if (countMode === "groups") {
    const repoGroupSev = new Map<
      string,
      Map<number, { sev: keyof SeverityCounts; mitigated: boolean }>
    >();
    for (const issue of trackedOpenIssues) {
      const repo =
        repos.length > 0
          ? resolveToTrackedRepoName(issue.repository ?? "", repos) ??
            "Unassigned"
          : issue.repository || "Unassigned";
      const gid = issue.issue_group_id ?? 0;
      if (!repoGroupSev.has(repo)) repoGroupSev.set(repo, new Map());
      const groupMap = repoGroupSev.get(repo)!;
      const sev = groupedSeverity(issue);
      if (sev === "info") continue;
      const existing = groupMap.get(gid);
      const rank = {
        info: 0,
        low: 1,
        medium: 2,
        high: 3,
        critical: 4,
      } as const;
      if (!existing || rank[sev] > rank[existing.sev]) {
        groupMap.set(gid, { sev, mitigated: isMitigated(issue) });
      } else if (existing && rank[sev] === rank[existing.sev]) {
        // Preserve highest severity and keep mitigated=true if any same-severity member is mitigated.
        groupMap.set(gid, {
          sev: existing.sev,
          mitigated: existing.mitigated || isMitigated(issue),
        });
      }
    }
    for (const [repo, groupMap] of Array.from(repoGroupSev)) {
      const entry = ensureRepo(repo);
      const mitigated: SeverityCounts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };
      for (const { sev, mitigated: mit } of Array.from(groupMap.values())) {
        entry.total++;
        if (sev !== "info") {
          if (mit) mitigated[sev]++;
          else
            (entry as unknown as Record<string, number>)[sev] =
              ((entry as unknown as Record<string, number>)[sev] ?? 0) + 1;
        }
      }
      repoMitigated.set(repo, mitigated);
    }
  } else {
    for (const issue of trackedOpenIssues) {
      const repo =
        repos.length > 0
          ? resolveToTrackedRepoName(issue.repository ?? "", repos) ??
            "Unassigned"
          : issue.repository || "Unassigned";
      const entry = ensureRepo(repo);
      entry.total++;
      const sev = normalizeSeverity(issue.severity, issue.severity_score);
      if (sev !== "info") {
        if (isMitigated(issue)) {
          const m = repoMitigated.get(repo) ?? {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
          };
          m[sev]++;
          repoMitigated.set(repo, m);
        } else {
          entry[sev]++;
        }
      }
    }
  }
  if (repoMap.size === 0 || (repoMap.size === 1 && repoMap.has("Unassigned"))) {
    if (issueGroups.length > 0) {
      repoMap.clear();
      for (const group of issueGroups) {
        const sev = normalizeSeverity(group.severity, group.severity_score);
        const count = countMode === "groups" ? 1 : group.issue_count || 1;
        const groupRepos =
          group.affected_repos && group.affected_repos.length > 0
            ? group.affected_repos
            : ["Unassigned"];
        for (const repoName of groupRepos) {
          const entry = ensureRepo(repoName);
          entry.total += count;
          if (sev !== "info") entry[sev] += count;
        }
      }
    }
  }
  for (const repo of repos) ensureRepo(repo.name);
  for (const entry of repoMap.values()) {
    const mitigated = repoMitigated.get(entry.repo);
    entry.score = computeORAPenalty(entry, mitigated);
  }
  return Array.from(repoMap.values()).sort((a, b) => b.score - a.score);
}

export function computeContainerRiskScores(
  containers: VATReportRepo[],
  issues: VATReportIssue[] = [],
  issueGroups: VATReportIssueGroup[] = [],
  countMode: CountMode = "instances",
  codeRepos: VATReportRepo[] = [],
): ContainerRiskScore[] {
  const groupedSeverity = (issue: VATReportIssue) =>
    normalizeSeverity(
      (issue.source_group_severity ?? issue.severity) as string,
      issue.severity_score,
    );
  const effectiveContainers = getEffectiveContainers(
    containers,
    issues,
    codeRepos,
  );
  const openIssues = issues.filter(isOpen);
  return effectiveContainers
    .map((c) => {
      let critical = 0;
      let high = 0;
      let medium = 0;
      let low = 0;
      let mitigatedCritical = 0;
      let mitigatedHigh = 0;
      let mitigatedMedium = 0;
      let mitigatedLow = 0;
      if (openIssues.length > 0) {
        if (countMode === "groups") {
          const groupWorst = new Map<
            number,
            { sev: "critical" | "high" | "medium" | "low"; mitigated: boolean }
          >();
          const rank = { low: 1, medium: 2, high: 3, critical: 4 } as const;
          for (const issue of openIssues) {
            const repo = issue.repository ?? "";
            if (!issueMatchesContainer(repo, c.name)) continue;
            const gid = issue.issue_group_id ?? 0;
            const sev = groupedSeverity(issue);
            if (
              sev === "critical" ||
              sev === "high" ||
              sev === "medium" ||
              sev === "low"
            ) {
              const existing = groupWorst.get(gid);
              if (!existing || rank[sev] > rank[existing.sev]) {
                groupWorst.set(gid, { sev, mitigated: isMitigated(issue) });
              } else if (rank[sev] === rank[existing.sev]) {
                groupWorst.set(gid, {
                  sev: existing.sev,
                  mitigated: existing.mitigated || isMitigated(issue),
                });
              }
            }
          }
          for (const { sev, mitigated: mit } of groupWorst.values()) {
            if (sev === "critical") {
              critical++;
              if (mit) mitigatedCritical++;
            } else if (sev === "high") {
              high++;
              if (mit) mitigatedHigh++;
            } else if (sev === "medium") {
              medium++;
              if (mit) mitigatedMedium++;
            } else if (sev === "low") {
              low++;
              if (mit) mitigatedLow++;
            }
          }
        } else {
          for (const issue of openIssues) {
            const repo = issue.repository ?? "";
            if (!issueMatchesContainer(repo, c.name)) continue;
            const sev = normalizeSeverity(issue.severity, issue.severity_score);
            const mit = isMitigated(issue);
            if (sev === "critical") {
              critical++;
              if (mit) mitigatedCritical++;
            } else if (sev === "high") {
              high++;
              if (mit) mitigatedHigh++;
            } else if (sev === "medium") {
              medium++;
              if (mit) mitigatedMedium++;
            } else if (sev === "low") {
              low++;
              if (mit) mitigatedLow++;
            }
          }
        }
      }
      // Fallback to issue groups only when issue instances are unavailable.
      // If issues are present, groups can include closed/history rows and would
      // re-inflate container counts that correctly resolved to zero from issues.
      if (
        issues.length === 0 &&
        critical + high + medium + low === 0 &&
        issueGroups.length > 0
      ) {
        for (const group of issueGroups) {
          const repos = group.affected_repos ?? [];
          if (!repos.some((r) => issueMatchesContainer(r, c.name))) continue;
          const sev = normalizeSeverity(group.severity, group.severity_score);
          const count = countMode === "groups" ? 1 : group.issue_count ?? 1;
          if (sev === "critical") critical += count;
          else if (sev === "high") high += count;
          else if (sev === "medium") medium += count;
          else if (sev === "low") low += count;
        }
      }
      const total = critical + high + medium + low;
      const counts = {
        critical: critical - mitigatedCritical,
        high: high - mitigatedHigh,
        medium: medium - mitigatedMedium,
        low: low - mitigatedLow,
        info: 0,
      };
      const mitigatedCounts = {
        critical: mitigatedCritical,
        high: mitigatedHigh,
        medium: mitigatedMedium,
        low: mitigatedLow,
      };
      const score = computeORAPenalty(counts, mitigatedCounts);
      return { repo: c.name, score, critical, high, medium, low, total };
    })
    .sort((a, b) => b.score - a.score);
}

export function computeAssetMix(
  issues: VATReportIssue[],
  repos: VATReportRepo[],
  containers: VATReportRepo[],
  vms: VATReportRepo[],
  countMode: CountMode = "groups",
  packageRepos: VATReportRepo[] = [],
): AssetMix {
  const open = issues.filter(isOpen);
  const seenGroups = countMode === "groups" ? new Set<number>() : null;
  let code = 0;
  let container = 0;
  let vm = 0;
  let package_ = 0;
  let other = 0;
  for (const issue of open) {
    if (countMode === "groups" && seenGroups) {
      const gid = issue.issue_group_id ?? 0;
      if (seenGroups.has(gid)) continue;
      seenGroups.add(gid);
    }
    const repo = (issue.repository ?? "").trim();
    if (!repo) {
      other++;
      continue;
    }
    // Prioritize explicit asset matches over heuristic — simple repo names (my-repo, kamiwaza)
    // would otherwise match looksLikePackageOrPath (no slash, no colon) and be misclassified as Package
    if (repos.some((r) => issueMatchesRepo(repo, r.name))) code++;
    else if (containers.some((c) => issueMatchesContainer(repo, c.name)))
      container++;
    else if (vms.some((v) => issueMatchesRepo(repo, v.name))) vm++;
    else if (packageRepos.some((p) => issueMatchesRepo(repo, p.name)))
      package_++;
    else if (looksLikePackageOrPath(repo)) package_++;
    else other++;
  }
  return { code, container, vm, package: package_, other };
}

/** Heuristic: repository looks like a package/path (local folder, SBOM, Helm bundle) rather than container. */
function looksLikePackageOrPath(repo: string): boolean {
  const s = repo.toLowerCase();
  if (s.startsWith("/") || s.startsWith("file:/")) return true; // path
  if (/^(npm|maven|pypi|cargo|go|nuget|composer):/i.test(s)) return true; // ecosystem prefix
  // package@version (no slash) — npm-style; container has org/image:tag (has slash before :)
  if (s.includes("@") && !s.includes("/")) return true;
  // No slash and no colon: container refs are org/image:tag; package/bundle names (e.g. kamiwaza-bundle, Helm charts) are not
  if (!s.includes("/") && !s.includes(":")) return true;
  return false;
}

/** Derive asset type for a single issue from its repository/location.
 * Order must match computeAssetMix: explicit asset matches before heuristic. */
export function getAssetTypeForIssue(
  repository: string | undefined,
  repoNames: string[],
  containerNames: string[],
  vmNames: string[],
  packageNames: string[] = [],
): "Code" | "Container" | "VM" | "Package" | "Other" {
  const repo = (repository ?? "").trim();
  if (!repo) return "Other";
  if (repoNames.some((r) => issueMatchesRepo(repo, r))) return "Code";
  if (containerNames.some((c) => issueMatchesContainer(repo, c)))
    return "Container";
  if (vmNames.some((v) => issueMatchesRepo(repo, v))) return "VM";
  if (packageNames.some((p) => issueMatchesRepo(repo, p))) return "Package";
  if (looksLikePackageOrPath(repo)) return "Package";
  return "Other";
}

export function computeReachabilityMatrix(
  _issues: VATReportIssue[],
  _reachabilityByIssueId?: Record<number, { exploitable?: boolean }>,
  countMode: CountMode = "groups",
): ReachabilityMatrixRow[] {
  return [];
}

export function getIssuesForRepo(
  issues: VATReportIssue[],
  issueGroups: VATReportIssueGroup[],
  repoName: string,
): VATReportIssue[] {
  const directMatch = issues.filter((i) => i.repository === repoName);
  if (directMatch.length > 0) return directMatch;
  const groupIds = new Set<number>();
  for (const g of issueGroups) {
    if (g.affected_repos?.includes(repoName)) groupIds.add(g.group_id);
  }
  if (groupIds.size > 0)
    return issues.filter((i) => groupIds.has(i.issue_group_id));
  return [];
}

export function getIssuesForContainer(
  issues: VATReportIssue[],
  issueGroups: VATReportIssueGroup[],
  containerName: string,
): VATReportIssue[] {
  const matches = (repo: string) => issueMatchesContainer(repo, containerName);
  const directMatch = issues.filter((i) => matches(i.repository ?? ""));
  if (directMatch.length > 0) return directMatch;
  const groupIds = new Set<number>();
  for (const g of issueGroups) {
    if (g.affected_repos?.some((r) => matches(r))) groupIds.add(g.group_id);
  }
  if (groupIds.size > 0)
    return issues.filter((i) => groupIds.has(i.issue_group_id));
  return [];
}

export function getIssuesForRepos(
  issues: VATReportIssue[],
  issueGroups: VATReportIssueGroup[],
  repoNames: string[],
): VATReportIssue[] {
  if (repoNames.length === 0) return issues;
  if (repoNames.length === 1)
    return getIssuesForRepo(issues, issueGroups, repoNames[0]);
  const seen = new Set<number>();
  const result: VATReportIssue[] = [];
  for (const repo of repoNames) {
    const forRepo = getIssuesForRepo(issues, issueGroups, repo);
    for (const i of forRepo) {
      if (!seen.has(i.issue_id)) {
        seen.add(i.issue_id);
        result.push(i);
      }
    }
  }
  return result;
}

/** Unified: match issue by repo or container semantics. Used for asset filter across all types. */
function issueMatchesAsset(issueRepo: string, assetName: string): boolean {
  return (
    issueMatchesRepo(issueRepo, assetName) ||
    issueMatchesContainer(issueRepo, assetName)
  );
}

/** Get issues matching any asset name (repos, containers, packages, VMs, etc.). */
export function getIssuesForAssets(
  issues: VATReportIssue[],
  issueGroups: VATReportIssueGroup[],
  assetNames: string[],
): VATReportIssue[] {
  if (assetNames.length === 0) return issues;
  const seen = new Set<number>();
  const result: VATReportIssue[] = [];
  for (const name of assetNames) {
    const forRepo = getIssuesForRepo(issues, issueGroups, name);
    const forContainer = getIssuesForContainer(issues, issueGroups, name);
    for (const i of [...forRepo, ...forContainer]) {
      if (!seen.has(i.issue_id)) {
        seen.add(i.issue_id);
        result.push(i);
      }
    }
  }
  return result;
}

export function computeMTTR(
  issues: VATReportIssue[],
  countMode: CountMode = "groups",
): MTTRData[] {
  const raw: Array<{ sev: keyof SeverityCounts; gid: number; days: number }> =
    [];
  for (const issue of issues) {
    if (!isClosedIssue(issue) || !issue.first_detected_at) continue;
    const detected = safeDate(issue.first_detected_at);
    const closed = safeDate(issue.closed_at!);
    if (!detected || !closed || closed < detected) continue;
    const days =
      (closed.getTime() - detected.getTime()) / (1000 * 60 * 60 * 24);
    if (!Number.isFinite(days) || days < 0) continue;
    const sev = normalizeSeverity(issue.severity, issue.severity_score);
    raw.push({ sev, gid: issue.issue_group_id ?? 0, days });
  }
  const severityGroups = new Map<string, number[]>();
  if (countMode === "groups") {
    const bestByGroup = new Map<string, number>();
    for (const { sev, gid, days } of raw) {
      const key = `${sev}:${gid}`;
      const prev = bestByGroup.get(key);
      if (prev === undefined || days < prev) bestByGroup.set(key, days);
    }
    for (const [key, days] of bestByGroup) {
      const sev = key.split(":")[0];
      if (!severityGroups.has(sev)) severityGroups.set(sev, []);
      severityGroups.get(sev)!.push(days);
    }
  } else {
    for (const { sev, days } of raw) {
      if (!severityGroups.has(sev)) severityGroups.set(sev, []);
      severityGroups.get(sev)!.push(days);
    }
  }
  return ["critical", "high", "medium", "low", "info"]
    .filter(
      (sev) => severityGroups.has(sev) && severityGroups.get(sev)!.length > 0,
    )
    .map((sev) => {
      const days = severityGroups.get(sev)!.sort((a, b) => a - b);
      const avg = days.reduce((s, d) => s + d, 0) / days.length;
      const mid = Math.floor(days.length / 2);
      const median =
        days.length % 2 === 0 ? (days[mid - 1]! + days[mid]!) / 2 : days[mid]!;
      return {
        severity: sev.charAt(0).toUpperCase() + sev.slice(1),
        avgDays: Number.isFinite(avg) ? Math.round(avg * 10) / 10 : 0,
        medianDays: Number.isFinite(median) ? Math.round(median * 10) / 10 : 0,
        count: days.length,
      };
    });
}

export function computeAgingBuckets(
  issues: VATReportIssue[],
  countMode: CountMode = "groups",
): AgingBucket[] {
  const buckets: AgingBucket[] = [
    { range: "0-7d", critical: 0, high: 0, medium: 0, low: 0 },
    { range: "8-30d", critical: 0, high: 0, medium: 0, low: 0 },
    { range: "31-90d", critical: 0, high: 0, medium: 0, low: 0 },
    { range: "91-180d", critical: 0, high: 0, medium: 0, low: 0 },
    { range: "180d+", critical: 0, high: 0, medium: 0, low: 0 },
  ];
  const seenGroups = countMode === "groups" ? new Set<number>() : null;
  for (const issue of issues.filter(isOpen)) {
    if (countMode === "groups" && seenGroups) {
      const gid = issue.issue_group_id ?? 0;
      if (seenGroups.has(gid)) continue;
      seenGroups.add(gid);
    }
    const age = safeAge(issue.first_detected_at);
    const sev = normalizeSeverity(issue.severity, issue.severity_score);
    if (sev === "info") continue;
    const idx =
      age <= 7 ? 0 : age <= 30 ? 1 : age <= 90 ? 2 : age <= 180 ? 3 : 4;
    buckets[idx]![sev]++;
  }
  return buckets;
}

/** ORA: 0–100, higher = safer. Composite (90% vuln + 10% assumed best for Maintained/DependencyUpdate). */
export function computeRiskScore(counts: SeverityCounts): number {
  const vulnScore = computeORAScore(counts);
  return toDisplayORA(vulnScore);
}

/** Risk level from display ORA score (toDisplayORA output, range 10–100).
 * Converts to raw ORA scale before applying thresholds; fixes scale mismatch. */
export function getRiskLevel(
  score: number,
): "Critical" | "High" | "Medium" | "Low" {
  const rawORA = (score - 10) / 0.9;
  return getORARiskLevel(rawORA);
}

/**
 * Report risk score: inverted ORA for stakeholder intuition.
 * 0 = no risk, 100 = maximum risk. Higher = worse.
 * Uses same ORA weighting; for reports only.
 */
export function computeReportRiskScore(counts: SeverityCounts): number {
  const oraScore = computeORAScore(counts);
  return Math.max(0, Math.min(100, Math.round(100 - oraScore)));
}

/** Risk level from report risk score (higher = worse). */
export function getReportRiskLevel(
  score: number,
): "Critical" | "High" | "Medium" | "Low" {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

function severityOrder(sev: string): number {
  const order: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  return order[sev] ?? 0;
}

export function getTopVulnerabilities(
  issues: VATReportIssue[],
  issueGroups: VATReportIssueGroup[],
  limit = 10,
  countMode: CountMode = "groups",
): TopVulnerability[] {
  const groupMap = new Map<number, VATReportIssueGroup>();
  for (const g of issueGroups) groupMap.set(g.group_id, g);
  const open = issues.filter(isOpen);
  let toSort: VATReportIssue[];
  if (countMode === "groups") {
    const byGroup = new Map<number, VATReportIssue>();
    for (const i of open) {
      const gid = i.issue_group_id ?? 0;
      const existing = byGroup.get(gid);
      const iSev = severityOrder(
        normalizeSeverity(i.severity, i.severity_score),
      );
      const eSev = existing
        ? severityOrder(
            normalizeSeverity(existing.severity, existing.severity_score),
          )
        : -1;
      const iScore = i.severity_score ?? 0;
      const eScore = existing?.severity_score ?? 0;
      const iAge = safeAge(i.first_detected_at);
      const eAge = existing ? safeAge(existing.first_detected_at) : 0;
      if (
        !existing ||
        iSev > eSev ||
        (iSev === eSev &&
          (iScore > eScore || (iScore === eScore && iAge > eAge)))
      ) {
        byGroup.set(gid, i);
      }
    }
    toSort = Array.from(byGroup.values());
  } else {
    toSort = open;
  }
  return toSort
    .map((i) => {
      const group = groupMap.get(i.issue_group_id);
      return {
        id: i.issue_id || i.issue_group_id,
        title: i.title,
        severity: normalizeSeverity(i.severity, i.severity_score),
        cve: i.cve_id || "N/A",
        repo: i.repository || "Unknown",
        age: safeAge(i.first_detected_at),
        score: i.severity_score || 0,
        hasTask: group?.has_task ?? false,
        sourceUrl: i.source_url || group?.source_url,
      };
    })
    .sort(
      (a, b) =>
        severityOrder(b.severity) - severityOrder(a.severity) ||
        b.score - a.score ||
        b.age - a.age,
    )
    .slice(0, limit);
}

export function computeAvgMttr(mttrData: MTTRData[]): number | undefined {
  if (mttrData.length === 0) return undefined;
  const totalCount = mttrData.reduce((s, m) => s + m.count, 0);
  if (totalCount === 0) return undefined;
  const weighted =
    mttrData.reduce((s, m) => s + m.avgDays * m.count, 0) / totalCount;
  return Number.isFinite(weighted) ? Math.round(weighted * 10) / 10 : undefined;
}

export interface SlaComplianceResult {
  withinSla: number;
  exceedingSla: number;
  total: number;
  pctCompliant: number;
  bySeverity: Array<{ severity: string; within: number; exceeding: number }>;
}

/** ABC SLA days (remediation from detection). Override via config. */
const ABC_SLA_DAYS = {
  critical: 15,
  high: 35,
  medium: 180,
  low: 360,
  info: 365,
} as const;

export function computeSlaCompliance(
  issues: VATReportIssue[],
  config: {
    criticalDays?: number;
    highDays?: number;
    mediumDays?: number;
    lowDays?: number;
  } = {},
  countMode: CountMode = "groups",
): SlaComplianceResult {
  const criticalDays = config.criticalDays ?? ABC_SLA_DAYS.critical;
  const highDays = config.highDays ?? ABC_SLA_DAYS.high;
  const mediumDays = config.mediumDays ?? ABC_SLA_DAYS.medium;
  const lowDays = config.lowDays ?? ABC_SLA_DAYS.low;
  const slaBySeverity: Record<string, number> = {
    critical: criticalDays,
    high: highDays,
    medium: mediumDays,
    low: lowDays,
    info: 365,
  };
  const open = issues.filter(isOpen);
  // In groups mode, evaluate SLA against the group's worst (max-severity)
  // instance and its earliest first_detected_at. Otherwise the bucket would
  // depend on iteration order and disagree with the executive summary KPIs
  // for the same group.
  const evaluables: Array<{ severity: string; ageDays: number }> = [];
  if (countMode === "groups") {
    const byGroup = new Map<
      number,
      { rep: VATReportIssue; earliestDetectedAt: string | undefined }
    >();
    for (const issue of open) {
      const gid = issue.issue_group_id ?? 0;
      const iSev = severityRank(
        normalizeSeverity(issue.severity, issue.severity_score),
      );
      const prev = byGroup.get(gid);
      const pSev = prev
        ? severityRank(
            normalizeSeverity(prev.rep.severity, prev.rep.severity_score),
          )
        : -1;
      // Track earliest first_detected_at independent of severity — SLA aging
      // should reflect when the group first appeared, not when the worst
      // instance was added.
      const earliest =
        prev && prev.earliestDetectedAt
          ? safeDate(issue.first_detected_at) &&
            safeDate(prev.earliestDetectedAt)! >
              safeDate(issue.first_detected_at!)!
            ? issue.first_detected_at
            : prev.earliestDetectedAt
          : issue.first_detected_at;
      if (!prev || iSev > pSev) {
        byGroup.set(gid, { rep: issue, earliestDetectedAt: earliest });
      } else {
        prev.earliestDetectedAt = earliest;
      }
    }
    for (const { rep, earliestDetectedAt } of Array.from(byGroup.values())) {
      evaluables.push({
        severity: normalizeSeverity(rep.severity, rep.severity_score),
        ageDays: safeAge(earliestDetectedAt ?? rep.first_detected_at),
      });
    }
  } else {
    for (const issue of open) {
      evaluables.push({
        severity: normalizeSeverity(issue.severity, issue.severity_score),
        ageDays: safeAge(issue.first_detected_at),
      });
    }
  }
  let withinSla = 0;
  let exceedingSla = 0;
  const bySev: Record<string, { within: number; exceeding: number }> = {};
  for (const { severity: sev, ageDays: age } of evaluables) {
    const limit = slaBySeverity[sev] ?? 365;
    const compliant = age <= limit;
    if (compliant) withinSla++;
    else exceedingSla++;
    if (!bySev[sev]) bySev[sev] = { within: 0, exceeding: 0 };
    if (compliant) bySev[sev]!.within++;
    else bySev[sev]!.exceeding++;
  }
  const total = withinSla + exceedingSla;
  const pctCompliant = total > 0 ? Math.round((withinSla / total) * 100) : 100;
  const bySeverity = ["critical", "high", "medium", "low", "info"]
    .filter((s) => (bySev[s]?.within ?? 0) + (bySev[s]?.exceeding ?? 0) > 0)
    .map((s) => ({
      severity: s,
      within: bySev[s]?.within ?? 0,
      exceeding: bySev[s]?.exceeding ?? 0,
    }));
  return { withinSla, exceedingSla, total, pctCompliant, bySeverity };
}

/** ABC compliance for VAT issues. Uses SLAs, max counts, CVE age tolerance. */
export function computeABCComplianceForIssues(
  issues: VATReportIssue[],
  countMode: CountMode = "groups",
): ABCCriteriaResult {
  const open = issues.filter(isOpen);
  const inputs: ABCIssueInput[] = [];
  if (countMode === "groups") {
    // Use the group's worst (max-severity) instance as the ABC representative.
    // The compliance bucket otherwise depended on iteration order, breaking
    // parity with the executive summary KPIs derived from
    // computeSeverityCountsByGroups.
    const byGroup = new Map<number, VATReportIssue>();
    for (const i of open) {
      const gid = i.issue_group_id ?? 0;
      const prev = byGroup.get(gid);
      const iSev = severityRank(
        normalizeSeverity(i.severity, i.severity_score),
      );
      const pSev = prev
        ? severityRank(normalizeSeverity(prev.severity, prev.severity_score))
        : -1;
      if (!prev || iSev > pSev) byGroup.set(gid, i);
    }
    for (const i of Array.from(byGroup.values())) {
      const vatIssue = i as VATReportIssue & {
        cve_published_at?: string | null;
      };
      inputs.push({
        severity: i.severity ?? "",
        severityScore: i.severity_score,
        firstDetectedAt: i.first_detected_at ?? "",
        cvePublishedAt: vatIssue.cve_published_at,
        status: i.status ?? "",
      });
    }
  } else {
    for (const i of open) {
      const vatIssue = i as VATReportIssue & {
        cve_published_at?: string | null;
      };
      inputs.push({
        severity: i.severity ?? "",
        severityScore: i.severity_score,
        firstDetectedAt: i.first_detected_at ?? "",
        cvePublishedAt: vatIssue.cve_published_at,
        status: i.status ?? "",
      });
    }
  }
  return computeABCCompliance(inputs);
}

export interface TrendMetrics {
  currentOpen: number;
  openOneWeekAgo: number;
  resolvedThisWeek: number;
  resolvedLastWeek: number;
  newThisWeek: number;
  newLastWeek: number;
}

function getCalendarWeekBounds(now: Date): {
  thisWeekStart: Date;
  thisWeekEnd: Date;
  lastWeekStart: Date;
  lastWeekEnd: Date;
} {
  const day = now.getDay();
  const diff = (day - 1 + 7) % 7;
  const thisWeekStart = new Date(now);
  thisWeekStart.setDate(now.getDate() - diff);
  thisWeekStart.setHours(0, 0, 0, 0);
  const thisWeekEnd = new Date(thisWeekStart);
  thisWeekEnd.setDate(thisWeekStart.getDate() + 6);
  thisWeekEnd.setHours(23, 59, 59, 999);
  const lastWeekStart = new Date(thisWeekStart);
  lastWeekStart.setDate(thisWeekStart.getDate() - 7);
  const lastWeekEnd = new Date(lastWeekStart);
  lastWeekEnd.setDate(lastWeekStart.getDate() + 6);
  lastWeekEnd.setHours(23, 59, 59, 999);
  return { thisWeekStart, thisWeekEnd, lastWeekStart, lastWeekEnd };
}

/** Calendar week (Mon–Sun) in UTC. Use to match Aikido dashboard. */
function getCalendarWeekBoundsUtc(now: Date): {
  thisWeekStart: Date;
  thisWeekEnd: Date;
  lastWeekStart: Date;
  lastWeekEnd: Date;
} {
  const day = now.getUTCDay();
  const diff = (day - 1 + 7) % 7;
  const thisWeekStart = new Date(
    Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate() - diff,
      0,
      0,
      0,
      0,
    ),
  );
  const thisWeekEnd = new Date(thisWeekStart);
  thisWeekEnd.setUTCDate(thisWeekStart.getUTCDate() + 6);
  thisWeekEnd.setUTCHours(23, 59, 59, 999);
  const lastWeekStart = new Date(thisWeekStart);
  lastWeekStart.setUTCDate(thisWeekStart.getUTCDate() - 7);
  const lastWeekEnd = new Date(lastWeekStart);
  lastWeekEnd.setUTCDate(lastWeekStart.getUTCDate() + 6);
  lastWeekEnd.setUTCHours(23, 59, 59, 999);
  return { thisWeekStart, thisWeekEnd, lastWeekStart, lastWeekEnd };
}

export function computeTrendMetrics(
  issues: VATReportIssue[],
  countMode: CountMode = "groups",
): TrendMetrics {
  const trendIssues = issuesForTrend(issues);
  const now = new Date();
  const { thisWeekStart, thisWeekEnd, lastWeekStart, lastWeekEnd } =
    getCalendarWeekBoundsUtc(now);
  const current = openAtDate(trendIssues, now);
  const previous = openAtDate(trendIssues, lastWeekEnd);
  const currentOpen =
    countMode === "groups"
      ? (() => {
          const counts = computeSeverityCountsByGroups(current.issues);
          return (
            counts.critical +
            counts.high +
            counts.medium +
            counts.low +
            counts.info
          );
        })()
      : current.total;
  const openOneWeekAgo =
    countMode === "groups"
      ? (() => {
          const counts = computeSeverityCountsByGroups(previous.issues);
          return (
            counts.critical +
            counts.high +
            counts.medium +
            counts.low +
            counts.info
          );
        })()
      : previous.total;
  const thisStartTs = thisWeekStart.getTime();
  const thisEndTs = thisWeekEnd.getTime();
  const lastStartTs = lastWeekStart.getTime();
  const lastEndTs = lastWeekEnd.getTime();
  let resolvedThisWeek = 0;
  let resolvedLastWeek = 0;
  let newThisWeek = 0;
  let newLastWeek = 0;
  // "New" = first detections in window, excluding ignored/auto_ignored/suppressed (matches Aikido).
  // VAT maps Aikido "ignored" → "Suppressed", so we must exclude suppressed to align with vulnerability-dashboard.
  const excludeNewStatuses = ["ignored", "auto_ignored", "suppressed"] as const;
  if (countMode === "groups") {
    // Groups mode: a group is "resolved this week" iff every instance is
    // closed AND the latest closure timestamp falls in the window — i.e. the
    // group transitioned off the open queue during the window. Mirrors the
    // group-deduped semantics of currentOpen/openOneWeekAgo above.
    const groupClosure = new Map<
      number,
      { allClosed: boolean; latestClosedTs: number }
    >();
    for (const i of trendIssues) {
      const gid = i.issue_group_id ?? 0;
      const open = isOpen(i);
      const closedTs =
        isClosedIssue(i) && i.closed_at
          ? (safeDate(i.closed_at)?.getTime() ?? null)
          : null;
      const prev = groupClosure.get(gid);
      if (!prev) {
        groupClosure.set(gid, {
          allClosed: !open,
          latestClosedTs: closedTs ?? -Infinity,
        });
      } else {
        if (open) prev.allClosed = false;
        if (closedTs !== null && closedTs > prev.latestClosedTs)
          prev.latestClosedTs = closedTs;
      }
    }
    for (const { allClosed, latestClosedTs } of groupClosure.values()) {
      if (!allClosed || latestClosedTs === -Infinity) continue;
      if (latestClosedTs >= thisStartTs && latestClosedTs <= thisEndTs)
        resolvedThisWeek++;
      else if (latestClosedTs >= lastStartTs && latestClosedTs <= lastEndTs)
        resolvedLastWeek++;
    }
    // Groups mode: a group is "new this week" iff the earliest first
    // detection across its non-excluded instances falls in the window. A
    // group already detected before the window doesn't count as new even if
    // additional instances appear later.
    const groupFirstDet = new Map<number, number>();
    for (const i of issues) {
      const st = (i.status ?? "").toLowerCase();
      if (
        excludeNewStatuses.includes(st as (typeof excludeNewStatuses)[number])
      )
        continue;
      const det = safeDate(i.first_detected_at);
      if (!det) continue;
      const gid = i.issue_group_id ?? 0;
      const ts = det.getTime();
      const prev = groupFirstDet.get(gid);
      if (prev === undefined || ts < prev) groupFirstDet.set(gid, ts);
    }
    for (const ts of Array.from(groupFirstDet.values())) {
      if (ts >= thisStartTs && ts <= thisEndTs) newThisWeek++;
      else if (ts >= lastStartTs && ts <= lastEndTs) newLastWeek++;
    }
  } else {
    // Instances mode: per-finding closure and detection events.
    // "Closed" matches VAT's product scope of triage + risk acceptance +
    // remediation: suppressions, false-positives, approvals all count as
    // "off the open queue". Aligns with computeMTTR (same isClosedIssue).
    for (const i of trendIssues) {
      if (!isClosedIssue(i)) continue;
      const closed = safeDate(i.closed_at!);
      if (!closed) continue;
      const ts = closed.getTime();
      if (ts >= thisStartTs && ts <= thisEndTs) resolvedThisWeek++;
      else if (ts >= lastStartTs && ts <= lastEndTs) resolvedLastWeek++;
    }
    for (const i of issues) {
      const st = (i.status ?? "").toLowerCase();
      if (
        excludeNewStatuses.includes(st as (typeof excludeNewStatuses)[number])
      )
        continue;
      const det = safeDate(i.first_detected_at);
      if (det) {
        const ts = det.getTime();
        if (ts >= thisStartTs && ts <= thisEndTs) newThisWeek++;
        else if (ts >= lastStartTs && ts <= lastEndTs) newLastWeek++;
      }
    }
  }
  return {
    currentOpen,
    openOneWeekAgo,
    resolvedThisWeek,
    resolvedLastWeek,
    newThisWeek,
    newLastWeek,
  };
}
