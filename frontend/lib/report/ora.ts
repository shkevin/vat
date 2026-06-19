/**
 * ORA (Overall Risk Assessment) and ABC (Acceptance Baseline Criteria) constants.
 *
 * ORA: Start at 100, subtract penalties. Higher score = safer (100 best, 0 worst).
 * ABC: SLA timelines, max counts, CVE age tolerance per severity.
 */

import { isOpenRisk } from "@/lib/metricSemantics";

export interface SeverityCountsLike {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
}

/** ORA severity weights (penalty per finding). */
export const ORA_WEIGHTS = {
  critical: 10,
  high: 4,
  medium: 0.5,
  low: 0.25,
} as const;

/** ORA caps: low total penalty ≤ 10, medium total penalty ≤ 30. */
export const ORA_CAPS = {
  low: 10,
  medium: 30,
} as const;

/** Mitigated findings impart half the usual penalty. */
export const ORA_MITIGATED_FACTOR = 0.5;

/** ABC: CVSS score ranges → severity. */
export const ABC_CVSS_RANGES = {
  critical: { min: 9.0, max: 10.0 },
  high: { min: 7.0, max: 8.9 },
  medium: { min: 4.0, max: 6.9 },
  low: { min: 0.1, max: 3.9 },
} as const;

/** ABC: Max open findings per severity before CVE age tolerance applies. */
export const ABC_MAX_COUNTS = {
  critical: 1,
  high: 4,
  medium: undefined,
  low: undefined,
} as const;

/** ABC: Justification deadline in calendar days from detection. */
export const ABC_JUSTIFICATION_DAYS = {
  critical: 5,
  high: 10,
  medium: 30,
  low: 60,
} as const;

/** ABC: Mitigation/remediation deadline in calendar days from detection. */
export const ABC_REMEDIATION_DAYS = {
  critical: 15,
  high: 35,
  medium: 180,
  low: 360,
} as const;

/** ABC: CVE age tolerance (published date) in calendar days. */
export const ABC_CVE_AGE_TOLERANCE_DAYS = {
  critical: 90,
  high: 180,
  medium: undefined,
  low: undefined,
} as const;

/**
 * Compute ORA penalty from severity counts.
 * @param counts - Open finding counts by severity (excludes false positives, resolved, etc.)
 * @param mitigatedCounts - Optional counts of mitigated (not remediated) findings; each imparts half penalty
 */
export function computeORAPenalty(
  counts: SeverityCountsLike,
  mitigatedCounts?: Partial<SeverityCountsLike>,
): number {
  let penalty = 0;

  penalty += (counts.critical ?? 0) * ORA_WEIGHTS.critical;
  penalty +=
    (mitigatedCounts?.critical ?? 0) *
    ORA_WEIGHTS.critical *
    ORA_MITIGATED_FACTOR;

  penalty += (counts.high ?? 0) * ORA_WEIGHTS.high;
  penalty +=
    (mitigatedCounts?.high ?? 0) * ORA_WEIGHTS.high * ORA_MITIGATED_FACTOR;

  const medTotal =
    (counts.medium ?? 0) * ORA_WEIGHTS.medium +
    (mitigatedCounts?.medium ?? 0) * ORA_WEIGHTS.medium * ORA_MITIGATED_FACTOR;
  penalty += Math.min(medTotal, ORA_CAPS.medium);

  const lowTotal =
    (counts.low ?? 0) * ORA_WEIGHTS.low +
    (mitigatedCounts?.low ?? 0) * ORA_WEIGHTS.low * ORA_MITIGATED_FACTOR;
  penalty += Math.min(lowTotal, ORA_CAPS.low);

  return penalty;
}

/**
 * Compute ORA vulnerability component (0-100). Start at 100, subtract penalty.
 * Higher = safer. Clamped to [0, 100].
 */
export function computeORAScore(
  counts: SeverityCountsLike,
  mitigatedCounts?: Partial<SeverityCountsLike>,
): number {
  const penalty = computeORAPenalty(counts, mitigatedCounts);
  return Math.max(0, Math.min(100, Math.round(100 - penalty)));
}

/**
 * Full ORA = 5% Maintained + 90% Vulnerabilities + 5% Dependency Update Tool.
 * VAT only has the Vulnerabilities component. When Maintained and Dependency Update are
 * unknown, assume best case (100 each).
 * Result: 0.9 * vulnScore + 10. E.g. vulnScore 0 → 10, vulnScore 100 → 100.
 */
export function toDisplayORA(vulnerabilityScore: number): number {
  const v = Math.max(0, Math.min(100, vulnerabilityScore));
  return Math.round(0.9 * v + 10);
}

/** Risk level from ORA score. Lower score = higher risk. */
export function getORARiskLevel(
  score: number,
): "Critical" | "High" | "Medium" | "Low" {
  if (score < 25) return "Critical";
  if (score < 50) return "High";
  if (score < 75) return "Medium";
  return "Low";
}

export interface ABCCriteriaResult {
  compliant: boolean;
  maxCountExceeded: { critical: boolean; high: boolean };
  justificationOverdue: number;
  remediationOverdue: number;
  cveAgeExceeded: number;
  bySeverity: Record<
    string,
    {
      count: number;
      maxCount?: number;
      justificationOverdue: number;
      remediationOverdue: number;
      cveAgeExceeded: number;
    }
  >;
}

export interface ABCIssueInput {
  severity: string;
  severityScore?: number;
  firstDetectedAt: string;
  cvePublishedAt?: string | null;
  status: string;
  isMitigated?: boolean;
}

function toSevKey(severity: string, score?: number): keyof SeverityCountsLike {
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

function daysSince(dateStr: string): number {
  const ts = new Date(dateStr).getTime();
  if (Number.isNaN(ts)) return 0;
  return Math.round((Date.now() - ts) / (1000 * 60 * 60 * 24));
}

/**
 * Compute ABC compliance for a set of open findings.
 */
export function computeABCCompliance(
  issues: ABCIssueInput[],
): ABCCriteriaResult {
  const open = issues.filter((i) => isOpenRisk(i.status));

  const bySev: Record<
    string,
    {
      count: number;
      maxCount?: number;
      justificationOverdue: number;
      remediationOverdue: number;
      cveAgeExceeded: number;
    }
  > = {
    critical: {
      count: 0,
      maxCount: ABC_MAX_COUNTS.critical,
      justificationOverdue: 0,
      remediationOverdue: 0,
      cveAgeExceeded: 0,
    },
    high: {
      count: 0,
      maxCount: ABC_MAX_COUNTS.high,
      justificationOverdue: 0,
      remediationOverdue: 0,
      cveAgeExceeded: 0,
    },
    medium: {
      count: 0,
      justificationOverdue: 0,
      remediationOverdue: 0,
      cveAgeExceeded: 0,
    },
    low: {
      count: 0,
      justificationOverdue: 0,
      remediationOverdue: 0,
      cveAgeExceeded: 0,
    },
  };

  let justificationOverdue = 0;
  let remediationOverdue = 0;
  let cveAgeExceeded = 0;

  for (const i of open) {
    const sev = toSevKey(i.severity, i.severityScore);
    if (sev === "info") continue;

    const entry = bySev[sev];
    if (!entry) continue;
    entry.count++;

    const daysSinceDetection = daysSince(i.firstDetectedAt);
    const cveAge = i.cvePublishedAt
      ? daysSince(i.cvePublishedAt)
      : daysSinceDetection;

    const justDays =
      ABC_JUSTIFICATION_DAYS[sev as keyof typeof ABC_JUSTIFICATION_DAYS];
    const remDays =
      ABC_REMEDIATION_DAYS[sev as keyof typeof ABC_REMEDIATION_DAYS];
    const ageTol =
      ABC_CVE_AGE_TOLERANCE_DAYS[
        sev as keyof typeof ABC_CVE_AGE_TOLERANCE_DAYS
      ];

    if (justDays !== undefined && daysSinceDetection > justDays) {
      entry.justificationOverdue++;
      justificationOverdue++;
    }
    if (remDays !== undefined && daysSinceDetection > remDays) {
      entry.remediationOverdue++;
      remediationOverdue++;
    }
    if (ageTol !== undefined && cveAge > ageTol) {
      entry.cveAgeExceeded++;
      cveAgeExceeded++;
    }
  }

  const maxCountExceeded = {
    critical:
      (bySev.critical?.count ?? 0) > (ABC_MAX_COUNTS.critical ?? Infinity),
    high: (bySev.high?.count ?? 0) > (ABC_MAX_COUNTS.high ?? Infinity),
  };

  const compliant =
    !maxCountExceeded.critical &&
    !maxCountExceeded.high &&
    justificationOverdue === 0 &&
    remediationOverdue === 0 &&
    cveAgeExceeded === 0;

  return {
    compliant,
    maxCountExceeded,
    justificationOverdue,
    remediationOverdue,
    cveAgeExceeded,
    bySeverity: bySev,
  };
}
