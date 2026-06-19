/**
 * Report metrics tests — verify Open count respects countMode (groups vs instances).
 * When 3 findings exist with 2 in one group and 1 in another:
 * - countMode "groups" → totalOpen = 2
 * - countMode "instances" → totalOpen = 3
 */

import { describe, it, expect } from "vitest";
import {
  resolveOpenCounts,
  getRiskLevel,
  computeRiskScore,
  computeContainerRiskScores,
  computeMTTR,
  computeTrendMetrics,
  isClosedIssue,
  computeScannerBreakdown,
  computeSlaCompliance,
  computeFleetRiskScore,
  computePeriodOverPeriodChange,
  computeABCComplianceForIssues,
} from "./metrics";
import { computeABCCompliance } from "./ora";
import type { VATReportIssue, VATReportIssueGroup } from "./vatReportAdapter";

function mkIssue(
  issueId: number,
  groupId: number,
  status = "open",
): VATReportIssue {
  return {
    issue_id: issueId,
    issue_group_id: groupId,
    first_detected_at: "2024-01-01T00:00:00Z",
    last_detected_at: "2024-01-01T00:00:00Z",
    repository: "test-repo",
    severity: "high",
    severity_score: 8,
    status,
    title: `Issue ${issueId}`,
  };
}

function mkGroup(groupId: number, severity = "high"): VATReportIssueGroup {
  return {
    group_id: groupId,
    title: `Group ${groupId}`,
    severity,
    severity_score: 8,
    status: "open",
    first_detected_at: "2024-01-01T00:00:00Z",
    issue_count: groupId === 1 ? 2 : 1,
    affected_repos: ["test-repo"],
    scanner_type: "VAT",
    has_task: false,
    source_url: "",
  };
}

describe("resolveOpenCounts countMode", () => {
  it("returns 2 when countMode is groups and 3 issues span 2 groups", () => {
    const issues: VATReportIssue[] = [
      mkIssue(1, 1),
      mkIssue(2, 1),
      mkIssue(3, 2),
    ];
    const groups: VATReportIssueGroup[] = [mkGroup(1), mkGroup(2)];
    const result = resolveOpenCounts(issues, {
      countMode: "groups",
      issueGroups: groups,
    });
    expect(result.totalOpen).toBe(2);
    expect(result.source).toBe("computed-groups-from-groups");
  });

  it("returns 3 when countMode is instances and 3 issues span 2 groups", () => {
    const issues: VATReportIssue[] = [
      mkIssue(1, 1),
      mkIssue(2, 1),
      mkIssue(3, 2),
    ];
    const result = resolveOpenCounts(issues, { countMode: "instances" });
    expect(result.totalOpen).toBe(3);
    expect(result.source).toBe("computed-instances");
  });

  it("groups mode without issueGroups falls back to computed-groups", () => {
    const issues: VATReportIssue[] = [
      mkIssue(1, 1),
      mkIssue(2, 1),
      mkIssue(3, 2),
    ];
    const result = resolveOpenCounts(issues, { countMode: "groups" });
    expect(result.totalOpen).toBe(2);
    expect(result.source).toBe("computed-groups");
  });
});

describe("getRiskLevel display-scale thresholds", () => {
  it("maps display score 10 (worst) to Critical", () => {
    expect(getRiskLevel(10)).toBe("Critical");
  });
  it("maps display score 32 (raw ~24) to Critical, not High", () => {
    expect(getRiskLevel(32)).toBe("Critical");
  });
  it("maps display score 54 (raw < 50) to High", () => {
    expect(getRiskLevel(54)).toBe("High");
  });
  it("maps display score 55 (raw 50) to Medium (boundary)", () => {
    expect(getRiskLevel(55)).toBe("Medium");
  });
  it("maps display score 77 (raw ~75) to Medium", () => {
    expect(getRiskLevel(77)).toBe("Medium");
  });
  it("maps display score 100 (best) to Low", () => {
    expect(getRiskLevel(100)).toBe("Low");
  });
  it("matches computeRiskScore for severe counts", () => {
    const score = computeRiskScore({
      critical: 39,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    });
    expect(score).toBe(10);
    expect(getRiskLevel(score)).toBe("Critical");
  });
});

describe("computeContainerRiskScores source of truth", () => {
  it("recomputes grouped counts from issues instead of pre-aggregated container counts", () => {
    const containers = [
      {
        id: 1,
        name: "containers/images/demo",
        provider: "vat",
        issue_count: 999,
        critical_count: 500,
        high_count: 400,
        medium_count: 99,
        low_count: 0,
      },
    ];
    const issues: VATReportIssue[] = [
      {
        issue_id: 1,
        issue_group_id: 10,
        first_detected_at: "2024-01-01T00:00:00Z",
        last_detected_at: "2024-01-01T00:00:00Z",
        repository: "containers/images/demo",
        severity: "high",
        severity_score: 8,
        status: "open",
        title: "Issue A",
      },
      {
        issue_id: 2,
        issue_group_id: 10,
        first_detected_at: "2024-01-01T00:00:00Z",
        last_detected_at: "2024-01-01T00:00:00Z",
        repository: "containers/images/demo",
        severity: "high",
        severity_score: 8,
        status: "open",
        title: "Issue A duplicate instance",
      },
    ];
    const scores = computeContainerRiskScores(
      containers,
      issues,
      [],
      "groups",
      [],
    );
    expect(scores).toHaveLength(1);
    expect(scores[0].critical).toBe(0);
    expect(scores[0].high).toBe(1);
    expect(scores[0].medium).toBe(0);
    expect(scores[0].low).toBe(0);
    expect(scores[0].total).toBe(1);
  });

  it("does not fallback to issueGroups when issue instances are present", () => {
    const containers = [
      {
        id: 1,
        name: "containers/images/cert-manager-acmesolver-fips",
        provider: "vat",
        issue_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
      },
    ];
    const issues: VATReportIssue[] = [
      {
        issue_id: 99,
        issue_group_id: 99,
        first_detected_at: "2026-03-01T00:00:00Z",
        last_detected_at: "2026-03-01T00:00:00Z",
        repository: "containers/images/some-other-container",
        severity: "low",
        severity_score: 3,
        status: "open",
        title: "Other container issue",
      },
    ];
    const issueGroups: VATReportIssueGroup[] = [
      {
        group_id: 501,
        title: "Historical group row",
        severity: "critical",
        severity_score: 10,
        status: "resolved",
        first_detected_at: "2026-01-01T00:00:00Z",
        issue_count: 4,
        affected_repos: ["containers/images/cert-manager-acmesolver-fips"],
        scanner_type: "VAT",
        has_task: false,
        source_url: "",
      },
    ];
    const scores = computeContainerRiskScores(
      containers,
      issues,
      issueGroups,
      "instances",
      [],
    );
    const target = scores.find(
      (s) => s.repo === "containers/images/cert-manager-acmesolver-fips",
    );
    expect(target).toBeTruthy();
    expect(target?.critical).toBe(0);
    expect(target?.high).toBe(0);
    expect(target?.medium).toBe(0);
    expect(target?.low).toBe(0);
    expect(target?.total).toBe(0);
  });

  it("uses worst severity per group in grouped mode", () => {
    const containers = [
      {
        id: 1,
        name: "containers/images/demo",
        provider: "vat",
        issue_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
      },
    ];
    const issues: VATReportIssue[] = [
      {
        issue_id: 1,
        issue_group_id: 77,
        first_detected_at: "2026-03-01T00:00:00Z",
        last_detected_at: "2026-03-01T00:00:00Z",
        repository: "containers/images/demo",
        severity: "medium",
        severity_score: 5,
        status: "open",
        title: "same group medium",
      },
      {
        issue_id: 2,
        issue_group_id: 77,
        first_detected_at: "2026-03-01T00:00:00Z",
        last_detected_at: "2026-03-01T00:00:00Z",
        repository: "containers/images/demo",
        severity: "critical",
        severity_score: 10,
        status: "open",
        title: "same group critical",
      },
    ];
    const scores = computeContainerRiskScores(
      containers,
      issues,
      [],
      "groups",
      [],
    );
    expect(scores).toHaveLength(1);
    expect(scores[0].critical).toBe(1);
    expect(scores[0].high).toBe(0);
    expect(scores[0].medium).toBe(0);
    expect(scores[0].low).toBe(0);
    expect(scores[0].total).toBe(1);
  });

  it("prefers source_group_severity for grouped container parity", () => {
    const containers = [
      {
        id: 1,
        name: "kamiwaza/images/core",
        provider: "vat",
        issue_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
      },
    ];
    const issues: VATReportIssue[] = [
      {
        issue_id: 1,
        issue_group_id: 5001,
        first_detected_at: "2026-03-01T00:00:00Z",
        last_detected_at: "2026-03-01T00:00:00Z",
        repository: "kamiwaza/images/core",
        severity: "low",
        source_group_severity: "high",
        severity_score: 3,
        status: "open",
        title: "group row with higher source severity",
      },
    ];
    const scores = computeContainerRiskScores(
      containers,
      issues,
      [],
      "groups",
      [],
    );
    expect(scores).toHaveLength(1);
    expect(scores[0].critical).toBe(0);
    expect(scores[0].high).toBe(1);
    expect(scores[0].medium).toBe(0);
    expect(scores[0].low).toBe(0);
  });
});

describe("isClosedIssue / unified resolved-vs-closed semantics", () => {
  // VAT's product scope treats triage, risk acceptance, and remediation as
  // peer outcomes. Any EXCLUDED_OPEN_STATUS with a closed_at timestamp is
  // "closed" — MTTR and "Closed this week" must agree.
  it("counts both Resolved and Suppressed findings as closed", () => {
    expect(
      isClosedIssue({
        ...mkIssue(1, 1, "Resolved"),
        closed_at: "2026-04-20T12:00:00Z",
      }),
    ).toBe(true);
    expect(
      isClosedIssue({
        ...mkIssue(2, 2, "Suppressed"),
        closed_at: "2026-04-20T12:00:00Z",
      }),
    ).toBe(true);
    expect(
      isClosedIssue({
        ...mkIssue(3, 3, "False Positive"),
        closed_at: "2026-04-20T12:00:00Z",
      }),
    ).toBe(true);
  });
  it("does NOT count Open findings or findings missing closed_at", () => {
    expect(isClosedIssue(mkIssue(1, 1, "Open"))).toBe(false);
    // status is closed but no closed_at — should not count
    expect(
      isClosedIssue({
        ...mkIssue(1, 1, "Resolved"),
        closed_at: undefined as unknown as string,
      }),
    ).toBe(false);
  });

  it("computeTrendMetrics counts Suppressed closures in 'resolved this week'", () => {
    // computeTrendMetrics uses Mon–Sun UTC weeks. `now - 2 days` lands in
    // last week on Mondays/Tuesdays, so use `now` itself which is always
    // inside [thisWeekStart, thisWeekEnd].
    const tsThisWeek = new Date().toISOString();

    const issues: VATReportIssue[] = [
      // 1 resolved + 2 suppressed + 1 false-positive, all closed this week
      {
        ...mkIssue(1, 1, "Resolved"),
        first_detected_at: "2024-01-01T00:00:00Z",
        closed_at: tsThisWeek,
      },
      {
        ...mkIssue(2, 2, "Suppressed"),
        first_detected_at: "2024-01-01T00:00:00Z",
        closed_at: tsThisWeek,
      },
      {
        ...mkIssue(3, 3, "Suppressed"),
        first_detected_at: "2024-01-01T00:00:00Z",
        closed_at: tsThisWeek,
      },
      {
        ...mkIssue(4, 4, "False Positive"),
        first_detected_at: "2024-01-01T00:00:00Z",
        closed_at: tsThisWeek,
      },
      // 1 currently open — should not be counted as closed
      mkIssue(5, 5, "Open"),
    ];
    const metrics = computeTrendMetrics(issues, "instances");
    // Before PR 2: only the Resolved one (1). After PR 2: all 4 closures count.
    expect(metrics.resolvedThisWeek).toBe(4);
  });

  it("computeTrendMetrics groups mode: resolved counts groups whose last open instance closed in window", () => {
    const thisWeekTs = new Date().toISOString();
    const longAgo = "2024-01-01T00:00:00Z";

    const issues: VATReportIssue[] = [
      // Group 1: 2 instances, both closed; latest closed_at is this week → counts as 1
      {
        ...mkIssue(1, 1, "Resolved"),
        first_detected_at: longAgo,
        closed_at: longAgo,
      },
      {
        ...mkIssue(2, 1, "Resolved"),
        first_detected_at: longAgo,
        closed_at: thisWeekTs,
      },
      // Group 2: 1 closed this week + 1 still open → group not fully closed, NOT counted
      {
        ...mkIssue(3, 2, "Resolved"),
        first_detected_at: longAgo,
        closed_at: thisWeekTs,
      },
      { ...mkIssue(4, 2, "Open"), first_detected_at: longAgo },
      // Group 3: single instance closed this week → counts as 1
      {
        ...mkIssue(5, 3, "Suppressed"),
        first_detected_at: longAgo,
        closed_at: thisWeekTs,
      },
    ];
    const groups = computeTrendMetrics(issues, "groups");
    expect(groups.resolvedThisWeek).toBe(2);
    // Instance-mode counts every closure event in the window: instances 2, 3, 5.
    const inst = computeTrendMetrics(issues, "instances");
    expect(inst.resolvedThisWeek).toBe(3);
  });

  it("computeTrendMetrics groups mode: new counts groups by earliest first detection", () => {
    const thisWeekTs = new Date().toISOString();
    const longAgo = "2024-01-01T00:00:00Z";

    const issues: VATReportIssue[] = [
      // Group 1: pre-existing — earliest detection is longAgo, NOT new this week
      // (even though instance 2 was first detected this week)
      { ...mkIssue(1, 1, "Open"), first_detected_at: longAgo },
      { ...mkIssue(2, 1, "Open"), first_detected_at: thisWeekTs },
      // Group 2: only this-week detections → counts as 1 new
      { ...mkIssue(3, 2, "Open"), first_detected_at: thisWeekTs },
      { ...mkIssue(4, 2, "Open"), first_detected_at: thisWeekTs },
      // Group 3: this-week detection but status is suppressed → excluded entirely
      { ...mkIssue(5, 3, "Suppressed"), first_detected_at: thisWeekTs },
    ];
    const groups = computeTrendMetrics(issues, "groups");
    expect(groups.newThisWeek).toBe(1);
    // Instance-mode counts every non-suppressed first detection: 1 + 2 = 3
    const inst = computeTrendMetrics(issues, "instances");
    expect(inst.newThisWeek).toBe(3);
  });

  it("computeMTTR counts all EXCLUDED_OPEN_STATUS findings with closed_at", () => {
    const issues: VATReportIssue[] = [
      // 2 high findings closed
      {
        ...mkIssue(1, 1, "Resolved"),
        first_detected_at: "2024-01-01T00:00:00Z",
        closed_at: "2024-01-11T00:00:00Z", // 10 days
      },
      {
        ...mkIssue(2, 2, "Suppressed"),
        first_detected_at: "2024-01-01T00:00:00Z",
        closed_at: "2024-01-03T00:00:00Z", // 2 days
      },
      // 1 currently open — skipped by computeMTTR
      mkIssue(3, 3, "Open"),
    ];
    const mttr = computeMTTR(issues, "instances");
    expect(mttr).toHaveLength(1);
    expect(mttr[0].severity).toBe("High");
    expect(mttr[0].count).toBe(2); // both closed findings count
    expect(mttr[0].avgDays).toBe(6); // (10 + 2) / 2
  });

  it("computeScannerBreakdown groups mode picks max-severity instance per group as representative", () => {
    // Group 1: two instances, Critical (Trivy) + Low (Grype). Server's
    // computeSeverityCountsByGroups would call this group Critical; the
    // breakdown must agree, attributing it to whichever scanner the worst
    // instance came from.
    const issues: VATReportIssue[] = [
      {
        ...mkIssue(1, 1, "open"),
        severity: "low",
        severity_score: 3,
        scanner_type: "Grype",
      },
      {
        ...mkIssue(2, 1, "open"),
        severity: "critical",
        severity_score: 9.8,
        scanner_type: "Trivy",
      },
      // Group 2: single Medium from Semgrep
      {
        ...mkIssue(3, 2, "open"),
        severity: "medium",
        severity_score: 5,
        scanner_type: "Semgrep",
      },
    ];
    const groups = computeScannerBreakdown(issues, "groups");
    const trivy = groups.find((g) => g.scanner === "Trivy");
    const grype = groups.find((g) => g.scanner === "Grype");
    expect(trivy?.count).toBe(1);
    expect(trivy?.critical).toBe(1);
    expect(trivy?.low).toBe(0);
    // Grype loses the attribution because Trivy's instance is the worst rep.
    expect(grype).toBeUndefined();
    // Instances mode counts every instance in its own scanner.
    const inst = computeScannerBreakdown(issues, "instances");
    expect(inst.find((g) => g.scanner === "Trivy")?.critical).toBe(1);
    expect(inst.find((g) => g.scanner === "Grype")?.low).toBe(1);
  });

  it("computeFleetRiskScore averages per-asset ORA so fleet-scale data doesn't saturate", () => {
    // Old computeReportRiskScore: 50 Critical → penalty 500 → score saturates
    // to 100/100 regardless of how many assets carry the load.
    // New: spread the same 50 Critical across 100 assets and the per-asset
    // ORA is non-zero, yielding a non-saturated fleet score.
    const issues: VATReportIssue[] = [];
    for (let asset = 0; asset < 100; asset++) {
      // Each asset has 1 Critical + 4 Low (a "noisy but tractable" repo)
      issues.push({
        ...mkIssue(asset * 5 + 1, asset * 5 + 1, "open"),
        repository: `repo-${asset}`,
        severity: "critical",
        severity_score: 9.8,
      });
      for (let lo = 0; lo < 4; lo++) {
        issues.push({
          ...mkIssue(asset * 5 + 2 + lo, asset * 5 + 2 + lo, "open"),
          repository: `repo-${asset}`,
          severity: "low",
          severity_score: 2,
        });
      }
    }
    // Per-asset penalty: 1*10 + min(4*0.25, 10) = 11 → ORA 89 → fleet 11.
    const score = computeFleetRiskScore(issues, "instances");
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThan(50); // not saturated
    expect(score).toBe(11);

    // Empty fleet → 0 risk.
    expect(computeFleetRiskScore([], "instances")).toBe(0);
  });

  it("computePeriodOverPeriodChange returns flat direction (no badge) when prior baseline is 0", () => {
    // Brand-new dataset: nothing existed at the comparison-window start.
    // Pre-fix every KPI surfaced a misleading +100% change.
    // dateFrom/dateTo strings parse as midnight UTC of those dates; pick a
    // detection timestamp safely inside the [from, to] window.
    const issues: VATReportIssue[] = [
      {
        ...mkIssue(1, 1, "open"),
        first_detected_at: "2026-03-01T12:00:00Z",
      },
      {
        ...mkIssue(2, 2, "open"),
        first_detected_at: "2026-03-01T12:00:00Z",
      },
    ];
    const change = computePeriodOverPeriodChange(
      issues,
      "2026-02-01",
      "2026-04-01",
      "instances",
    );
    expect(change).not.toBeNull();
    // currentTotal=2, previousTotal=0 → no baseline. Pre-fix: pctChange=100,
    // direction="up". Post-fix: pctChange=0, direction="flat".
    expect(change!.openIssues.previous).toBe(0);
    expect(change!.openIssues.current).toBe(2);
    expect(change!.openIssues.direction).toBe("flat");
    expect(change!.openIssues.pctChange).toBe(0);
  });

  it("computeSlaCompliance groups mode evaluates against group's worst severity and earliest detection", () => {
    const longAgo = "2024-01-01T00:00:00Z";
    const recent = new Date(Date.now() - 5 * 86400000).toISOString();
    // Group 1: Critical instance detected long ago + Low instance detected
    // recently. Bucket should be Critical (15-day SLA), aged from longAgo →
    // exceeding. Pre-fix, if Low was visited first, the bucket would be Low's
    // 360-day SLA aged from longAgo → still within (false negative).
    const issues: VATReportIssue[] = [
      {
        ...mkIssue(1, 1, "open"),
        severity: "low",
        severity_score: 3,
        first_detected_at: recent,
      },
      {
        ...mkIssue(2, 1, "open"),
        severity: "critical",
        severity_score: 9.8,
        first_detected_at: longAgo,
      },
    ];
    const groups = computeSlaCompliance(issues, {}, "groups");
    expect(groups.total).toBe(1);
    expect(groups.exceedingSla).toBe(1);
    expect(groups.bySeverity[0]?.severity).toBe("critical");
  });

  it("computeABCComplianceForIssues uses canonical VAT open-risk semantics", () => {
    const oldDate = "2024-01-01T00:00:00Z";
    const issues: VATReportIssue[] = [
      {
        ...mkIssue(1, 1, "Risk Accepted"),
        severity: "critical",
        severity_score: 10,
        first_detected_at: oldDate,
      },
      {
        ...mkIssue(2, 2, "Rejected"),
        severity: "high",
        severity_score: 8,
        first_detected_at: oldDate,
      },
      {
        ...mkIssue(3, 3, "Resolved"),
        severity: "critical",
        severity_score: 10,
        first_detected_at: oldDate,
      },
    ];

    const abc = computeABCComplianceForIssues(issues, "instances");

    expect(abc.bySeverity.critical.count).toBe(0);
    expect(abc.bySeverity.high.count).toBe(1);
    expect(abc.remediationOverdue).toBe(1);
  });

  it("computeABCCompliance directly excludes risk accepted and includes rejected open risk", () => {
    const oldDate = "2024-01-01T00:00:00Z";
    const abc = computeABCCompliance([
      {
        severity: "critical",
        severityScore: 10,
        firstDetectedAt: oldDate,
        status: "Risk Accepted",
      },
      {
        severity: "high",
        severityScore: 8,
        firstDetectedAt: oldDate,
        status: "Rejected",
      },
      {
        severity: "critical",
        severityScore: 10,
        firstDetectedAt: oldDate,
        status: "Resolved",
      },
    ]);

    expect(abc.bySeverity.critical.count).toBe(0);
    expect(abc.bySeverity.high.count).toBe(1);
    expect(abc.remediationOverdue).toBe(1);
  });
});
