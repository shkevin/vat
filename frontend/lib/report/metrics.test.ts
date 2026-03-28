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
} from "./metrics";
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
