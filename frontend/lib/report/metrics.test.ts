/**
 * Report metrics tests — verify Open count respects countMode (groups vs instances).
 * When 3 findings exist with 2 in one group and 1 in another:
 * - countMode "groups" → totalOpen = 2
 * - countMode "instances" → totalOpen = 3
 */

import { describe, it, expect } from "vitest";
import { resolveOpenCounts, getRiskLevel, computeRiskScore } from "./metrics";
import type { VATReportIssue, VATReportIssueGroup } from "./vatReportAdapter";

function mkIssue(
  issueId: number,
  groupId: number,
  status = "open"
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
    aikido_url: "",
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
    const score = computeRiskScore({ critical: 39, high: 0, medium: 0, low: 0, info: 0 });
    expect(score).toBe(10);
    expect(getRiskLevel(score)).toBe("Critical");
  });
});
