/**
 * Report engine integration test — verify Open count in context respects countMode.
 * When 3 findings exist with 2 in one group and 1 in another:
 * - countMode "groups" → context.openIssues = 2
 * - countMode "instances" → context.openIssues = 3
 */

import { describe, it, expect } from "vitest";
import {
  buildReportHtmlFromDefinition,
  computeReportContext,
  createDefaultReportDefinition,
} from "./report-engine";
import { toVATDashboardData } from "./vatReportAdapter";
import type { Finding, Asset } from "@/types";

function mkFinding(
  id: string,
  cveId: string,
  component: string,
  componentBase: string,
): Finding {
  return {
    id,
    findingType: "SCA",
    fingerprintId: `fp-${id}`,
    cveId,
    severity: "High",
    status: "Open",
    sources: [],
    audit: [],
    component,
    componentBase,
    title: `${cveId} in ${component}`,
  };
}

describe("computeReportContext countMode", () => {
  const findings: Finding[] = [
    mkFinding("f1", "CVE-2024-8385", "firefox-esr 115.0", "firefox-esr"),
    mkFinding("f2", "CVE-2024-8381", "firefox-esr 115.0", "firefox-esr"),
    mkFinding("f3", "CVE-2024-5432", "openssl 3.0.0", "openssl"),
  ];
  const assets: Asset[] = [];

  const baseFilters = {
    repoFilter: [],
    branchFilter: null,
    severityFilter: [],
    dateFrom: null,
    dateTo: null,
    notes: "",
  };

  it("returns openIssues=2 when countMode is groups (2 groups)", () => {
    const data = toVATDashboardData(findings, assets, "VAT", {
      groupFindings: true,
    });
    const ctx = computeReportContext(data, {
      ...baseFilters,
      countMode: "groups",
    });
    expect(ctx.openIssues).toBe(2);
  });

  it("returns openIssues=3 when countMode is instances (3 instances)", () => {
    const data = toVATDashboardData(findings, assets, "VAT", {
      groupFindings: true,
    });
    const ctx = computeReportContext(data, {
      ...baseFilters,
      countMode: "instances",
    });
    expect(ctx.openIssues).toBe(3);
  });

  it("dedupes findings that share an issue_group_id in groups mode regardless of reported repository", () => {
    // Two findings the backend considers the same group (explicit groupKey),
    // but with different repository strings. Previously the renderer applied
    // its own asset-scope on top of the group id and counted them as 2 when
    // the raw repo strings differed; now the groupId is the sole dedup key,
    // matching the server-side severity donut / trend / aging widgets.
    const sameGroupDifferentRepoStrings: Finding[] = [
      {
        id: "f-a",
        findingType: "SCA",
        fingerprintId: "fp-a",
        cveId: "CVE-2026-1000",
        severity: "High",
        status: "Open",
        sources: [],
        audit: [],
        component: "libfoo 1.0",
        image: "containers/images/api",
        groupKey: "sca:npm|libfoo#shared-asset",
        title: "libfoo vuln",
      },
      {
        id: "f-b",
        findingType: "SCA",
        fingerprintId: "fp-b",
        cveId: "CVE-2026-1000",
        severity: "High",
        status: "Open",
        sources: [],
        audit: [],
        component: "libfoo 1.0",
        image: "containers/images/api-replica",
        groupKey: "sca:npm|libfoo#shared-asset",
        title: "libfoo vuln",
      },
    ];
    const data = toVATDashboardData(sameGroupDifferentRepoStrings, [], "VAT", {
      groupFindings: true,
    });
    const groupsCtx = computeReportContext(data, {
      ...baseFilters,
      countMode: "groups",
    });
    expect(groupsCtx.openIssues).toBe(1);
    expect(groupsCtx.counts.high).toBe(1);
    const instancesCtx = computeReportContext(data, {
      ...baseFilters,
      countMode: "instances",
    });
    expect(instancesCtx.openIssues).toBe(2);
    expect(instancesCtx.counts.high).toBe(2);
  });
});

describe("trend stacked dropdown filters", () => {
  it("does not gate trend chart updates behind server counts", () => {
    const findings: Finding[] = [
      mkFinding("f1", "CVE-2024-1111", "pkg-a 1.0.0", "pkg-a"),
    ];
    const data = toVATDashboardData(findings, [], "VAT", {
      groupFindings: true,
    });
    data.issueCounts = { open: 1, critical: 0, high: 1, medium: 0, low: 0 };
    const definition = createDefaultReportDefinition("VAT");
    const ctx = computeReportContext(data, definition.filters);
    const html = buildReportHtmlFromDefinition(ctx, definition, {
      preview: true,
    });
    expect(html).not.toContain("&& !useServerCounts");
  });

  it("keeps historical trend buckets based on closure date, not current status", () => {
    const findings: Finding[] = [
      mkFinding("f1", "CVE-2024-1111", "pkg-a 1.0.0", "pkg-a"),
    ];
    const data = toVATDashboardData(findings, [], "VAT", {
      groupFindings: true,
    });
    const definition = createDefaultReportDefinition("VAT");
    const ctx = computeReportContext(data, definition.filters);
    const html = buildReportHtmlFromDefinition(ctx, definition, {
      preview: true,
    });
    expect(html).not.toContain("var weekOpen = openAtWeek.filter");
    expect(html).toContain("countBySeverityTrend(openAtWeek)");
  });
});

describe("report adapter severity source of truth", () => {
  it("uses finding.severity for container counts, not sourceGroupSeverity overrides", () => {
    const findings: Finding[] = [
      {
        id: "f-low",
        findingType: "SCA",
        fingerprintId: "fp-low",
        cveId: "CVE-2026-0001",
        severity: "Low",
        sourceGroupSeverity: "Critical",
        status: "Open",
        sources: [],
        audit: [],
        image: "containers/images/demo",
        component: "pkg-a",
        title: "pkg-a issue",
      },
    ];
    const assets: Asset[] = [
      {
        id: "containers/images/demo",
        name: "containers/images/demo",
        type: "container",
        findings,
        openCount: 1,
        inReviewCount: 0,
        statusBreakdown: { Open: 1 },
        worstSeverity: "Low",
        overdueCount: 0,
        verifiedPct: 0,
        oraPct: 99,
      },
    ];
    const data = toVATDashboardData(findings, assets, "VAT", {
      groupFindings: true,
    });
    expect(data.containers).toHaveLength(1);
    expect(data.containers[0].critical_count).toBe(0);
    expect(data.containers[0].high_count).toBe(0);
    expect(data.containers[0].medium_count).toBe(0);
    expect(data.containers[0].low_count).toBe(1);
  });
});

describe("report container risk source of truth", () => {
  it("applies report filters before computing container risk counts", () => {
    const findings: Finding[] = [
      {
        id: "f-old-critical",
        findingType: "SCA",
        fingerprintId: "fp-old-critical",
        cveId: "CVE-2026-0100",
        severity: "Critical",
        status: "Open",
        sources: [],
        audit: [],
        image: "containers/images/demo",
        component: "pkg-critical",
        title: "old critical",
        firstDetectedAt: "2025-01-01T00:00:00.000Z",
      },
      {
        id: "f-new-low",
        findingType: "SCA",
        fingerprintId: "fp-new-low",
        cveId: "CVE-2026-0101",
        severity: "Low",
        status: "Open",
        sources: [],
        audit: [],
        image: "containers/images/demo",
        component: "pkg-low",
        title: "new low",
        firstDetectedAt: "2026-03-20T00:00:00.000Z",
      },
    ];
    const assets: Asset[] = [
      {
        id: "containers/images/demo",
        name: "containers/images/demo",
        type: "container",
        findings,
        openCount: 2,
        inReviewCount: 0,
        statusBreakdown: { Open: 2 },
        worstSeverity: "Critical",
        overdueCount: 0,
        verifiedPct: 0,
        oraPct: 50,
      },
    ];
    const data = toVATDashboardData(findings, assets, "VAT", {
      groupFindings: true,
    });
    const ctx = computeReportContext(data, {
      repoFilter: [],
      branchFilter: null,
      severityFilter: [],
      dateFrom: "2026-03-01",
      dateTo: "2026-03-31",
      notes: "",
      countMode: "instances",
    });
    expect(ctx.containerRisk).toHaveLength(1);
    expect(ctx.containerRisk[0].critical).toBe(0);
    expect(ctx.containerRisk[0].low).toBe(1);
    expect(ctx.containerRisk[0].total).toBe(1);
  });
});
