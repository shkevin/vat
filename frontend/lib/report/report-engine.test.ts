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
import { computeTrendMetrics } from "./metrics";
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

function mkReportFinding(
  id: string,
  status: string,
  severity: string,
  groupKey: string,
  image: string,
): Finding {
  return {
    id,
    findingType: "SCA",
    fingerprintId: `fp-${id}`,
    cveId: `CVE-2026-${id}`,
    severity,
    status,
    sources: [{ name: "trivy", importedAt: "2026-06-01T00:00:00Z" }],
    source: "trivy",
    audit: [],
    component: "openssl 3.0",
    image,
    groupKey,
    title: `${id} ${severity}`,
    firstDetectedAt: "2024-01-01T00:00:00Z",
    closedAt: status === "Resolved" ? "2026-06-01T00:00:00Z" : undefined,
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

describe("computeReportContext golden VAT semantics", () => {
  const filters = {
    repoFilter: [],
    branchFilter: null,
    severityFilter: [],
    dateFrom: null,
    dateTo: null,
    notes: "",
  };

  const findings: Finding[] = [
    mkReportFinding("0001", "Open", "Critical", "g-critical", "repo-a"),
    mkReportFinding("0002", "Risk Accepted", "Critical", "g-waived", "repo-a"),
    mkReportFinding("0003", "Rejected", "High", "g-high", "repo-a"),
    mkReportFinding("0004", "In Review", "Medium", "g-high", "repo-a"),
    mkReportFinding("0005", "Resolved", "Critical", "g-closed", "repo-b"),
    mkReportFinding("0006", "Reopened", "Low", "g-low", "repo-b"),
  ];

  it("reports grouped widgets from canonical open-risk groups", () => {
    const data = toVATDashboardData(findings, [], "VAT", {
      groupFindings: true,
    });
    const ctx = computeReportContext(data, {
      ...filters,
      countMode: "groups",
    });

    expect(ctx.totalIssues).toBe(5);
    expect(ctx.openIssues).toBe(3);
    expect(ctx.counts).toMatchObject({
      critical: 1,
      high: 1,
      medium: 0,
      low: 1,
      info: 0,
    });
    expect(ctx.riskScore).toBe(7);
    expect(ctx.repoRisk.find((r) => r.repo === "repo-a")).toMatchObject({
      critical: 1,
      high: 1,
      medium: 0,
      low: 0,
      total: 2,
    });
    expect(ctx.repoRisk.find((r) => r.repo === "repo-b")).toMatchObject({
      critical: 0,
      high: 0,
      medium: 0,
      low: 1,
      total: 1,
    });
    expect(ctx.scanners).toHaveLength(1);
    expect(ctx.scanners[0]).toMatchObject({
      scanner: "trivy",
      critical: 1,
      high: 1,
      low: 1,
      count: 3,
    });
  });

  it("reports instance widgets from canonical open-risk instances", () => {
    const data = toVATDashboardData(findings, [], "VAT", {
      groupFindings: true,
    });
    const ctx = computeReportContext(data, {
      ...filters,
      countMode: "instances",
    });

    expect(ctx.totalIssues).toBe(6);
    expect(ctx.openIssues).toBe(4);
    expect(ctx.counts).toMatchObject({
      critical: 1,
      high: 1,
      medium: 1,
      low: 1,
      info: 0,
    });
    expect(ctx.riskScore).toBe(7);
    expect(ctx.repoRisk.find((r) => r.repo === "repo-a")).toMatchObject({
      critical: 1,
      high: 1,
      medium: 1,
      low: 0,
      total: 3,
    });
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

  it("prefers server full-set trend metrics for this-week KPIs (truncation guard)", () => {
    // When the report payload is capped to maxIssues, the per-issue recompute in the
    // client script undercounts "new/closed this week". The this-week KPIs must fall
    // back to the engine's pre-computed full-set serverTrendMetrics.
    const findings: Finding[] = [
      mkFinding("f1", "CVE-2024-3001", "pkg-a 1.0.0", "pkg-a"),
    ];
    const data = toVATDashboardData(findings, [], "VAT", {
      groupFindings: true,
    });
    const definition = createDefaultReportDefinition("VAT");
    const ctx = computeReportContext(data, definition.filters);
    const html = buildReportHtmlFromDefinition(ctx, definition, {
      preview: true,
    });
    expect(html).toContain("reportData.serverTrendMetrics");
    expect(html).toContain("serverTrendMetrics.resolvedThisWeek");
    expect(html).toContain("serverTrendMetrics.newThisWeek");
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

  it("does not treat Rejected as closed in embedded report widget recomputation", () => {
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

    expect(html).not.toContain(
      's === "not applicable" || s === "rejected"',
    );
  });

  it("suppresses baseline-less +100% spikes in summary period deltas", () => {
    const findings: Finding[] = [
      mkFinding("f1", "CVE-2024-1112", "pkg-b 1.0.0", "pkg-b"),
    ];
    const data = toVATDashboardData(findings, [], "VAT", {
      groupFindings: true,
    });
    const definition = createDefaultReportDefinition("VAT");
    // Enable period comparison path in the client script.
    definition.filters.dateFrom = "2026-01-01";
    definition.filters.dateTo = "2026-05-01";
    const ctx = computeReportContext(data, definition.filters);
    const html = buildReportHtmlFromDefinition(ctx, definition, {
      preview: true,
    });
    expect(html).not.toContain("b === 0 ? (a > 0 ? 100 : 0)");
    expect(html).toContain(
      'function pct(a,b) { return b === 0 ? 0 : Math.round(((a - b) / b) * 100); }',
    );
    expect(html).toContain(
      'function dir(a,b) { return b === 0 ? "flat" : a > b ? "up" : a < b ? "down" : "flat"; }',
    );
  });

  it("aligns trend top-bar current open with summary open when trend filters are all selected", () => {
    const findings: Finding[] = [
      mkFinding("f1", "CVE-2024-1113", "pkg-c 1.0.0", "pkg-c"),
    ];
    const data = toVATDashboardData(findings, [], "VAT", {
      groupFindings: true,
    });
    const definition = createDefaultReportDefinition("VAT");
    const ctx = computeReportContext(data, definition.filters);
    const html = buildReportHtmlFromDefinition(ctx, definition, {
      preview: true,
    });
    expect(html).toContain(
      "var trendUsesAllDimensions = (!trendSevSet || trendSevSet.size === 0) && (!trendTypesSet || trendTypesSet.size === 0);",
    );
    expect(html).toContain(
      "var trendCurrDisplay = (trendUsesAllDimensions && trendCountMode === countMode) ? summaryOpenVal : trendCurr;",
    );
  });

  it("labels report periods as trend lookback while clarifying current-open KPI semantics", () => {
    const findings: Finding[] = [
      mkFinding("f1", "CVE-2024-1114", "pkg-d 1.0.0", "pkg-d"),
    ];
    const data = toVATDashboardData(findings, [], "VAT", {
      groupFindings: true,
    });
    const definition = createDefaultReportDefinition("VAT");
    definition.filters.dateFrom = "2026-01-01";
    definition.filters.dateTo = "2026-03-31";
    const ctx = computeReportContext(data, definition.filters);
    const html = buildReportHtmlFromDefinition(ctx, definition, {
      preview: true,
    });

    expect(html).toContain("Trend lookback:");
    expect(html).toContain(
      "KPIs and risk widgets show current open findings; trend widgets use the lookback period.",
    );
    expect(html).not.toContain("Date range:");
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
  it("can use date range as a trend lookback without excluding older open backlog from current counts", () => {
    const findings: Finding[] = [
      {
        id: "f-old-critical",
        findingType: "SCA",
        fingerprintId: "fp-old-critical",
        cveId: "CVE-2025-0100",
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
        id: "f-new-high",
        findingType: "SCA",
        fingerprintId: "fp-new-high",
        cveId: "CVE-2026-0101",
        severity: "High",
        status: "Open",
        sources: [],
        audit: [],
        image: "containers/images/demo",
        component: "pkg-high",
        title: "new high",
        firstDetectedAt: "2026-03-20T00:00:00.000Z",
      },
    ];
    const data = toVATDashboardData(findings, [], "VAT", {
      groupFindings: true,
    });
    const ctx = computeReportContext(data, {
      repoFilter: [],
      branchFilter: null,
      severityFilter: ["critical", "high"],
      dateFrom: "2026-03-01",
      dateTo: "2026-04-01",
      notes: "",
      countMode: "instances",
      dateFilterMode: "trendOnly",
    });

    expect(ctx.dateFrom).toBe("2026-03-01");
    expect(ctx.dateTo).toBe("2026-04-01");
    expect(ctx.openIssues).toBe(2);
    expect(ctx.counts.critical).toBe(1);
    expect(ctx.counts.high).toBe(1);
  });

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
      dateFilterMode: "detected",
      notes: "",
      countMode: "instances",
    });
    expect(ctx.containerRisk).toHaveLength(1);
    expect(ctx.containerRisk[0].critical).toBe(0);
    expect(ctx.containerRisk[0].low).toBe(1);
    expect(ctx.containerRisk[0].total).toBe(1);
  });
});

describe("trend this-week counts: instances must not be group-deduped", () => {
  const DAY = 86400000;
  const now = Date.now();
  const thisWeek = new Date(now).toISOString(); // today — always in the current week
  const old = new Date(now - 30 * DAY).toISOString();

  function mk(
    id: string,
    cve: string,
    pkg: string,
    status: string,
    firstDetectedAt: string,
    closedAt?: string,
  ): Finding {
    return {
      id,
      findingType: "SCA",
      fingerprintId: `fp-${id}`,
      cveId: cve,
      severity: "High",
      status,
      sources: [],
      audit: [],
      component: pkg,
      componentBase: pkg,
      image: "img-x",
      title: `${cve} in ${pkg}`,
      firstDetectedAt,
      closedAt,
    } as unknown as Finding;
  }

  // Group A: 2 instances, both newly detected this week, still open.
  // Group B: 2 instances, both closed this week.
  const findings: Finding[] = [
    mk("a1", "CVE-A", "pkg-a", "Open", thisWeek),
    mk("a2", "CVE-A", "pkg-a", "Open", thisWeek),
    mk("b1", "CVE-B", "pkg-b", "Resolved", old, thisWeek),
    mk("b2", "CVE-B", "pkg-b", "Resolved", old, thisWeek),
  ];
  const data = toVATDashboardData(findings, [], "VAT", { groupFindings: true });

  it("instances mode counts each finding (new=2, closed=2)", () => {
    const m = computeTrendMetrics(data.issues, "instances");
    expect(m.newThisWeek).toBe(2);
    expect(m.resolvedThisWeek).toBe(2);
  });

  it("groups mode dedupes by group (new=1, closed=1)", () => {
    const m = computeTrendMetrics(data.issues, "groups");
    expect(m.newThisWeek).toBe(1);
    expect(m.resolvedThisWeek).toBe(1);
  });
});

describe("vulnerability vs compliance in report context", () => {
  const baseFilters = {
    repoFilter: [],
    branchFilter: null,
    severityFilter: [],
    dateFrom: null,
    dateTo: null,
    notes: "",
    countMode: "instances" as const,
  };
  const mkVuln = (id: string, sev: string): Finding => ({
    id,
    findingType: "SCA",
    fingerprintId: `fp-${id}`,
    cveId: `CVE-2026-${id}`,
    severity: sev,
    status: "Open",
    sources: [],
    source: "trivy",
    audit: [],
    component: "openssl 3.0",
    image: "img-a",
    title: `${id}`,
    firstDetectedAt: "2024-01-01T00:00:00Z",
  });
  const mkLicense = (id: string): Finding => ({
    id,
    findingType: "License",
    fingerprintId: `fp-${id}`,
    cveId: undefined as unknown as string,
    severity: "High", // GPL rated High
    status: "Open",
    sources: [],
    source: "trivy",
    audit: [],
    component: "busybox",
    image: "img-a",
    title: `GPL ${id}`,
    firstDetectedAt: "2024-01-01T00:00:00Z",
  });

  it("counts compliance separately and keeps risk score vulnerability-only", () => {
    const vulnOnly = [mkVuln("1", "Critical")];
    const withLicenses = [
      mkVuln("1", "Critical"),
      mkLicense("L1"),
      mkLicense("L2"),
      mkLicense("L3"),
    ];
    const ctxVuln = computeReportContext(
      toVATDashboardData(vulnOnly, [], "VAT", { groupFindings: true }),
      baseFilters,
    );
    const ctxMixed = computeReportContext(
      toVATDashboardData(withLicenses, [], "VAT", { groupFindings: true }),
      baseFilters,
    );
    // Licenses are reported as compliance, not vulnerabilities.
    expect(ctxMixed.complianceCount).toBe(3);
    expect(ctxVuln.complianceCount).toBe(0);
    // The 3 GPL "High" licenses must NOT change the vulnerability risk score.
    expect(ctxMixed.riskScore).toBe(ctxVuln.riskScore);
  });
});

describe("exported report embedded JS validity (compliance split)", () => {
  const baseFilters = {
    repoFilter: [],
    branchFilter: null,
    severityFilter: [],
    dateFrom: null,
    dateTo: null,
    notes: "",
    countMode: "instances" as const,
  };
  const mkVuln = (id: string, sev: string): Finding => ({
    id,
    findingType: "SCA",
    fingerprintId: `fp-${id}`,
    cveId: `CVE-2026-${id}`,
    severity: sev,
    status: "Open",
    sources: [],
    source: "trivy",
    audit: [],
    component: "openssl 3.0",
    image: "containers/images/img-a",
    title: id,
    firstDetectedAt: "2024-01-01T00:00:00Z",
  });
  const mkLicense = (id: string): Finding => ({
    id,
    findingType: "License",
    fingerprintId: `fp-${id}`,
    cveId: undefined as unknown as string,
    severity: "High",
    status: "Open",
    sources: [],
    source: "trivy",
    audit: [],
    component: "busybox",
    image: "containers/images/img-a",
    title: `GPL ${id}`,
    firstDetectedAt: "2024-01-01T00:00:00Z",
  });

  it("embedded client script parses and the report exposes the Compliance column/KPI", () => {
    const findings = [mkVuln("1", "Critical"), mkLicense("L1"), mkLicense("L2")];
    const data = toVATDashboardData(findings, [], "VAT", { groupFindings: true });
    const definition = createDefaultReportDefinition("VAT");
    const ctx = computeReportContext(data, { ...definition.filters, ...baseFilters });
    const html = buildReportHtmlFromDefinition(ctx, definition, { preview: true });

    // Every embedded <script> must be syntactically valid JS (new Function parses,
    // does not execute) — guards the string-built client filter logic.
    const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)].map(
      (m) => m[1],
    );
    expect(scripts.length).toBeGreaterThan(0);
    for (const body of scripts) {
      if (body.trim()) expect(() => new Function(body)).not.toThrow();
    }
    // Compliance surfaced (KPI label at minimum).
    expect(html).toContain("Compliance");
  });
});
