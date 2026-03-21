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
});
