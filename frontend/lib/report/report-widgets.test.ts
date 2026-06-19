import { describe, expect, it, vi } from "vitest";
import { computeReportContext } from "./report-engine";
import {
  WIDGET_DEFAULT_CONFIG,
  type ReportContext,
  type WidgetType,
} from "./report-types";
import { toVATDashboardData } from "./vatReportAdapter";
import { renderWidget } from "./report-widgets";
import type { Finding } from "@/types";

function finding(
  id: string,
  status: string,
  severity: string,
  groupKey: string,
  repository: string,
  source = "trivy",
): Finding {
  return {
    id,
    findingType: "SCA",
    fingerprintId: `fp-${id}`,
    cveId: `CVE-2026-${id}`,
    severity,
    status,
    source,
    sources: [{ name: source, importedAt: "2026-06-01T00:00:00Z" }],
    audit: [],
    component: "openssl 3.0",
    image: repository,
    groupKey,
    title: `${id} ${severity}`,
    firstDetectedAt: "2026-05-01T00:00:00Z",
    closedAt: status === "Resolved" ? "2026-06-10T00:00:00Z" : undefined,
  };
}

const baseFilters = {
  repoFilter: [],
  branchFilter: null,
  severityFilter: [],
  dateFrom: null,
  dateTo: null,
  notes: "",
  countMode: "groups" as const,
};

function buildContext(): ReportContext {
  vi.setSystemTime(new Date("2026-06-18T12:00:00Z"));
  const findings: Finding[] = [
    finding("0001", "Open", "Critical", "g-critical", "repo-a"),
    finding("0002", "Risk Accepted", "Critical", "g-waived", "repo-a"),
    finding("0003", "Rejected", "High", "g-high", "repo-a"),
    finding("0004", "In Review", "Medium", "g-high", "repo-a"),
    finding("0005", "Resolved", "Critical", "g-closed", "repo-b"),
    finding("0006", "Reopened", "Low", "g-low", "repo-b", "grype"),
  ];
  const data = toVATDashboardData(findings, [], "VAT", {
    groupFindings: true,
  });
  const ctx = computeReportContext(data, baseFilters);
  return {
    ...ctx,
    teams: [{ id: "team-a", name: "Team A" }],
    activityLog: [
      {
        id: "activity-1",
        action: "status.changed",
        timestamp: "2026-06-18T10:00:00Z",
        user: "analyst@example.com",
        target_name: "CVE-2026-0005",
        details: "Resolved finding",
      },
    ],
    soc2Compliance: {
      score: 82,
      status: "Compliant",
      controls_total: 10,
      controls_passed: 8,
    },
    reachabilityMatrix: [
      { severity: "Critical", exploitable: 1, notExploitable: 2, unknown: 3 },
    ],
    ciScans: [
      { created_at: "2026-06-18T08:00:00Z", success: true },
      { created_at: "2026-06-18T09:00:00Z", success: false },
    ],
    taskProjects: [{ name: "Linear VAT", type: "Linear" }],
    tasksByGroupId: { 1: [{ title: "Fix critical", url: "https://example.test" }] },
    containerRisk: [
      {
        repo: "repo-b",
        critical: 0,
        high: 0,
        medium: 0,
        low: 1,
        total: 1,
        score: 0,
      },
    ],
  };
}

const widgetTypes = Object.keys(WIDGET_DEFAULT_CONFIG) as WidgetType[];

function configFor(type: WidgetType): Record<string, unknown> {
  if (type === "text") return { content: "Executive note" };
  if (type === "complianceScoreCard") return { framework: "soc2" };
  return WIDGET_DEFAULT_CONFIG[type];
}

describe("report widget golden rendering", () => {
  it("renders every registered widget type from the canonical VAT fixture", () => {
    const ctx = buildContext();

    for (const type of widgetTypes) {
      const html = renderWidget(type, ctx, configFor(type));
      expect(html, type).toContain("section");
    }
  });

  it("renders summary and severity widgets from canonical open-risk counts", () => {
    const ctx = buildContext();

    expect(renderWidget("summary", ctx, { variant: "default" })).toContain(
      '<div class="kpi-label">Open</div><div class="kpi-value">3</div>',
    );
    expect(renderWidget("severityPills", ctx, {})).toContain("Critical 1");
    expect(renderWidget("severityPills", ctx, {})).toContain("High 1");
    expect(renderWidget("severityPills", ctx, {})).toContain("Medium 0");
    expect(renderWidget("severityPills", ctx, {})).toContain("Low 1");
    expect(renderWidget("criticalHighKpi", ctx, {})).toContain(
      '<div class="value" style="color:#f97316">2</div>',
    );
  });

  it("keeps risk accepted separate in remediation progress", () => {
    const ctx = buildContext();
    const html = renderWidget("openVsClosed", ctx, {});

    expect(html).toContain('<div class="label">Open risk</div>');
    expect(html).toContain('<div class="value" style="color:#f97316">3</div>');
    expect(html).toContain('<div class="label">Risk accepted</div>');
    expect(html).toContain('<div class="value" style="color:#0ea5e9">1</div>');
    expect(html).toContain('<div class="label">Closed</div>');
    expect(html).toContain('<div class="value" style="color:#22c55e">1</div>');
  });

  it("renders source, repo, container, and inventory widgets from open-risk data", () => {
    const ctx = buildContext();

    expect(renderWidget("sourceBar", ctx, {})).toContain("trivy: 2");
    expect(renderWidget("sourceBar", ctx, {})).toContain("grype: 1");
    expect(renderWidget("scannerTable", ctx, {})).toContain(
      '<td class="mono">trivy</td><td class="text-right mono" style="font-weight:600">2</td>',
    );
    expect(renderWidget("repoTable", ctx, { limit: 25 })).toContain(
      '<td class="mono">repo-a</td>',
    );
    expect(renderWidget("containerTable", ctx, { limit: 25 })).toContain(
      '<td class="mono">repo-b</td>',
    );
    expect(renderWidget("issueList", ctx, { limit: 100 })).toContain(
      'data-report-aggregate="issue-list"',
    );
  });

  it("renders compliance and operational widgets with exact fixture values", () => {
    const ctx = buildContext();

    expect(renderWidget("abcCompliance", ctx, {})).toContain(
      "2 remediation(s) overdue",
    );
    expect(renderWidget("slaCompliance", ctx, {})).toContain(
      '<div class="label">Exceeding SLA</div><div class="value" style="color:#ef4444">2</div>',
    );
    expect(renderWidget("teamTable", ctx, {})).toContain("Team A");
    expect(renderWidget("activityTimeline", ctx, {})).toContain(
      "status.changed",
    );
    expect(renderWidget("complianceScoreCard", ctx, { framework: "soc2" })).toContain(
      '<div class="value" style="color:#22c55e">82%</div>',
    );
    expect(renderWidget("reachabilityMatrix", ctx, {})).toContain(
      '<td class="text-right mono" style="color:#22c55e">1</td>',
    );
    expect(renderWidget("ciScanFrequency", ctx, { periodDays: 30 })).toContain(
      "<td class=\"mono\">2026-06-18</td><td class=\"text-right mono\">2</td>",
    );
    expect(renderWidget("taskProjectsTable", ctx, {})).toContain("Linear VAT");
    expect(renderWidget("text", ctx, { content: "Executive note" })).toContain(
      "Executive note",
    );
  });
});
