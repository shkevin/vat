"use client";

import { useEffect, useRef, useMemo } from "react";
import { notFound } from "next/navigation";
import {
  buildReportHtmlFromDefinition,
  computeReportContext,
} from "@/lib/report/report-engine";
import type {
  VATDashboardData,
  VATReportIssue,
} from "@/lib/report/vatReportAdapter";
import type { ReportDefinition } from "@/lib/report/report-types";
import { createDefaultReportDefinition } from "@/lib/report/report-engine";

/** Mock issues so the filter bar appears with Severity, Repo, Branch options. */
function createMockDashboardData(): VATDashboardData {
  const now = new Date().toISOString();
  const issues: VATReportIssue[] = [
    {
      issue_id: 1,
      issue_group_id: 1,
      first_detected_at: now,
      last_detected_at: now,
      repository: "acme/backend",
      branch: "main",
      severity: "critical",
      severity_score: 10,
      status: "open",
      title: "SQL Injection in auth module",
    },
    {
      issue_id: 2,
      issue_group_id: 2,
      first_detected_at: now,
      last_detected_at: now,
      repository: "acme/backend",
      branch: "develop",
      severity: "high",
      severity_score: 8,
      status: "open",
      title: "XSS in user profile",
    },
    {
      issue_id: 3,
      issue_group_id: 3,
      first_detected_at: now,
      last_detected_at: now,
      repository: "acme/frontend",
      branch: "main",
      severity: "medium",
      severity_score: 5,
      status: "open",
      title: "Outdated dependency",
    },
  ];
  return {
    issues,
    issueGroups: issues.map((i) => ({
      group_id: i.issue_group_id,
      title: i.title,
      severity: i.severity,
      severity_score: i.severity_score,
      status: i.status,
      first_detected_at: i.first_detected_at,
      issue_count: 1,
      affected_repos: i.repository ? [i.repository] : [],
      scanner_type: "SAST",
      cve_id: undefined,
      has_task: false,
      source_url: "",
    })),
    repos: [
      {
        id: 1,
        name: "acme/backend",
        provider: "github",
        issue_count: 2,
        critical_count: 1,
        high_count: 1,
        medium_count: 0,
        low_count: 0,
      },
      {
        id: 2,
        name: "acme/frontend",
        provider: "github",
        issue_count: 1,
        critical_count: 0,
        high_count: 0,
        medium_count: 1,
        low_count: 0,
      },
    ],
    packageRepos: [],
    containers: [],
    vms: [],
    teams: [],
    workspace: { id: "test", name: "Test Workspace", plan: "free" },
    fetchedAt: now,
  };
}

/** Extract body content and script content from full report HTML. */
function extractBodyAndScripts(html: string): {
  body: string;
  scripts: string[];
} {
  const bodyMatch = html.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  const body = bodyMatch ? bodyMatch[1] : html;
  const scripts: string[] = [];
  const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = scriptRegex.exec(html)) !== null) {
    scripts.push(m[1]);
  }
  return { body, scripts };
}

export default function TestReportPage() {
  // Dev-only fixture: exposes eval() of mock report scripts. 404 in
  // production so the eval surface is unreachable from the live app.
  if (process.env.NODE_ENV === "production") {
    notFound();
  }
  const containerRef = useRef<HTMLDivElement>(null);

  const reportHtml = useMemo(() => {
    const data = createMockDashboardData();
    const definition: ReportDefinition = createDefaultReportDefinition(
      data.workspace.name,
      undefined,
      "vat",
    );
    const context = computeReportContext(data, definition.filters);
    return buildReportHtmlFromDefinition(context, definition, {
      preview: true,
    });
  }, []);

  useEffect(() => {
    const el = containerRef.current;
    if (!el || !reportHtml) return;

    const { body, scripts } = extractBodyAndScripts(reportHtml);
    el.innerHTML = body;
    (window as unknown as { __reportScripts?: string[] }).__reportScripts =
      scripts;

    // Scripts injected via innerHTML do not execute. Use eval so IIFE runs in global scope.
    for (let i = 0; i < scripts.length; i++) {
      const scriptContent = scripts[i];
      try {
        // eslint-disable-next-line no-eval
        eval(scriptContent);
      } catch (err) {
        const msg = (err as Error).message;
        // Try to find position from V8/SpiderMonkey format: "Unexpected token ')' (at line 1, col 12345)"
        const posMatch =
          msg.match(/at line (\d+)/i) || msg.match(/position (\d+)/i);
        const pos = posMatch ? parseInt(posMatch[1], 10) : -1;
        const search = scriptContent.indexOf("Unexpected");
        const ctx =
          scriptContent.slice(0, 500) +
          "\n...[truncated]...\n" +
          scriptContent.slice(-500);
        console.error(
          `[test-report] Script ${i} (len=${scriptContent.length}) error:`,
          msg,
          "\nFirst 500 chars:",
          scriptContent.slice(0, 500),
        );
      }
    }
  }, [reportHtml]);

  const openStandalone = () => {
    const blob = new Blob([reportHtml], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank", "noopener");
  };

  return (
    <div style={{ padding: 24, maxWidth: 1200, margin: "0 auto" }}>
      <h1 style={{ marginBottom: 16, fontSize: 18 }}>
        Report Filter Test Page
      </h1>
      <p style={{ marginBottom: 24, color: "#64748b", fontSize: 14 }}>
        Minimal report HTML rendered directly (no iframe) to test the filter
        script.{" "}
        <button
          type="button"
          onClick={openStandalone}
          style={{ padding: "4px 8px", cursor: "pointer", fontSize: 13 }}
        >
          Open as standalone HTML
        </button>{" "}
        (opens full document in new tab)
      </p>
      <div
        ref={containerRef}
        className="report-test-container"
        style={{
          border: "1px solid #e2e8f0",
          borderRadius: 8,
          padding: 24,
          background: "#fff",
        }}
      />
    </div>
  );
}
