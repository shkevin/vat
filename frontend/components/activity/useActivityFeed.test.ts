import { describe, expect, it } from "vitest";

import type { ApiAuditEvent } from "@/lib/api";
import type { ActivityEvent } from "@/types/activity";
import { rollupFindingEvents, toSystemEvent } from "./useActivityFeed";

describe("toSystemEvent", () => {
  it("formats ingest rollup windows with readable title and detail", () => {
    const row: ApiAuditEvent = {
      eventId: "evt-rollup-1",
      traceId: "trace-1",
      eventType: "ingest.rollup.window",
      createdAt: "2026-04-04T12:00:00Z",
      data: {
        sourceId: "vat-local-trivy",
        parserId: "sarif",
        dedupNewCount: 12,
        dedupMergedCount: 7,
        failed: 1,
        windowDurationSec: 19.3,
        flushReason: "timeout",
        sampledMappings: [{ assetId: "a1" }],
        sampledDedup: [{ findingId: "f1" }, { findingId: "f2" }],
        sampledFailures: [{ cveId: "CVE-1" }],
      },
    };

    const event = toSystemEvent(row);
    expect(event.kind).toBe("ingest");
    expect(event.title).toBe("Ingest window: 12 created, 7 merged, 1 failed");
    expect(event.detail).toContain("source: vat-local-trivy");
    expect(event.detail).toContain("parser: sarif");
    expect(event.detail).toContain("window: 19.3s");
    expect(event.detail).toContain("flush: timeout");
    expect(event.detail).toContain("samples: 1 mappings, 2 dedup, 1 failures");
  });

  it("keeps non-rollup system events unchanged", () => {
    const row: ApiAuditEvent = {
      eventId: "evt-generic-1",
      traceId: "trace-2",
      eventType: "sync.queue.processed",
      createdAt: "2026-04-04T12:00:00Z",
      data: { count: 3 },
    };
    const event = toSystemEvent(row);
    expect(event.kind).toBe("sync");
    expect(event.title).toBe("sync.queue.processed");
  });

  it("rolls up noisy finding events per asset with snapshot summary", () => {
    const rows: ActivityEvent[] = [
      {
        id: "e1",
        source: "finding",
        kind: "decision",
        eventType: "finding.audit",
        timestamp: "2026-04-04T12:00:08Z",
        title: "License finding from SBOM",
        findingId: "f-1",
        assetId: "asset-a",
        assetName: "team/app-a",
        severity: "High",
      },
      {
        id: "e2",
        source: "finding",
        kind: "decision",
        eventType: "finding.audit",
        timestamp: "2026-04-04T12:00:19Z",
        title: "License finding from SBOM",
        findingId: "f-2",
        assetId: "asset-a",
        assetName: "team/app-a",
        severity: "High",
      },
      {
        id: "e3",
        source: "finding",
        kind: "decision",
        eventType: "finding.audit",
        timestamp: "2026-04-04T12:00:42Z",
        title: "Imported from Aikido scan",
        findingId: "f-3",
        assetId: "asset-a",
        assetName: "team/app-a",
        severity: "Medium",
      },
      {
        id: "e4",
        source: "finding",
        kind: "decision",
        eventType: "finding.audit",
        timestamp: "2026-04-04T12:00:50Z",
        title: "License finding from SBOM",
        findingId: "f-4",
        assetId: "asset-b",
      },
    ];

    const rolled = rollupFindingEvents(rows);
    const assetARollup = rolled.find(
      (row) => row.eventType === "finding.audit.rollup.asset" && row.assetId === "asset-a",
    );
    expect(assetARollup).toBeTruthy();
    expect(assetARollup?.title).toBe("team/app-a: activity rollup (3 updates)");
    expect(assetARollup?.detail).toContain("severity: High ×2, Medium ×1");
    expect(assetARollup?.detail).toContain("License finding from SBOM ×2");
    expect(assetARollup?.relatedFindingIds).toEqual(["f-1", "f-2", "f-3"]);
    expect(assetARollup?.relatedFindings?.length).toBe(3);
    expect(assetARollup?.relatedFindings?.[0]?.id).toBe("f-1");
    expect(assetARollup?.relatedFindings?.[0]?.title).toBe("License finding from SBOM");
    const assetBOriginal = rolled.find((row) => row.id === "e4");
    expect(assetBOriginal).toBeTruthy();
  });
});
