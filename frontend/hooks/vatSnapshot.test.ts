import { describe, expect, it } from "vitest";
import {
  dehydrateSnapshotAssets,
  rehydrateSnapshotAssets,
} from "./useVATData";
import type { Asset, Finding } from "@/types";

function finding(id: string): Finding {
  return {
    id,
    findingType: "vuln",
    cveId: `CVE-${id}`,
    severity: "High",
    status: "Open",
    archived: false,
    sources: [],
    audit: [],
    attestation: null,
  } as unknown as Finding;
}

function asset(id: string, findings: Finding[]): Asset {
  return {
    id,
    name: id,
    type: "container",
    findings,
    openCount: findings.length,
    inReviewCount: 0,
    statusBreakdown: { Open: findings.length },
    worstSeverity: "High",
    overdueCount: 0,
    verifiedPct: 0,
    oraPct: 50,
  };
}

describe("snapshot asset (de)hydration", () => {
  it("stores finding ids only, then rehydrates from the shared findings array", () => {
    const findings = [finding("f1"), finding("f2"), finding("f3")];
    const assets = [
      asset("a1", [findings[0], findings[1]]),
      asset("a2", [findings[2]]),
    ];

    const dehydrated = dehydrateSnapshotAssets(assets);
    // No nested finding objects survive — only ids (the size win).
    expect(dehydrated[0]).not.toHaveProperty("findings");
    expect(dehydrated[0].findingIds).toEqual(["f1", "f2"]);
    expect(JSON.stringify(dehydrated)).not.toContain("CVE-");

    const rehydrated = rehydrateSnapshotAssets(dehydrated, findings);
    expect(rehydrated[0].findings.map((f) => f.id)).toEqual(["f1", "f2"]);
    expect(rehydrated[1].findings.map((f) => f.id)).toEqual(["f3"]);
    // Rollup fields round-trip untouched.
    expect(rehydrated[0].openCount).toBe(2);
    expect(rehydrated[0].oraPct).toBe(50);
  });

  it("drops ids with no matching finding instead of yielding undefined rows", () => {
    const findings = [finding("f1")];
    const dehydrated = dehydrateSnapshotAssets([asset("a1", [finding("f1"), finding("gone")])]);
    const rehydrated = rehydrateSnapshotAssets(dehydrated, findings);
    expect(rehydrated[0].findings.map((f) => f.id)).toEqual(["f1"]);
  });

  it("passes through legacy snapshots that still nest full findings", () => {
    const findings = [finding("f1")];
    const legacy = [asset("a1", findings)] as unknown as Parameters<
      typeof rehydrateSnapshotAssets
    >[0];
    const rehydrated = rehydrateSnapshotAssets(legacy, []);
    expect(rehydrated[0].findings.map((f) => f.id)).toEqual(["f1"]);
  });
});
