import { describe, it, expect } from "vitest";
import {
  assetTagSortKey,
  containerTagListForAsset,
  pickLatestVersionTag,
} from "./assetUtils";
import type { Asset, Finding } from "@/types";

function minimalFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    findingType: "vuln",
    fingerprintId: "fp",
    cveId: "CVE-2024-1",
    severity: "High",
    status: "Open",
    sources: [],
    audit: [],
    ...overrides,
  };
}

describe("containerTagListForAsset", () => {
  it("dedupes observedTags from API when present", () => {
    const asset: Asset = {
      id: "registry.io/proj/app",
      name: "app",
      type: "container",
      findings: [],
      openCount: 0,
      inReviewCount: 0,
      statusBreakdown: {},
      worstSeverity: "High",
      overdueCount: 0,
      verifiedPct: 100,
      oraPct: 100,
      observedTags: [
        { tag: "1.2.0" },
        { tag: "latest" },
        { tag: "1.2.0" },
      ],
    };
    expect(containerTagListForAsset(asset)).toEqual(["1.2.0", "latest"]);
  });

  it("unions observedTags with tags from findings", () => {
    const asset: Asset = {
      id: "registry.io/proj/app",
      name: "app",
      type: "container",
      findings: [
        minimalFinding({ id: "a", tag: "release-0.11.0" }),
        minimalFinding({ id: "b", tag: "1.2.0" }),
      ],
      openCount: 2,
      inReviewCount: 0,
      statusBreakdown: {},
      worstSeverity: "High",
      overdueCount: 0,
      verifiedPct: 100,
      oraPct: 100,
      observedTags: [{ tag: "1.2.0" }, { tag: "latest" }],
    };
    expect(containerTagListForAsset(asset)).toEqual([
      "1.2.0",
      "latest",
      "release-0.11.0",
    ]);
  });

  it("infers unique tags from findings when observedTags absent", () => {
    const asset: Asset = {
      id: "registry.io/proj/app",
      name: "app",
      type: "container",
      findings: [
        minimalFinding({ id: "a", tag: "v1" }),
        minimalFinding({ id: "b", tag: "v2" }),
        minimalFinding({ id: "c", tag: "v1" }),
      ],
      openCount: 3,
      inReviewCount: 0,
      statusBreakdown: {},
      worstSeverity: "High",
      overdueCount: 0,
      verifiedPct: 0,
      oraPct: 50,
    };
    expect(containerTagListForAsset(asset)).toEqual(["v1", "v2"]);
  });
});

describe("pickLatestVersionTag", () => {
  it("picks highest semver, excludes literal latest as primary", () => {
    const tags = ["11.3.3", "11.4.0", "11.4.2", "latest"];
    const { primary, restCount } = pickLatestVersionTag(tags);
    expect(primary).toBe("11.4.2");
    expect(restCount).toBe(3);
  });

  it("falls back to latest when only tag", () => {
    const { primary, restCount } = pickLatestVersionTag(["latest"]);
    expect(primary).toBe("latest");
    expect(restCount).toBe(0);
  });

  it("returns empty when no tags", () => {
    const { primary, restCount } = pickLatestVersionTag([]);
    expect(primary).toBe("");
    expect(restCount).toBe(0);
  });

  it("sorts non-semver tags last", () => {
    const tags = ["edge", "stable", "11.0.0"];
    const { primary, restCount } = pickLatestVersionTag(tags);
    expect(primary).toBe("11.0.0");
    expect(restCount).toBe(2);
  });
});

describe("assetTagSortKey", () => {
  it("sorts containers by joined tag list", () => {
    const a: Asset = {
      id: "x",
      name: "x",
      type: "container",
      findings: [],
      openCount: 0,
      inReviewCount: 0,
      statusBreakdown: {},
      worstSeverity: "High",
      overdueCount: 0,
      verifiedPct: 100,
      oraPct: 100,
      observedTags: [{ tag: "z" }, { tag: "a" }],
    };
    const b: Asset = {
      ...a,
      id: "y",
      observedTags: [{ tag: "m" }],
    };
    expect(assetTagSortKey(a).localeCompare(assetTagSortKey(b))).toBeLessThan(0);
  });
});
