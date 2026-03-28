import { describe, it, expect } from "vitest";
import { SEV_ORDER } from "@/lib/constants";
import {
  sameAssetIdentity,
  collectFindingsForAssetIdentity,
  resolveAssetForPage,
  mergeSuggestionTargetAlreadyRepresentedOnAsset,
} from "./assetUtils";
import type { Asset, Finding } from "@/types";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    findingType: "SCA",
    fingerprintId: "fp",
    cveId: "CVE-2024-1",
    severity: "High",
    status: "Open",
    sources: [],
    audit: [],
    ...overrides,
  };
}

describe("sameAssetIdentity", () => {
  it("treats docker.io and bare path as same container", () => {
    expect(
      sameAssetIdentity(
        "docker.io/containers/images/extension-operator",
        "containers/images/extension-operator",
      ),
    ).toBe(true);
  });

  it("is false for different images", () => {
    expect(
      sameAssetIdentity(
        "docker.io/containers/images/a",
        "docker.io/containers/images/b",
      ),
    ).toBe(false);
  });
});

describe("collectFindingsForAssetIdentity", () => {
  it("collects findings across image ref variants", () => {
    const findings = [
      finding({
        id: "1",
        image: "docker.io/containers/images/extension-operator",
        tag: "t1",
      }),
      finding({
        id: "2",
        image: "containers/images/extension-operator",
        tag: "t2",
      }),
      finding({ id: "3", image: "docker.io/other/image", tag: "x" }),
    ];
    const out = collectFindingsForAssetIdentity(
      "containers/images/extension-operator",
      findings,
    );
    expect(out.map((f) => f.id).sort()).toEqual(["1", "2"]);
  });
});

describe("resolveAssetForPage", () => {
  it("merges findings and keeps API id and observedTags", () => {
    const findings = [
      finding({
        id: "1",
        image: "docker.io/containers/images/extension-operator",
        tag: "a",
      }),
      finding({
        id: "2",
        image: "containers/images/extension-operator",
        tag: "b",
      }),
    ];
    const reportAssets: Asset[] = [
      {
        id: "containers/images/extension-operator",
        name: "containers/images/extension-operator",
        type: "container",
        findings: [findings[1]!],
        openCount: 1,
        inReviewCount: 0,
        statusBreakdown: {},
        worstSeverity: "High",
        overdueCount: 0,
        verifiedPct: 0,
        oraPct: 50,
        observedTags: [{ tag: "from-api" }],
      },
    ];
    const asset = resolveAssetForPage(
      "containers/images/extension-operator",
      reportAssets,
      findings,
      SEV_ORDER,
    );
    expect(asset).not.toBeNull();
    expect(asset!.id).toBe("containers/images/extension-operator");
    expect(asset!.findings.map((f) => f.id).sort()).toEqual(["1", "2"]);
    expect(asset!.observedTags).toEqual([{ tag: "from-api" }]);
  });
});

describe("mergeSuggestionTargetAlreadyRepresentedOnAsset", () => {
  it("is true when a finding uses the target image id", () => {
    const asset: Pick<Asset, "id" | "findings"> = {
      id: "containers/images/extension-operator",
      findings: [
        finding({
          id: "1",
          image: "docker.io/containers/images/extension-operator",
        }),
      ],
    };
    expect(
      mergeSuggestionTargetAlreadyRepresentedOnAsset(
        "docker.io/containers/images/extension-operator",
        asset,
      ),
    ).toBe(true);
  });

  it("is false for a distinct merge target", () => {
    const asset: Pick<Asset, "id" | "findings"> = {
      id: "containers/images/a",
      findings: [finding({ id: "1", image: "containers/images/a" })],
    };
    expect(
      mergeSuggestionTargetAlreadyRepresentedOnAsset(
        "containers/images/b",
        asset,
      ),
    ).toBe(false);
  });
});
