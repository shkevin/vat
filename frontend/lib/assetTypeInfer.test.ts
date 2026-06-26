import { describe, expect, it } from "vitest";
import { getAssetTypeFromAsset } from "./assetUtils";
import { isKnownApiAssetType, looksLikeKubernetesNodeAsset } from "./assetTypeInfer";
import type { Asset } from "@/types";

const baseAsset: Omit<Asset, "id" | "name"> = {
  type: undefined,
  findings: [],
  openCount: 0,
  inReviewCount: 0,
  statusBreakdown: {},
  worstSeverity: "Informational",
  overdueCount: 0,
  verifiedPct: 100,
  oraPct: 100,
};

describe("asset type inference", () => {
  it("recognizes Kubernetes node assets", () => {
    const id = "k8s/k3s-remote/cluster/node/k3s-agent-1";

    expect(isKnownApiAssetType("node")).toBe(true);
    expect(looksLikeKubernetesNodeAsset(id)).toBe(true);
    expect(getAssetTypeFromAsset({ ...baseAsset, id, name: id })).toBe("node");
  });
});
