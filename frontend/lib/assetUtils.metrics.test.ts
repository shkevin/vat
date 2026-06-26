import { describe, expect, it } from "vitest";
import { deriveAssets } from "./assetUtils";
import type { Finding } from "@/types";

function finding(
  id: string,
  status: string,
  severity: string,
  slaDue = "2026-06-17T00:00:00Z",
): Finding {
  return {
    id,
    findingType: "SCA",
    fingerprintId: `${id}-fingerprint`,
    cveId: id,
    severity,
    status,
    component: "openssl 3.0",
    title: id,
    sources: [],
    audit: [],
    archived: false,
    trackerComment: false,
    slaDue,
  } as Finding;
}

describe("deriveAssets metric rollups", () => {
  it("keeps risk-accepted findings out of open-risk, overdue, and ORA rollups", () => {
    const assets = deriveAssets(
      [
        finding("waived-critical", "Risk Accepted", "Critical"),
        finding("reopened-high", "Reopened", "High"),
        finding("resolved-medium", "Resolved", "Medium"),
      ],
      ["Critical", "High", "Medium", "Low", "Informational"],
    );

    expect(assets).toHaveLength(1);
    expect(assets[0].openCount).toBe(1);
    expect(assets[0].overdueCount).toBe(1);
    expect(assets[0].verifiedPct).toBe(33.3);
    expect(assets[0].oraPct).toBe(96);
  });

  it("hides Kubernetes object paths from the main asset list", () => {
    const assets = deriveAssets(
      [
        {
          ...finding("svc", "Open", "Low"),
          image: "k8s/k3s-remote/monitoring/service/alloy",
          component: "Service alloy",
        },
        {
          ...finding("pod", "Open", "Low"),
          image: "k8s/k3s-remote/monitoring/pod/alloy-k2x27/alloy",
          component: "alloy",
        },
        {
          ...finding("container", "Open", "Low"),
          image: "ghcr.io/acme/alloy:v1",
          component: "alloy",
        },
      ],
      ["Critical", "High", "Medium", "Low", "Informational"],
    );

    expect(assets.map((asset) => asset.id)).toEqual(["ghcr.io/acme/alloy"]);
  });
});
