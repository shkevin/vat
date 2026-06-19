/**
 * Frontend grouping parity test. Loads backend fixture and asserts getFindingGroupKey
 * produces identical keys. Protects against frontend/backend drift.
 * See docs/implementation-plan-grouping-model.md §13.3.
 */

import { describe, it, expect } from "vitest";
import { effectiveGroupKey, getFindingGroupKey } from "./findingGroupUtils";
import type { Finding } from "@/types";
import { FINDING_TYPES } from "@/lib/constants";
// Sync with backend/tests/fixtures/grouping_keys.json when changing grouping logic (§13.3)
import fixture from "@/tests/fixtures/grouping_keys.json";

function fixtureToFinding(item: (typeof fixture.fixtures)[number]): Finding {
  const optional = item as Partial<Record<keyof Finding | "expectedKey", string>>;
  return {
    id: item.id,
    findingType: item.findingType,
    fingerprintId: "fp",
    cveId: item.cveId,
    severity: "High",
    status: "Open",
    sources: [],
    audit: [],
    component: optional.component ?? undefined,
    componentBase: optional.componentBase ?? undefined,
    ecosystem: optional.ecosystem ?? undefined,
    title: optional.title ?? undefined,
    ruleId: optional.ruleId ?? undefined,
    cweId: optional.cweId ?? undefined,
    secretType: optional.secretType ?? undefined,
    image: optional.image ?? undefined,
    branch: optional.branch ?? undefined,
    tag: optional.tag ?? undefined,
    benchmarkFamily: optional.benchmarkFamily ?? undefined,
  };
}

describe("getFindingGroupKey fixture parity", () => {
  it("produces keys matching backend fixture for all finding types", () => {
    for (const item of fixture.fixtures) {
      const finding = fixtureToFinding(item);
      const key = getFindingGroupKey(finding);
      expect(key).toBe(item.expectedKey);
    }
  });

  it("fixture covers all finding types (CI guard)", () => {
    const fixtureTypes = new Set(
      fixture.fixtures.map((f) => f.findingType.toUpperCase()),
    );
    for (const ft of Object.keys(FINDING_TYPES)) {
      expect(fixtureTypes.has(ft.toUpperCase())).toBe(true);
    }
  });
});

describe("effectiveGroupKey", () => {
  it("matches getFindingGroupKey when groupKey is absent", () => {
    const item = fixture.fixtures[0];
    if (!item) throw new Error("fixture empty");
    const finding = fixtureToFinding(item);
    expect(effectiveGroupKey(finding)).toBe(getFindingGroupKey(finding));
  });

  it("prefers server-provided groupKey when set", () => {
    const item = fixture.fixtures[0];
    if (!item) throw new Error("fixture empty");
    const finding = {
      ...fixtureToFinding(item),
      groupKey: "sca:server-authoritative|pkg#||",
    };
    expect(effectiveGroupKey(finding)).toBe("sca:server-authoritative|pkg#||");
  });
});
