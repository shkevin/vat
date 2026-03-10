/**
 * Frontend grouping parity test. Loads backend fixture and asserts getFindingGroupKey
 * produces identical keys. Protects against frontend/backend drift.
 * See docs/implementation-plan-grouping-model.md §13.3.
 */

import { describe, it, expect } from "vitest";
import { getFindingGroupKey } from "./findingGroupUtils";
import type { Finding } from "@/types";
import { FINDING_TYPES } from "@/lib/constants";
// Sync with backend/tests/fixtures/grouping_keys.json when changing grouping logic (§13.3)
import fixture from "@/tests/fixtures/grouping_keys.json";

function fixtureToFinding(item: (typeof fixture.fixtures)[number]): Finding {
  return {
    id: item.id,
    findingType: item.findingType,
    fingerprintId: "fp",
    cveId: item.cveId,
    severity: "High",
    status: "Open",
    sources: [],
    audit: [],
    component: item.component ?? undefined,
    componentBase: item.componentBase ?? undefined,
    ecosystem: item.ecosystem ?? undefined,
    title: item.title ?? undefined,
    ruleId: item.ruleId ?? undefined,
    cweId: item.cweId ?? undefined,
    secretType: item.secretType ?? undefined,
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
    const fixtureTypes = new Set(fixture.fixtures.map((f) => f.findingType.toUpperCase()));
    for (const ft of Object.keys(FINDING_TYPES)) {
      expect(fixtureTypes.has(ft.toUpperCase())).toBe(true);
    }
  });
});
