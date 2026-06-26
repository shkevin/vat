import { describe, expect, it } from "vitest";

import { chooseFindingForDetail, toDetailFinding } from "./findingDetail";
import type { ApiFinding } from "./api";
import type { Finding } from "@/types";

function finding(id: string, auditCount: number): Finding {
  return {
    id,
    findingType: "SCA",
    fingerprintId: `fp-${id}`,
    cveId: `CVE-${id}`,
    severity: "High",
    status: "Open",
    audit: Array.from({ length: auditCount }, (_, index) => ({
      ts: `2026-06-26T00:00:0${index}Z`,
      user: "reviewer@example.com",
      action: `Action ${index}`,
      note: null,
    })),
  };
}

describe("finding detail mapping", () => {
  it("preserves full audit history from the detail API response", () => {
    const raw = {
      id: "f-1",
      findingType: "SCA",
      fingerprintId: "fp-1",
      cveId: "CVE-2026-0001",
      severity: "High",
      status: "Open",
      audit: [
        {
          ts: "2026-06-26T00:00:00Z",
          user: "reviewer@example.com",
          action: "Finding updated",
          note: "triaged",
        },
      ],
      sources: [{ name: "trivy", importedAt: "2026-06-26T00:00:00Z" }],
      externalLinks: [{ kind: "tracker", url: "https://linear.example/ABC-1" }],
    } as ApiFinding;

    const mapped = toDetailFinding(raw);

    expect(mapped.audit).toEqual(raw.audit);
    expect(mapped.sources).toEqual(raw.sources);
    expect(mapped.externalLinks).toEqual(raw.externalLinks);
  });

  it("prefers a selected finding with newer audit over a stale detail snapshot", () => {
    const selected = finding("f-1", 2);
    const staleDetail = finding("f-1", 1);

    expect(chooseFindingForDetail(selected, staleDetail)).toBe(selected);
  });
});
