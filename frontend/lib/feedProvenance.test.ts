import { describe, expect, it } from "vitest";

import { getFeedProvenanceFromSources } from "./feedProvenance";

describe("getFeedProvenanceFromSources", () => {
  it("returns feed-match provenance entry when metadata exists", () => {
    const row = getFeedProvenanceFromSources([
      { name: "trivy-ci", importedAt: "2026-04-01T00:00:00Z" },
      {
        name: "vuln_feed_match",
        importedAt: "2026-04-01T01:00:00Z",
        feedSource: "osv",
        matchStrategy: "name+version+ecosystem",
        matchConfidence: "high",
        matchedPackage: "axios",
        matchedVersion: "1.7.9",
      },
    ]);
    expect(row?.feedSource).toBe("osv");
    expect(row?.matchStrategy).toBe("name+version+ecosystem");
  });

  it("returns undefined when feed source has no provenance fields", () => {
    const row = getFeedProvenanceFromSources([
      { name: "vuln_feed_match", importedAt: "2026-04-01T01:00:00Z" },
    ]);
    expect(row).toBeUndefined();
  });
});
