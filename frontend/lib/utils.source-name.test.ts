import { describe, expect, it } from "vitest";
import { displaySourceName } from "./utils";

describe("displaySourceName", () => {
  it("maps feed materialization source to friendly label", () => {
    expect(displaySourceName("vuln_feed_match")).toBe("Feed Match");
  });

  it("still strips scanner prefixes for local sources", () => {
    expect(displaySourceName("vat-local-trivy")).toBe("trivy");
    expect(displaySourceName("folder-scan-grype")).toBe("grype");
  });
});
