import { describe, expect, it } from "vitest";
import {
  buildSourceFilterOptions,
  sourceFilterKey,
} from "./sourceFilterOptions";

describe("sourceFilterOptions", () => {
  it("collapses source variants by display name and combines counts", () => {
    const options = buildSourceFilterOptions(
      [
        { source: "vat-local-trivy" },
        { source: "folder-scan-trivy" },
        { source: "trivy" },
        { source: "folder-scan-grype" },
      ],
      [
        { id: "folder-scan-trivy", name: "Folder Scan (trivy)" },
        { id: "manual-trivy", name: "Folder Scan (trivy)" },
        { id: "openscap", name: "OpenSCAP" },
      ],
    );

    expect(options).toEqual([
      { value: "grype", label: "grype (1)" },
      { value: "openscap", label: "OpenSCAP (0)" },
      { value: "trivy", label: "trivy (3)" },
    ]);
  });

  it("uses the same normalized key for filtering raw scanner variants", () => {
    expect(sourceFilterKey("vat-local-trivy")).toBe("trivy");
    expect(sourceFilterKey("folder-scan-trivy")).toBe("trivy");
    expect(sourceFilterKey("trivy")).toBe("trivy");
  });
});
