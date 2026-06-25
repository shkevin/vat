import { describe, it, expect } from "vitest";
import {
  defaultContainerVariantKey,
  containerVariantKey,
  formatContainerVariantOptionLabel,
} from "./assetUtils";
import type { Finding } from "@/types";

function f(
  overrides: Partial<Finding> & Pick<Finding, "id" | "imageDigest" | "tag">,
): Finding {
  return {
    findingType: "SCA",
    fingerprintId: "fp",
    cveId: "CVE-1",
    severity: "High",
    status: "Open",
    sources: [],
    audit: [],
    ...overrides,
  } as Finding;
}

describe("defaultContainerVariantKey", () => {
  it("returns the only key when one variant", () => {
    const findings = [
      f({
        id: "1",
        imageDigest: "sha256:aaa",
        tag: "1.0.0",
        image: "img",
      }),
    ];
    const keys = [...new Set(findings.map(containerVariantKey))];
    expect(defaultContainerVariantKey(keys, findings)).toBe(keys[0]);
  });

  it("prefers variant with highest semver tag", () => {
    const d1 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const d2 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const findings = [
      f({ id: "a", imageDigest: d1, tag: "11.3.3", image: "img" }),
      f({ id: "b", imageDigest: d2, tag: "11.4.2", image: "img" }),
    ];
    const keys = [...new Set(findings.map(containerVariantKey))].sort();
    expect(defaultContainerVariantKey(keys, findings)).toBe(d2);
  });

  it("ignores literal latest for semver pick when numeric tags exist", () => {
    const d1 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const d2 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const findings = [
      f({ id: "a", imageDigest: d1, tag: "latest", image: "img" }),
      f({ id: "b", imageDigest: d2, tag: "2.0.0", image: "img" }),
    ];
    const keys = [...new Set(findings.map(containerVariantKey))].sort();
    expect(defaultContainerVariantKey(keys, findings)).toBe(d2);
  });
});

describe("formatContainerVariantOptionLabel", () => {
  it("shows the image tag only when the tag uniquely identifies a variant", () => {
    const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const findings = [
      f({ id: "a", imageDigest: digest, tag: "v1.2.14", image: "img" }),
    ];

    expect(formatContainerVariantOptionLabel(findings, findings)).toBe("v1.2.14");
  });

  it("adds a short digest only when the same tag maps to multiple variants", () => {
    const d1 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const d2 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const findings = [
      f({ id: "a", imageDigest: d1, tag: "latest", image: "img" }),
      f({ id: "b", imageDigest: d2, tag: "latest", image: "img" }),
    ];
    const firstVariant = findings.filter(
      (finding) => containerVariantKey(finding) === d1,
    );

    expect(formatContainerVariantOptionLabel(firstVariant, findings)).toBe(
      "latest (sha256:aaaaaaaaaaaa…)",
    );
  });
});
