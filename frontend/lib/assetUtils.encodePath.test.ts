import { describe, it, expect } from "vitest";
import { encodeAssetIdPath } from "./assetUtils";

describe("encodeAssetIdPath", () => {
  it("leaves slashes literal so proxies don't reject the path", () => {
    // encodeURIComponent would give docker.io%2Fns%2Fimages%2Fapi, which the
    // reverse proxy in front of this deployment answers 400 for.
    expect(encodeAssetIdPath("docker.io/ns/images/api")).toBe(
      "docker.io/ns/images/api",
    );
    expect(encodeAssetIdPath("docker.io/ns/images/api")).not.toContain("%2F");
  });

  it("still encodes everything else that needs it", () => {
    expect(encodeAssetIdPath("cloud-init 24.4-7.el9_7.1")).toBe(
      "cloud-init%2024.4-7.el9_7.1",
    );
    expect(encodeAssetIdPath("ns/a b/c?d")).toBe("ns/a%20b/c%3Fd");
    expect(encodeAssetIdPath("has#hash")).toBe("has%23hash");
  });

  it("round-trips through the catch-all route's decode", () => {
    for (const id of [
      "docker.io/ns/images/api",
      "cloud-init 24.4-7.el9_7.1",
      "plain",
      "ns/with space/and#hash",
    ]) {
      const decoded = encodeAssetIdPath(id)
        .split("/")
        .map(decodeURIComponent)
        .join("/");
      expect(decoded).toBe(id);
    }
  });

  it("handles empty input", () => {
    expect(encodeAssetIdPath("")).toBe("");
  });
});
