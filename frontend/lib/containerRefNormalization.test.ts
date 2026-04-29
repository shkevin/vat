import { describe, it, expect, afterEach } from "vitest";
import {
  inferAssetKindForGrouping,
  normalizeContainerRef,
  applyContainerAssetPathAliases,
  containerDisplayPathWithoutRegistry,
  setContainerAssetPathAliases,
} from "./containerRefNormalization";
import { containerImageGroupKey, getAssetDisplayTitle } from "./assetUtils";

afterEach(() => {
  // Reset alias rules between tests so leakage from one stub doesn't affect others.
  setContainerAssetPathAliases("");
});

describe("normalizeContainerRef parity with backend vectors", () => {
  it("merges bundle-style and docker.io registry paths", () => {
    const a = normalizeContainerRef("containers/images/metrics-server");
    const b = normalizeContainerRef(
      "docker.io/containers/images/metrics-server:1.2.3",
    );
    expect(a.canonicalAssetKey).toBe(b.canonicalAssetKey);
    expect(a.canonicalAssetKey).toBe("docker.io/containers/images/metrics-server");
  });

  it("matches containerImageGroupKey for repo/container kinds", () => {
    const raw = "ghcr.io/acme/svc:1.0.0";
    expect(containerImageGroupKey(raw, null)).toBe(
      normalizeContainerRef(raw).canonicalAssetKey,
    );
  });

  it("applyContainerAssetPathAliases mirrors backend prefix rewrite", () => {
    setContainerAssetPathAliases(
      "docker.io/operators/images/=>docker.io/containers/images/",
    );
    expect(
      applyContainerAssetPathAliases("docker.io/operators/images/etcd"),
    ).toBe("docker.io/containers/images/etcd");
    expect(
      applyContainerAssetPathAliases("docker.io/other/etcd"),
    ).toBe("docker.io/other/etcd");
  });

  it("applyContainerAssetPathAliases strips prefix when target is empty (backend parity)", () => {
    setContainerAssetPathAliases(
      "docker.io/=>;ghcr.io/kamiwaza-internal/=>;registry-1.docker.io/=>",
    );
    expect(
      applyContainerAssetPathAliases("docker.io/containers/images/python"),
    ).toBe("containers/images/python");
    expect(
      applyContainerAssetPathAliases(
        "ghcr.io/kamiwaza-internal/containers/images/python",
      ),
    ).toBe("containers/images/python");
  });

  it("containerImageGroupKey applies path aliases for container kind only", () => {
    setContainerAssetPathAliases(
      "docker.io/operators/images/=>docker.io/containers/images/",
    );
    expect(containerImageGroupKey("docker.io/operators/images/etcd", null)).toBe(
      "docker.io/containers/images/etcd",
    );
  });

  it("leaves package-scope ids unchanged", () => {
    expect(inferAssetKindForGrouping("2026-03-09_1801")).toBe("package_scope");
    expect(containerImageGroupKey("2026-03-09_1801", null)).toBe(
      "2026-03-09_1801",
    );
  });

  it("containerDisplayPathWithoutRegistry drops registry (Iron Bank–style path)", () => {
    expect(
      containerDisplayPathWithoutRegistry(
        "docker.io/containers/images/metrics-server",
      ),
    ).toBe("containers/images/metrics-server");
    expect(
      containerDisplayPathWithoutRegistry("containers/images/metrics-server"),
    ).toBe("containers/images/metrics-server");
    expect(
      containerDisplayPathWithoutRegistry(
        "registry1.dso.mil/a1/caseprocessing/a1caseprocessing",
      ),
    ).toBe("a1/caseprocessing/a1caseprocessing");
  });

  it("getAssetDisplayTitle uses path without registry for containers", () => {
    expect(
      getAssetDisplayTitle({
        id: "docker.io/containers/images/extension-operator",
        name: "docker.io/containers/images/extension-operator",
        type: "container",
      }),
    ).toBe("containers/images/extension-operator");
  });
});
