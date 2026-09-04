import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * The export bundle must cover what is on screen. Without a scope it refetched
 * every finding in the workspace, so an applied team loadout was silently
 * ignored and the ZIP shipped all of them.
 */
const fetchVATData = vi.fn();
const fetchSbomPackages = vi.fn(async () => []);

vi.mock("@/lib/api", () => ({
  fetchVATData: (...a: unknown[]) => fetchVATData(...a),
  fetchSbomPackages: (...a: unknown[]) => fetchSbomPackages(...a),
}));

// The bundle writes a ZIP and triggers a download; neither is under test here.
vi.mock("jszip", () => ({
  default: class {
    folder() {
      return { file: () => {} };
    }
    generateAsync() {
      return Promise.resolve(new Uint8Array());
    }
  },
}));

const { buildAndDownloadExportBundle } = await import("./exportBundle");

const asset = { id: "docker.io/ns/api", findings: [] } as never;
const finding = { id: "f1", severity: "High", status: "Open" } as never;

beforeEach(() => {
  fetchVATData.mockReset();
  fetchVATData.mockResolvedValue({ findings: [], assets: [] });
  // Node env: give the download path something to bind to.
  (globalThis as Record<string, unknown>).URL ??= {};
  const u = (globalThis as { URL: Record<string, unknown> }).URL;
  u.createObjectURL ??= () => "blob:x";
  u.revokeObjectURL ??= () => {};
});

describe("export bundle scope", () => {
  it("uses the supplied scope and does not refetch the workspace", async () => {
    await buildAndDownloadExportBundle(undefined, {
      findings: [finding],
      assets: [asset],
    }).catch(() => {
      /* download step may no-op outside a browser; the fetch assertion is the point */
    });
    expect(fetchVATData).not.toHaveBeenCalled();
  });

  it("falls back to fetching when no scope is given", async () => {
    await buildAndDownloadExportBundle().catch(() => {});
    expect(fetchVATData).toHaveBeenCalledOnce();
    expect(fetchVATData.mock.calls[0][0]).toMatchObject({ full: true });
  });
});
