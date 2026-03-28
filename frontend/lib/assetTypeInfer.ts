/**
 * Asset scope type — mirrors backend app.services.asset_type_infer.
 * Used when API omits type (deriveAssets) and as a fallback; prefer asset.type from API.
 */

import type { Finding } from "@/types";
import { ASSET_TYPES, type AssetType } from "@/lib/constants";

const TYPE_PRIORITY: Record<AssetType, number> = {
  container: 4,
  repo: 3,
  path: 2,
  package: 1,
};

const CODE_FINDING_TYPES = new Set(["sast", "secret", "iac"]);
const CONTAINER_BIAS_SOURCES = new Set(["openscap", "openscap_oval"]);

export function looksLikeContainerImageRef(image: string | undefined): boolean {
  const s = (image ?? "").trim();
  if (!s || s.startsWith("path:")) return false;
  if (s.includes("/images/")) return true;
  if (s.includes("@sha256:")) return true;
  if (!s.includes(":")) return false;
  const before = s.split(":", 1)[0]!;
  if (before.includes("/")) return true;
  return /^[a-z0-9._-]+$/i.test(before);
}

function inferAssetTypeFromOneFinding(f: Finding): AssetType {
  const img = f.image?.trim() ?? "";
  const branch = f.branch?.trim() ?? "";
  const comp = f.component?.trim() ?? "";
  const fp = f.filePath?.trim() ?? "";
  const ft = (f.findingType ?? "").toLowerCase();
  const src = (f.source ?? "").trim().toLowerCase();
  const isCode = CODE_FINDING_TYPES.has(ft);

  if (ft === "secret") {
    if (branch) return "repo";
    if (img && looksLikeContainerImageRef(f.image)) return "container";
    return "path";
  }

  if (CONTAINER_BIAS_SOURCES.has(src) && img) return "container";

  if (img.includes("/images/")) return "container";

  if (img && branch) return "repo";
  if (img && isCode) return "repo";
  if (img && looksLikeContainerImageRef(f.image)) return "container";
  if (img) return "container";
  if (fp && !img && !comp) return "path";
  if (fp && isCode) return "repo";
  if (comp) return "package";
  return "package";
}

/** Merge per-finding types (container > repo > path > package). */
export function inferAssetTypeFromFindings(findings: Finding[]): AssetType {
  if (findings.length === 0) return "package";
  const candidates = findings.map(inferAssetTypeFromOneFinding);
  return candidates.reduce((a, b) =>
    TYPE_PRIORITY[a] >= TYPE_PRIORITY[b] ? a : b,
  );
}

export function isKnownApiAssetType(t: string | undefined): t is AssetType {
  const u = (t ?? "").trim().toLowerCase();
  return (ASSET_TYPES as readonly string[]).includes(u);
}
