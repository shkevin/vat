/**
 * Asset derivation utilities — shared between useVATData and AssetPage.
 * ORA aligned with Iron Bank (0–100, higher = safer).
 */

import { computeORAScore } from "./report/ora";
import { daysLeft } from "./utils";
import type { AssetType } from "./constants";
import type { Asset, Finding } from "@/types";

/** Prefer sourceGroupSeverity when available for consistency with report engine. */
function severityToKey(sev: string, sourceGroupSeverity?: string | null): "critical" | "high" | "medium" | "low" | "info" {
    const s = ((sourceGroupSeverity?.trim() || sev) ?? "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium" || s === "moderate") return "medium";
  if (s === "low") return "low";
  return "info";
}

/**
 * Asset key for grouping — image or component only. Branches are shown in the asset page dropdown.
 */
function assetKey(f: Finding): string {
  const img = f.image?.trim();
  const comp = f.component?.trim();
  if (img) return img;
  if (comp) return comp;
  return `unknown-${f.id}`;
}

/** Return the asset id for a finding (same logic as assetKey). Used for filtering findings by asset. */
export function assetIdForFinding(f: Finding): string {
  return assetKey(f);
}

/** Extract tag/version from a finding (component version or image:tag). */
export function getFindingTag(f: Finding): string | undefined {
  const c = f.component?.trim();
  const img = f.image?.trim();
  const verMatch = c?.match(/\d+\.\d+(\.\d+)?/);
  if (verMatch) return verMatch[0];
  if (img?.includes(":")) return img.split(":")[1];
  return f.tag ?? undefined;
}

/** Compute verifiedPct and oraPct from a list of findings. */
export function computeMetricsFromFindings(
  findings: Finding[],
  sevOrder: readonly string[]
): { verifiedPct: number; oraPct: number } {
  if (findings.length === 0) return { verifiedPct: 100, oraPct: 100 };
  let verifiedCount = 0;
  for (const f of findings) {
    if (["Resolved", "False Positive", "Approved", "Suppressed", "Not Applicable", "Duplicate"].includes(f.status ?? ""))
      verifiedCount++;
  }
  const verifiedPct = Math.round((verifiedCount / findings.length) * 1000) / 10;
  const openFindings = findings.filter(
    (f) =>
      !["Resolved", "False Positive", "Duplicate", "Not Applicable", "Approved", "Suppressed"].includes(f.status ?? "")
  );
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of openFindings) {
    counts[severityToKey(f.severity ?? "", f.sourceGroupSeverity)]++;
  }
  const oraPct = openFindings.length > 0 ? computeORAScore(counts) : 100;
  return { verifiedPct, oraPct };
}

/** Finding types that indicate code/SAST/Secret/IaC — used to distinguish code repos from containers. */
const CODE_FINDING_TYPES = new Set(["sast", "secret", "iac"]);

/** Derive asset type from asset id and findings. ASSET_TYPES: repo, container, package, path. */
export function getAssetTypeFromAsset(asset: Asset): AssetType {
  const id = asset.id ?? asset.name ?? "";
  // Repo/container from API Asset record (for 0-finding assets)
  if (asset.type === "repo") return "repo";
  if (asset.type === "container") return "container";
  // Infer from first finding when available — check finding fields before id heuristics,
  // since package identifiers (npm:pkg, maven:g:a, component:version) often contain ":" too
  const f = asset.findings?.[0];
  if (f) {
    const hasImage = !!(f.image?.trim());
    const hasBranch = !!(f.branch?.trim());
    const hasComponent = !!(f.component?.trim());
    const hasFilePath = !!(f.filePath?.trim());
    const findingType = (f.findingType ?? "").toLowerCase();
    const isCodeFinding = CODE_FINDING_TYPES.has(findingType);
    // image + branch = code repo (e.g. Aikido SAST with branch)
    if (hasImage && hasBranch) return "repo";
    // image + code finding type (SAST/Secret/IaC) = code repo — Aikido code often has image but no branch
    if (hasImage && isCodeFinding) return "repo";
    // image without branch/code-type = container (CVE, License, etc.)
    if (hasImage) return "container";
    if (hasFilePath && !hasImage && !hasComponent) return "path";
    // file_path + code finding type = code repo — Aikido SAST/Secret/IaC keyed by component (no image)
    // when code_repo_name is missing; otherwise they get misclassified as package
    if (hasFilePath && isCodeFinding) return "repo";
    if (hasComponent) return "package";
  }
  // Fallback for 0-finding assets: id with ":" is likely container (registry/image:tag)
  if (id.includes(":")) return "container";
  return "package";
}

/** Derive assets from findings — group by image or component. Assets can be VMs, repos, containers, packages, IaC, etc. */
export function deriveAssets(
  findings: Finding[],
  sevOrder: readonly string[]
): Asset[] {
  const byKey = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = assetKey(f);
    const list = byKey.get(key) ?? [];
    list.push(f);
    byKey.set(key, list);
  }
  return Array.from(byKey.entries()).map(([key, list]) => {
    const statusBreakdown: Record<string, number> = {};
    let openCount = 0;
    let inReviewCount = 0;
    let overdueCount = 0;
    let verifiedCount = 0;
    let worstIdx = -1;
    for (const f of list) {
      statusBreakdown[f.status] = (statusBreakdown[f.status] ?? 0) + 1;
      if (f.status === "Open") openCount++;
      if (f.status === "In Review") inReviewCount++;
      if (
        !["Resolved", "False Positive", "Duplicate", "Not Applicable", "Approved", "Suppressed"].includes(f.status)
      ) {
        const d = daysLeft(f.slaDue);
        if (d !== null && d < 0) overdueCount++;
      }
      if (["Resolved", "False Positive", "Approved", "Suppressed", "Not Applicable", "Duplicate"].includes(f.status))
        verifiedCount++;
      const idx = sevOrder.indexOf(f.severity);
      if (idx >= 0 && (worstIdx < 0 || idx < worstIdx)) worstIdx = idx;
    }
    const verifiedPct = list.length > 0 ? Math.round((verifiedCount / list.length) * 1000) / 10 : 100;
    const openFindings = list.filter(
      (f) =>
        !["Resolved", "False Positive", "Duplicate", "Not Applicable", "Approved", "Suppressed"].includes(f.status)
    );
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of openFindings) {
      counts[severityToKey(f.severity ?? "", f.sourceGroupSeverity)]++;
    }
    const oraPct = openFindings.length > 0 ? computeORAScore(counts) : 100;
    const tag = (() => {
      const c = list[0]?.component;
      const img = list[0]?.image;
      const verMatch = c?.match(/\d+\.\d+(\.\d+)?/);
      if (verMatch) return verMatch[0];
      if (img?.includes(":")) return img.split(":")[1];
      return undefined;
    })();
    return {
      id: key,
      name: key,
      tag,
      findings: list,
      openCount,
      inReviewCount,
      statusBreakdown,
      worstSeverity: worstIdx >= 0 ? sevOrder[worstIdx] : "Informational",
      overdueCount,
      verifiedPct,
      oraPct,
    };
  });
}

/** Get a single asset by id from findings. Returns null if not found. */
export function getAssetById(
  findings: Finding[],
  assetId: string,
  sevOrder: readonly string[]
): Asset | null {
  const assets = deriveAssets(findings, sevOrder);
  return assets.find((a) => a.id === assetId) ?? null;
}
