/**
 * Asset derivation utilities — shared between useVATData and AssetPage.
 * ORA aligned with Iron Bank (0–100, higher = safer).
 */

import { computeORAScore } from "./report/ora";
import { daysLeft } from "./utils";
import type { AssetType } from "./constants";
import type { Asset, Finding } from "@/types";
import {
  inferAssetTypeFromFindings,
  isKnownApiAssetType,
} from "./assetTypeInfer";
import {
  inferAssetKindForGrouping,
  normalizeContainerRef,
  applyContainerAssetPathAliases,
  containerDisplayPathWithoutRegistry,
} from "./containerRefNormalization";

function severityToKey(
  sev: string,
  _sourceGroupSeverity?: string | null,
): "critical" | "high" | "medium" | "low" | "info" {
  const s = (sev ?? "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium" || s === "moderate") return "medium";
  if (s === "low") return "low";
  return "info";
}

/**
 * One row per logical image (canonical registry path), not per tag.
 * Aligns with backend normalize_container_ref + infer_asset_kind (same family as correlation ingest).
 */
export function containerImageGroupKey(
  image: string,
  _tag?: string | null,
): string {
  const img = image.trim();
  if (!img) return img;
  const kind = inferAssetKindForGrouping(img);
  if (kind === "container" || kind === "repo") {
    return applyContainerAssetPathAliases(
      normalizeContainerRef(img).canonicalAssetKey,
    );
  }
  return img;
}

/**
 * Asset key for grouping — image or component only. Branches/tags are shown on the asset page.
 */
function assetKey(f: Finding): string {
  const img = f.image?.trim();
  const comp = f.component?.trim();
  if (img) return containerImageGroupKey(img, f.tag);
  if (comp) return comp;
  return `unknown-${f.id}`;
}

/** Return the asset id for a finding (same logic as assetKey). Used for filtering findings by asset. */
export function assetIdForFinding(f: Finding): string {
  return assetKey(f);
}

/**
 * True when two asset id strings refer to the same logical asset (e.g. registry
 * prefix vs path-only container refs that normalize to the same canonical key).
 */
export function sameAssetIdentity(a: string, b: string): boolean {
  const ta = (a ?? "").trim();
  const tb = (b ?? "").trim();
  if (!ta || !tb) return ta === tb;
  if (ta === tb) return true;
  const ka = inferAssetKindForGrouping(ta);
  const kb = inferAssetKindForGrouping(tb);
  if (ka === "container" && kb === "container") {
    return containerImageGroupKey(ta) === containerImageGroupKey(tb);
  }
  return false;
}

/** All findings that belong to the same logical asset id as `assetId`. */
export function collectFindingsForAssetIdentity(
  assetId: string,
  findings: Finding[],
): Finding[] {
  const id = (assetId ?? "").trim();
  if (!id) return [];
  return findings.filter((f) => sameAssetIdentity(assetIdForFinding(f), id));
}

/**
 * Merge suggestion target is redundant when it is the same logical image as this
 * asset or already appears as a finding's `image` on the page.
 */
export function mergeSuggestionTargetAlreadyRepresentedOnAsset(
  targetAssetId: string,
  asset: Pick<Asset, "id" | "findings">,
): boolean {
  const tid = (targetAssetId ?? "").trim();
  if (!tid) return true;
  if (sameAssetIdentity(tid, asset.id)) return true;
  for (const f of asset.findings ?? []) {
    const img = f.image?.trim();
    if (img && sameAssetIdentity(img, tid)) return true;
  }
  return false;
}

/**
 * Resolve the asset page model: union findings across image ref variants (same
 * canonical container key) and preserve API-only fields (`observedTags`, digest
 * conflicts) from `reportAssets` when present.
 */
export function resolveAssetForPage(
  assetId: string,
  reportAssets: Asset[],
  allFindings: Finding[],
  sevOrder: readonly string[],
): Asset | null {
  const related = collectFindingsForAssetIdentity(assetId, allFindings);
  const apiMatch = reportAssets.find((a) => sameAssetIdentity(a.id, assetId));

  if (related.length === 0) {
    return apiMatch ?? null;
  }

  const derivedList = deriveAssets(related, sevOrder);
  const matchDerived =
    derivedList.find((a) => sameAssetIdentity(a.id, assetId)) ??
    derivedList[0] ??
    null;
  if (!matchDerived) return apiMatch ?? null;

  if (!apiMatch) return matchDerived;

  return {
    ...matchDerived,
    id: apiMatch.id,
    name: apiMatch.name ?? matchDerived.name,
    type: apiMatch.type ?? matchDerived.type,
    observedTags: apiMatch.observedTags ?? matchDerived.observedTags,
    digestConflictOpen:
      apiMatch.digestConflictOpen ?? matchDerived.digestConflictOpen,
    digestConflicts: apiMatch.digestConflicts ?? matchDerived.digestConflicts,
  };
}

const SHA256_HEX = /^[0-9a-f]{12,64}$/i;

/** Normalize digest to ``sha256:<hex>`` or undefined. */
export function normalizeImageDigestString(
  raw: string | undefined,
): string | undefined {
  if (!raw?.trim()) return undefined;
  const s = raw.trim().toLowerCase();
  const hex = s.startsWith("sha256:")
    ? s
        .slice(7)
        .replace(/[^0-9a-f]/g, "")
        .slice(0, 64)
    : s.replace(/[^0-9a-f]/g, "").slice(0, 64);
  if (hex.length < 12 || !SHA256_HEX.test(hex)) return undefined;
  return `sha256:${hex}`;
}

function extractDigestFromImageField(
  image: string | undefined,
): string | undefined {
  if (!image?.includes("@sha256:")) return undefined;
  const part = image.split("@sha256:", 2)[1] ?? "";
  const hex = part
    .replace(/[^0-9a-f]/gi, "")
    .toLowerCase()
    .slice(0, 64);
  return normalizeImageDigestString(hex ? `sha256:${hex}` : undefined);
}

/** Prefer stored imageDigest; else parse ``@sha256:`` from image reference. */
export function getFindingImageDigest(f: Finding): string | undefined {
  const fromField = normalizeImageDigestString(f.imageDigest);
  if (fromField) return fromField;
  return extractDigestFromImageField(f.image);
}

/**
 * Stable key for container “variant” filtering: digest when known, else one slot per tag
 * (legacy data without digest).
 */
export function containerVariantKey(f: Finding): string {
  const d = getFindingImageDigest(f);
  if (d) return d;
  const tag = f.tag?.trim() || getFindingTag(f) || "";
  return `tag:${tag || "latest"}`;
}

/** Short label for digest chips (Docker Hub–style). */
export function formatDigestShort(digest: string | undefined): string {
  if (!digest?.startsWith("sha256:")) return digest ?? "—";
  const h = digest.slice(7, 19);
  return h ? `sha256:${h}…` : digest;
}

/** Extract image tag for filtering (prefer finding.tag; avoid package version as tag for containers). */
export function getFindingTag(f: Finding): string | undefined {
  const explicit = f.tag?.trim();
  if (explicit) return explicit;
  const img = f.image?.trim();
  if (img?.includes("/images/")) {
    return undefined;
  }
  const c = f.component?.trim();
  const verMatch = c?.match(/\d+\.\d+(\.\d+)?/);
  if (verMatch && !img) return verMatch[0];
  if (img?.includes(":")) {
    const lastSeg = img.split("/").pop() ?? img;
    if (lastSeg.includes(":")) {
      const idx = lastSeg.indexOf(":");
      return lastSeg.slice(idx + 1) || undefined;
    }
  }
  return undefined;
}

/** Compute verifiedPct and oraPct from a list of findings. */
export function computeMetricsFromFindings(
  findings: Finding[],
  sevOrder: readonly string[],
): { verifiedPct: number; oraPct: number } {
  if (findings.length === 0) return { verifiedPct: 100, oraPct: 100 };
  let verifiedCount = 0;
  for (const f of findings) {
    if (
      [
        "Resolved",
        "False Positive",
        "Approved",
        "Suppressed",
        "Not Applicable",
        "Duplicate",
      ].includes(f.status ?? "")
    )
      verifiedCount++;
  }
  const verifiedPct = Math.round((verifiedCount / findings.length) * 1000) / 10;
  const openFindings = findings.filter(
    (f) =>
      ![
        "Resolved",
        "False Positive",
        "Duplicate",
        "Not Applicable",
        "Approved",
        "Suppressed",
      ].includes(f.status ?? ""),
  );
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of openFindings) {
    counts[severityToKey(f.severity ?? "", f.sourceGroupSeverity)]++;
  }
  const oraPct = openFindings.length > 0 ? computeORAScore(counts) : 100;
  return { verifiedPct, oraPct };
}

/**
 * Display type for an asset. Prefer backend `type` (see asset_type_infer + assets API);
 * otherwise infer from all findings (same rules as backend); last resort id heuristics.
 */
export function getAssetTypeFromAsset(asset: Asset): AssetType {
  const raw = (asset.type ?? "").trim().toLowerCase();
  if (isKnownApiAssetType(raw)) return raw;
  if (asset.findings?.length) {
    return inferAssetTypeFromFindings(asset.findings);
  }
  const id = asset.id ?? asset.name ?? "";
  if (id.includes(":")) return "container";
  return "package";
}

/**
 * Human-friendly title for dashboards (Iron Bank VAT–style: repo path without
 * registry). Identity remains `asset.id` (full canonical ref). Use for table links
 * and asset header; keep `asset.id` for URLs, admin copy, and SBOM matching.
 */
export function getAssetDisplayTitle(
  asset: Pick<Asset, "id" | "name"> & { type?: string },
): string {
  const id = (asset.id ?? "").trim();
  const fallback = (asset.name ?? id).trim();
  if (!id) return fallback;

  const apiType = (asset.type ?? "").trim().toLowerCase();
  if (apiType === "container") {
    return containerDisplayPathWithoutRegistry(id);
  }
  if (apiType === "repo") {
    const parts = id.split("/").filter(Boolean);
    return parts.length > 0 ? parts[parts.length - 1]! : fallback;
  }

  const kind = inferAssetKindForGrouping(id);
  if (kind === "container") {
    return containerDisplayPathWithoutRegistry(id);
  }
  if (kind === "repo") {
    const parts = id.split("/").filter(Boolean);
    return parts.length > 0 ? parts[parts.length - 1]! : fallback;
  }
  if (kind === "path_scope") {
    const raw = id.startsWith("path:") ? id.slice(5) : id;
    const parts = raw.split("/").filter(Boolean);
    return parts.length > 0 ? parts[parts.length - 1]! : raw;
  }
  return fallback;
}

/** Derive assets from findings — group by image or component. Assets can be VMs, repos, containers, packages, IaC, etc. */
export function deriveAssets(
  findings: Finding[],
  sevOrder: readonly string[],
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
        ![
          "Resolved",
          "False Positive",
          "Duplicate",
          "Not Applicable",
          "Approved",
          "Suppressed",
        ].includes(f.status)
      ) {
        const d = daysLeft(f.slaDue);
        if (d !== null && d < 0) overdueCount++;
      }
      if (
        [
          "Resolved",
          "False Positive",
          "Approved",
          "Suppressed",
          "Not Applicable",
          "Duplicate",
        ].includes(f.status)
      )
        verifiedCount++;
      const idx = sevOrder.indexOf(f.severity);
      if (idx >= 0 && (worstIdx < 0 || idx < worstIdx)) worstIdx = idx;
    }
    const verifiedPct =
      list.length > 0
        ? Math.round((verifiedCount / list.length) * 1000) / 10
        : 100;
    const openFindings = list.filter(
      (f) =>
        ![
          "Resolved",
          "False Positive",
          "Duplicate",
          "Not Applicable",
          "Approved",
          "Suppressed",
        ].includes(f.status),
    );
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of openFindings) {
      counts[severityToKey(f.severity ?? "", f.sourceGroupSeverity)]++;
    }
    const oraPct = openFindings.length > 0 ? computeORAScore(counts) : 100;
    const inferredType = inferAssetTypeFromFindings(list);
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
      name: getAssetDisplayTitle({ id: key, name: key, type: inferredType }),
      type: inferredType,
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
  sevOrder: readonly string[],
): Asset | null {
  const assets = deriveAssets(findings, sevOrder);
  return assets.find((a) => a.id === assetId) ?? null;
}

/**
 * Tags for container assets: prefer API `observedTags`, else unique tags from findings.
 * Used by the assets table Tags column and sorting.
 */
export function containerTagListForAsset(asset: Asset): string[] {
  const seen = new Set<string>();
  for (const o of asset.observedTags ?? []) {
    const t = o.tag?.trim();
    if (t) seen.add(t);
  }
  for (const f of asset.findings ?? []) {
    const tag = f.tag?.trim() || getFindingTag(f);
    if (tag) seen.add(tag);
  }
  return [...seen].sort((a, b) => a.localeCompare(b));
}

/**
 * Picks the "latest" version tag from a list, excluding literal "latest".
 * Uses semver ordering; non-semver tags sort last. Used to show a single tag
 * badge + "+N" instead of multiple chips.
 */
export function pickLatestVersionTag(tags: string[]): {
  primary: string;
  restCount: number;
} {
  if (tags.length === 0) {
    return { primary: "", restCount: 0 };
  }
  const withoutLatest = tags.filter((t) => t.toLowerCase() !== "latest");
  const candidates = withoutLatest.length > 0 ? withoutLatest : tags;
  const sorted = [...candidates].sort(compareSemverDesc);
  const primary = sorted[0] ?? "";
  const restCount = tags.length - 1;
  return { primary, restCount };
}

function parseSemverParts(tag: string): number[] {
  const match = tag.match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!match) return [-1];
  return [
    parseInt(match[1], 10),
    parseInt(match[2], 10),
    parseInt(match[3] ?? "0", 10),
  ];
}

function compareSemverDesc(a: string, b: string): number {
  const pa = parseSemverParts(a);
  const pb = parseSemverParts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const va = pa[i] ?? 0;
    const vb = pb[i] ?? 0;
    if (va !== vb) return vb - va;
  }
  return a.localeCompare(b);
}

/**
 * Default container variant filter: the variant whose findings carry the highest
 * semver-style tag (literal `latest` only if no numeric tags), matching
 * `pickLatestVersionTag` semantics. Tie-break: stable digest/key sort.
 */
export function defaultContainerVariantKey(
  variantKeys: string[],
  findings: Finding[],
): string | undefined {
  if (variantKeys.length === 0) return undefined;
  if (variantKeys.length === 1) return variantKeys[0];
  const primaryForKey = (key: string): string => {
    const tags = new Set<string>();
    for (const f of findings) {
      if (containerVariantKey(f) !== key) continue;
      const t = f.tag?.trim() || getFindingTag(f) || "";
      if (t) tags.add(t);
    }
    return pickLatestVersionTag([...tags]).primary;
  };
  return [...variantKeys].sort((ka, kb) => {
    const c = compareSemverDesc(primaryForKey(ka), primaryForKey(kb));
    if (c !== 0) return c;
    return ka.localeCompare(kb);
  })[0];
}

/** Sort key for the Tags column (containers use multi-tag list). */
export function assetTagSortKey(asset: Asset): string {
  if (getAssetTypeFromAsset(asset) === "container") {
    const list = containerTagListForAsset(asset);
    if (list.length) return list.join("\0");
  }
  return asset.tag ?? "";
}
