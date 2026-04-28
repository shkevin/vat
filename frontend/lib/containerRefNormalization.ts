/**
 * Mirrors backend/app/services/container_ref_normalization.py and
 * infer_asset_kind(..., "") from asset_resolver.py for asset sidebar grouping.
 * Keep in sync when changing normalization rules.
 */

export interface NormalizedContainerRef {
  canonicalAssetKey: string;
  observedTag: string | null;
  observedDigest: string | null;
  rawRef: string;
}

function normalizeHexDigest(value: string | undefined): string | undefined {
  if (!value?.trim()) return undefined;
  const s = value.trim().toLowerCase();
  const hex = s.startsWith("sha256:")
    ? s.slice(7).replace(/[^0-9a-f]/g, "").slice(0, 64)
    : s.replace(/[^0-9a-f]/g, "").slice(0, 64);
  if (hex.length < 12) return undefined;
  return `sha256:${hex}`;
}

function splitDigest(ref: string): [string, string | null] {
  if (!ref.includes("@sha256:")) return [ref, null];
  const [left, right] = ref.split("@sha256:", 2);
  const digest = normalizeHexDigest(right ? `sha256:${right}` : undefined);
  return [left.trim(), digest ?? null];
}

function splitTag(repoRef: string): [string, string | null] {
  if (!repoRef.includes(":")) return [repoRef, null];
  const lastSlash = repoRef.lastIndexOf("/");
  const lastColon = repoRef.lastIndexOf(":");
  if (lastColon > lastSlash) {
    const tag = repoRef.slice(lastColon + 1).trim();
    if (tag) return [repoRef.slice(0, lastColon).trim(), tag];
  }
  return [repoRef, null];
}

function splitRegistryAndPath(repo: string): [string | null, string] {
  if (!repo) return [null, ""];
  if (!repo.includes("/")) return [null, repo];
  const first = repo.slice(0, repo.indexOf("/"));
  const rest = repo.slice(repo.indexOf("/") + 1);
  if (
    first.includes(".") ||
    first.includes(":") ||
    first === "localhost"
  ) {
    return [first, rest];
  }
  return [null, repo];
}

function dockerHubPath(path: string): string {
  const p = (path || "").replace(/^\/+|\/+$/g, "");
  if (!p) return "library/unknown";
  if (!p.includes("/")) return `library/${p}`;
  return p;
}

/**
 * Same semantics as backend normalize_container_ref().
 */
export function normalizeContainerRef(value: string | null | undefined): NormalizedContainerRef {
  const raw = (value ?? "").trim();
  if (!raw) {
    return {
      canonicalAssetKey: "docker.io/library/unknown",
      observedTag: null,
      observedDigest: null,
      rawRef: "",
    };
  }
  const [repoTagPart, digest] = splitDigest(raw);
  const [repoPart, tag] = splitTag(repoTagPart);
  let [registry, path] = splitRegistryAndPath(repoPart);

  if (registry === null) {
    registry = "docker.io";
    path = dockerHubPath(path);
  }

  let canonical = `${registry.toLowerCase()}/${(path || "").replace(/^\/+|\/+$/g, "").toLowerCase()}`.replace(/\/+$/g, "");
  if (!canonical) canonical = "docker.io/library/unknown";

  return {
    canonicalAssetKey: canonical,
    observedTag: tag || null,
    observedDigest: digest,
    rawRef: raw,
  };
}

/** Parse ``NEXT_PUBLIC_VAT_CONTAINER_ASSET_PATH_ALIASES``: ``from=>to;from2=>to2``. Empty ``to`` = strip ``from`` (same as backend). */
export function parseContainerAssetPathAliases(
  raw: string | undefined,
): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  if (!raw?.trim()) return out;
  for (const segment of raw.split(";")) {
    const s = segment.trim();
    if (!s.includes("=>")) continue;
    const idx = s.indexOf("=>");
    const left = s.slice(0, idx);
    const right = s.slice(idx + 2);
    const src = left.trim().toLowerCase();
    const dst = right.trim().toLowerCase();
    if (src) out.push([src, dst]);
  }
  return out;
}

/**
 * Mirrors backend ``apply_container_asset_path_aliases`` (tenant prefix rewrite).
 * Read env on each call so tests can stub ``NEXT_PUBLIC_VAT_CONTAINER_ASSET_PATH_ALIASES``.
 */
export function applyContainerAssetPathAliases(canonicalKey: string): string {
  const k = canonicalKey.trim();
  if (!k) return canonicalKey;
  const raw =
    typeof process !== "undefined"
      ? (process.env.NEXT_PUBLIC_VAT_CONTAINER_ASSET_PATH_ALIASES ?? "")
      : "";
  const pairs = parseContainerAssetPathAliases(raw);
  if (!pairs.length) return canonicalKey;
  const lower = k.toLowerCase();
  for (const [src, dst] of pairs) {
    if (lower.startsWith(src)) {
      return dst + k.slice(src.length);
    }
  }
  return canonicalKey;
}

/**
 * Iron Bank VAT–style display: repository path **without** the registry host.
 * Canonical ref is `registry/org/.../image`; UI shows `org/.../image` (e.g.
 * `a1/caseprocessing/a1caseprocessing`, `containers/images/metrics-server`).
 * Identity remains the full normalized ref in `asset.id`; tags stay separate in UI.
 */
export function containerDisplayPathWithoutRegistry(ref: string): string {
  const { canonicalAssetKey } = normalizeContainerRef(ref);
  const parts = canonicalAssetKey.split("/").filter(Boolean);
  if (parts.length <= 1) {
    return parts[0] ?? canonicalAssetKey;
  }
  return parts.slice(1).join("/");
}

/**
 * Mirrors backend infer_asset_kind(asset_id, parser_id) with parser_id "".
 */
export function inferAssetKindForGrouping(
  assetId: string,
  parserId: string = "",
): string {
  const aid = (assetId || "").trim();
  const pid = (parserId || "").trim().toLowerCase();
  if (!aid) return "unknown";
  if (pid === "openscap" || pid === "openscap_oval") return "host_scope";
  if (pid === "semgrep" || pid === "sarif" || pid === "gitleaks")
    return "path_scope";
  if (pid === "npm_audit" || pid === "pip_audit") return "package_scope";
  if (aid.includes("/images/") || aid.startsWith("sha256:") || aid.includes(":"))
    return "container";
  if (aid.includes("/") && !aid.startsWith("/")) return "repo";
  if (aid.startsWith("/") || aid.startsWith("commit:") || aid.includes(">"))
    return "path_scope";
  return "package_scope";
}
