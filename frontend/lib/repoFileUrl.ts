/**
 * Build repo file URL for clickable file links in finding details.
 * Parses file path from description ("File: path") or uses component when it looks like a path.
 */

import type { Finding } from "@/types";

/** Extract file path and optional line from finding. */
export function parseFileLocation(
  finding: Finding,
): { filePath: string; line?: number } | null {
  // 0. Prefer explicit filePath/line from backend (local scans, SARIF, etc.)
  const fp = finding.filePath?.trim();
  if (fp) {
    const line = finding.line != null ? Number(finding.line) : undefined;
    return { filePath: fp, line: Number.isFinite(line) ? line : undefined };
  }

  // 1. Parse "File: path" or "File: path (line N)" from description (Aikido format)
  const desc = finding.description ?? "";
  const fileMatch = desc.match(
    /File:\s*(.+?)(?:\s*\(line\s+(\d+)\))?(?:\s|$)/i,
  );
  if (fileMatch) {
    let filePath = fileMatch[1].trim();
    let line: number | undefined;
    if (fileMatch[2]) {
      line = parseInt(fileMatch[2], 10);
    } else {
      const lineMatch =
        desc.match(/Line:\s*(\d+)/i) ||
        desc.match(/[#:]L?(\d+)/) ||
        filePath.match(/:(\d+)$/);
      line = lineMatch ? parseInt(lineMatch[1], 10) : undefined;
      if (lineMatch && filePath.match(/:(\d+)$/))
        filePath = filePath.replace(/:(\d+)$/, "");
    }
    if (filePath) return { filePath, line };
  }

  // 2. Component may be a file path for SAST/Secret/IaC (contains /)
  const comp = finding.component ?? "";
  if (comp && comp.includes("/") && !comp.includes(" ")) {
    return { filePath: comp };
  }

  return null;
}

/** Build GitHub/GitLab blob URL for repo file at line. */
export function buildRepoFileUrl(
  repoBaseUrl: string,
  repo: string,
  branch: string,
  filePath: string,
  line?: number,
  urlType: "github" | "gitlab" = "github",
): string {
  const base = repoBaseUrl.replace(/\/$/, "");
  const repoPart = repo.replace(/^\//, "").replace(/\/$/, "");
  const pathPart = filePath.replace(/^\//, "");

  if (urlType === "gitlab") {
    return `${base}/${repoPart}/-/blob/${branch}/${pathPart}${
      line ? `#L${line}` : ""
    }`;
  }
  return `${base}/${repoPart}/blob/${branch}/${pathPart}${
    line ? `#L${line}` : ""
  }`;
}

/** Get clickable repo file URL for a finding. Prefers sourceFileUrl from Aikido when present. */
export function getRepoFileUrl(
  finding: Finding,
  repoBaseUrl?: string,
  repoUrlType: "github" | "gitlab" = "github",
): string | null {
  // Prefer direct URL from source (Aikido provides this)
  if (finding.sourceFileUrl?.trim()) {
    return finding.sourceFileUrl.trim();
  }

  // Fallback: build from repoBaseUrl when configured
  if (!repoBaseUrl?.trim()) return null;

  const loc = parseFileLocation(finding);
  if (!loc) return null;

  // Repo: image (container/repo) or tag/component (asset for local scans)
  const repo =
    finding.image?.trim() || finding.tag?.trim() || finding.component?.trim();
  if (!repo) return null;

  const branch = finding.branch?.trim() || "main";
  return buildRepoFileUrl(
    repoBaseUrl,
    repo,
    branch,
    loc.filePath,
    loc.line,
    repoUrlType,
  );
}

/** Human-readable location string (path:line) for display. */
export function formatFileLocation(finding: Finding): string | null {
  const loc = parseFileLocation(finding);
  if (!loc?.filePath) return null;
  return loc.line != null ? `${loc.filePath}:${loc.line}` : loc.filePath;
}
