import type { Finding } from "@/types";

export type FeedProvenance = NonNullable<Finding["sources"]>[number];

export function getFeedProvenanceFromSources(
  sources: Finding["sources"] | undefined,
): FeedProvenance | undefined {
  return (sources ?? []).find((s) => {
    const isFeedMatch = (s?.name ?? "").trim().toLowerCase() === "vuln_feed_match";
    return Boolean(
      isFeedMatch &&
        (s.feedSource ||
          s.matchStrategy ||
          s.matchConfidence ||
          s.matchedPackage ||
          s.matchedVersion),
    );
  });
}
