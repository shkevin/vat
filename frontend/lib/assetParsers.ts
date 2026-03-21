/**
 * nuqs parsers for asset page filter state.
 * Used with useQueryStates for type-safe URL state management.
 */

import { parseAsString, parseAsArrayOf, parseAsStringLiteral } from "nuqs";

const SORT_OPTS = [
  "severity",
  "status",
  "cve",
  "title",
  "source",
  "sla",
] as const;

export const assetParsers = {
  status: parseAsArrayOf(parseAsString).withDefault(["Open"]),
  severity: parseAsArrayOf(parseAsString).withDefault([]),
  source: parseAsArrayOf(parseAsString).withDefault([]),
  type: parseAsArrayOf(parseAsString).withDefault([]),
  // search intentionally omitted: local state only, never in URL (clears on refresh)
  sort: parseAsStringLiteral(SORT_OPTS).withDefault("severity"),
  branch: parseAsString.withDefault(""),
  tag: parseAsString.withDefault(""),
} as const;
