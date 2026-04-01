/**
 * nuqs parsers for dashboard filter state.
 * Used with useQueryStates for type-safe URL state management.
 */

import {
  parseAsString,
  parseAsStringLiteral,
  parseAsArrayOf,
  parseAsInteger,
  parseAsBoolean,
} from "nuqs";

const VALID_TABS = [
  "findings",
  "review",
  "report",
  "dash",
  "feeds",
  "settings",
] as const;

export const dashboardParsers = {
  tab: parseAsStringLiteral(VALID_TABS).withDefault("findings"),
  // search intentionally omitted: local state only, never in URL (clears on refresh)
  status: parseAsArrayOf(parseAsString).withDefault([]),
  abc: parseAsArrayOf(parseAsString).withDefault([]),
  verifiedMin: parseAsInteger.withDefault(0),
  verifiedMax: parseAsInteger.withDefault(100),
  oraMin: parseAsInteger.withDefault(0),
  oraMax: parseAsInteger.withDefault(100),
  assetTypes: parseAsArrayOf(parseAsString).withDefault([]),
  archived: parseAsBoolean.withDefault(false),
  favorites: parseAsBoolean.withDefault(false),
  /** When true, include assets with no findings in the list. Default false hides them. */
  showEmptyAssets: parseAsBoolean.withDefault(false),
  needsJustification: parseAsBoolean.withDefault(false),
  finding: parseAsString.withDefault(""),
} as const;
