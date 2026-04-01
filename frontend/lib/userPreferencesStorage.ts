/**
 * User preferences persistence — localStorage-backed.
 * Remembers display and UI preferences per browser.
 */

const STORAGE_KEY = "vat-user-preferences";

export type ThemeId =
  | "vat"
  | "default"
  | "light"
  | "slate"
  | "dracula"
  | "nord"
  | "catppuccin"
  | "tokyo-night";

export interface UserPreferences {
  /** Table density: compact, default, or comfortable */
  tableDensity?: "compact" | "default" | "comfortable";
  /** Show/hide certain columns (future) */
  collapsedSections?: string[];
  /** App and report builder theme */
  themeId?: ThemeId;
  /** Group findings like Aikido (same CVE+package across sources). When false, show flat list. */
  groupFindings?: boolean;
  /** Activity feed dock collapsed/expanded. */
  activityFeedCollapsed?: boolean;
  /** Activity feed source filter selection. */
  activityFeedSourceFilter?: "all" | "finding" | "system";
}

const DEFAULTS: UserPreferences = {
  tableDensity: "default",
  collapsedSections: [],
  themeId: "default",
  groupFindings: true,
  activityFeedCollapsed: false,
  activityFeedSourceFilter: "all",
};

function loadFromStorage(): UserPreferences | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as UserPreferences;
    if (parsed && typeof parsed === "object") {
      const validThemes = [
        "vat",
        "default",
        "light",
        "slate",
        "dracula",
        "nord",
        "catppuccin",
        "tokyo-night",
      ];
      return {
        tableDensity: ["compact", "default", "comfortable"].includes(
          parsed.tableDensity ?? "",
        )
          ? parsed.tableDensity
          : DEFAULTS.tableDensity,
        collapsedSections: Array.isArray(parsed.collapsedSections)
          ? parsed.collapsedSections
          : DEFAULTS.collapsedSections,
        groupFindings:
          typeof parsed.groupFindings === "boolean"
            ? parsed.groupFindings
            : DEFAULTS.groupFindings,
        activityFeedCollapsed:
          typeof parsed.activityFeedCollapsed === "boolean"
            ? parsed.activityFeedCollapsed
            : DEFAULTS.activityFeedCollapsed,
        activityFeedSourceFilter:
          parsed.activityFeedSourceFilter === "finding" ||
          parsed.activityFeedSourceFilter === "system" ||
          parsed.activityFeedSourceFilter === "all"
            ? parsed.activityFeedSourceFilter
            : DEFAULTS.activityFeedSourceFilter,
        themeId: (() => {
          const raw = String(parsed.themeId ?? "");
          if (raw === "kamiwaza") return "default"; /* migrate from kamiwaza */
          if (validThemes.includes(raw as ThemeId)) return raw as ThemeId;
          return DEFAULTS.themeId;
        })(),
      };
    }
  } catch {
    /* ignore */
  }
  return null;
}

export function loadUserPreferences(): UserPreferences {
  const stored = loadFromStorage();
  return stored ? { ...DEFAULTS, ...stored } : { ...DEFAULTS };
}

export function saveUserPreferences(prefs: Partial<UserPreferences>): void {
  if (typeof window === "undefined") return;
  try {
    const current = loadFromStorage() ?? DEFAULTS;
    const merged: UserPreferences = {
      tableDensity:
        prefs.tableDensity ?? current.tableDensity ?? DEFAULTS.tableDensity,
      collapsedSections:
        prefs.collapsedSections ??
        current.collapsedSections ??
        DEFAULTS.collapsedSections,
      groupFindings:
        prefs.groupFindings ?? current.groupFindings ?? DEFAULTS.groupFindings,
      activityFeedCollapsed:
        prefs.activityFeedCollapsed ??
        current.activityFeedCollapsed ??
        DEFAULTS.activityFeedCollapsed,
      activityFeedSourceFilter:
        prefs.activityFeedSourceFilter ??
        current.activityFeedSourceFilter ??
        DEFAULTS.activityFeedSourceFilter,
      themeId: prefs.themeId ?? current.themeId ?? DEFAULTS.themeId,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(merged));
  } catch {
    /* ignore */
  }
}
