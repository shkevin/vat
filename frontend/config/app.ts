/**
 * App config — config file defaults + server-side env overrides.
 * Use getAppConfig() in server components only (reads process.env).
 */

export interface AppConfig {
  banner: {
    companyName: string;
    logo: string;
    appName: string;
    classification: string;
    searchPlaceholder: string;
    showThemeToggle: boolean;
    envLabel?: string;
  };
  footer: {
    classification: string;
    suffix?: string;
  };
  /** When true, shows Review tab on asset pages. */
  isAdmin?: boolean;
  /** Base URL for repo file links (e.g. https://github.com/org). When set, Component/Asset in finding details link to repo file at line. */
  repoBaseUrl?: string;
  /** Repo URL format: github | gitlab. Default: github. */
  repoUrlType?: "github" | "gitlab";
}

export const defaultAppConfig: AppConfig = {
  banner: {
    companyName: "VAT",
    logo: "/vat-logo-dark.svg",
    appName: "VAT",
    classification: "", // empty = no banner; set CLASSIFICATION in compose for deployment
    searchPlaceholder: "Search assets…",
    showThemeToggle: false,
    envLabel: undefined,
  },
  footer: {
    classification: "",
    suffix: "",
  },
};

/**
 * Get app config with server-side env overrides.
 * Call only from server components (uses process.env).
 */
export function getAppConfig(): AppConfig {
  const logo = process.env.APP_LOGO ?? defaultAppConfig.banner.logo;
  const effectiveLogo = logo === "▣" ? defaultAppConfig.banner.logo : logo;
  return {
    banner: {
      companyName:
        process.env.APP_COMPANY_NAME ?? defaultAppConfig.banner.companyName,
      logo: effectiveLogo,
      appName: process.env.APP_NAME ?? defaultAppConfig.banner.appName,
      classification:
        process.env.CLASSIFICATION ?? defaultAppConfig.banner.classification,
      searchPlaceholder:
        process.env.SEARCH_PLACEHOLDER ??
        defaultAppConfig.banner.searchPlaceholder,
      showThemeToggle:
        process.env.SHOW_THEME_TOGGLE !== undefined
          ? process.env.SHOW_THEME_TOGGLE === "true"
          : defaultAppConfig.banner.showThemeToggle,
      envLabel: process.env.ENV_LABEL || defaultAppConfig.banner.envLabel,
    },
    footer: {
      classification:
        process.env.FOOTER_CLASSIFICATION ??
        process.env.CLASSIFICATION ??
        defaultAppConfig.footer.classification,
      suffix: process.env.FOOTER_SUFFIX ?? defaultAppConfig.footer.suffix,
    },
    isAdmin: process.env.VAT_IS_ADMIN === "true",
    repoBaseUrl:
      process.env.REPO_BASE_URL ||
      process.env.NEXT_PUBLIC_REPO_BASE_URL ||
      undefined,
    repoUrlType: (process.env.REPO_URL_TYPE ||
      process.env.NEXT_PUBLIC_REPO_URL_TYPE ||
      "github") as "github" | "gitlab",
  };
}
