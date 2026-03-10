/**
 * Report branding overrides — client-visible via NEXT_PUBLIC_ env vars.
 * Override logo, company name, etc. for the default report theme.
 * When unset, reports use generic defaults suitable for external publishing.
 */

export interface ReportBrandingOverride {
  /** Logo URL for report header. Override via NEXT_PUBLIC_REPORT_LOGO_URL */
  logoUrl?: string;
  /** Company name in report header. Override via NEXT_PUBLIC_REPORT_COMPANY_NAME */
  companyName?: string;
  /** Tagline. Override via NEXT_PUBLIC_REPORT_TAGLINE */
  tagline?: string;
  /** Website URL. Override via NEXT_PUBLIC_REPORT_WEBSITE_URL */
  websiteUrl?: string;
}

/** Read report branding overrides from env. Available in client bundle. */
export function getReportBrandingOverride(): ReportBrandingOverride {
  return {
    logoUrl: process.env.NEXT_PUBLIC_REPORT_LOGO_URL || undefined,
    companyName: process.env.NEXT_PUBLIC_REPORT_COMPANY_NAME || undefined,
    tagline: process.env.NEXT_PUBLIC_REPORT_TAGLINE || undefined,
    websiteUrl: process.env.NEXT_PUBLIC_REPORT_WEBSITE_URL || undefined,
  };
}
