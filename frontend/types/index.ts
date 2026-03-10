/**
 * VAT domain types — shared across components and hooks.
 */

/** Finding — core vulnerability/triage record */
export interface Finding {
  id: string;
  findingType: string;
  fingerprintId: string;
  cveId: string;
  title?: string;
  severity: string;
  status: string;
  previousStatus?: string | null;
  sources: Array<{ name: string; importedAt: string }>;
  source?: string;
  component?: string;
  image?: string;
  branch?: string;
  tag?: string;
  cvss?: string;
  epss?: string;
  team?: string;
  owner?: string;
  trackerId?: string;
  /** Unified links to external issues (sources and trackers). */
  externalLinks?: Array<{
    adapterKey: string;
    kind: 'tracker' | 'source';
    issueId: string;
    url?: string | null;
    createdAt?: string;
    lastSyncedAt?: string;
  }>;
  controlRef?: string;
  suppressionScope?: string | null;
  attestation?: {
    approver?: string;
    approverTitle?: string;
    approvedAt?: string;
    waiverRef?: string;
    expiresAt?: string;
    expiredAt?: string;
  } | null;
  regressionOf?: string[];
  regressionCount?: number;
  description?: string;
  justification?: string;
  compensatingControls?: string;
  reviewerNote?: string;
  trackerComment?: boolean;
  archived?: boolean;
  archivedAt?: string | null;
  archivedReason?: string | null;
  archivedBy?: string | null;
  /** Direct URL to file at line from source (e.g. Aikido). Use when present for clickable file link. */
  sourceFileUrl?: string | null;
  /** File path for location-based grouping (SAST, Secret, IaC). */
  filePath?: string | null;
  /** Line number for location-based grouping. */
  line?: number | null;
  /** Line preview with sensitive parts masked (e.g. ***REDACTED***). */
  snippetMasked?: string | null;
  /** When source (e.g. Aikido) first detected the issue. Used for report trend alignment with vulnerability-dashboard. */
  firstDetectedAt?: string | null;
  /** When source (e.g. Aikido) closed/resolved the issue. Used for report trend alignment. */
  closedAt?: string | null;
  /** Source-provided group id — use for grouping when present (matches source dashboard) */
  sourceIssueGroupId?: string | null;
  /** Grouping: SAST/IaC/Secret rule or check ID */
  ruleId?: string | null;
  /** Grouping: CWE-XXX for SAST */
  cweId?: string | null;
  /** Grouping: Package ecosystem (npm, pypi, go, etc.) */
  ecosystem?: string | null;
  /** Grouping: Secret category (e.g. AWS Key) */
  secretType?: string | null;
  /** Grouping: IaC resource path/ARN */
  resource?: string | null;
  /** Source-provided group severity — use for grouped display when present (matches source dashboard) */
  sourceGroupSeverity?: string | null;
  audit: Array<{ ts: string; user: string; action: string; note: string | null }>;
  slaDue?: string;
  created?: string;
  /** Sync state: pending_sync when enqueued to tracker. */
  syncStatus?: string;
}

/** Source configuration (Aikido, Drata, Trivy, etc.) */
export interface Source {
  id: string;
  name: string;
  color: string;
  type: string;
  adapter: string;
  description: string;
  /** webhook | push | none. Push sources (Trivy) need VAT API key. */
  authType?: "webhook" | "push" | "none";
  /** For push sources: identifier used when ingesting (e.g. trivy-ci). */
  sourceId?: string;
  /** Parser for manual/push sources: trivy, snyk, semgrep, gitleaks, sarif, canonical */
  parser?: string;
  /** Asset type for ingest: package (folder/bundle), container, repo, or auto (infer from findings) */
  assetType?: "auto" | "package" | "container" | "repo";
}

/** Task tracker configuration (Linear, etc.) */
export interface Tracker {
  id?: string;
  name: string;
  type: string;
  baseUrl: string;
  icon: string;
  description: string;
  commentPrefix: string;
  /** Template injected into Linear issues. Use {cve_id} as placeholder. */
  issueTemplate?: string;
  /** groups: one ticket per CVE/title (deduplicate). instances: one ticket per finding. */
  pushMode?: "groups" | "instances";
  /** Minimum severity to push: critical, high, medium, low, informational, or all. E.g. high = Critical and High only. */
  pushMinSeverity?: "all" | "critical" | "high" | "medium" | "low" | "informational";
  /** When true, use Aikido's own Linear integration for tracking. VAT pulls linked tasks from Aikido and displays them; VAT does not create Linear issues. */
  useAikidoTracking?: boolean;
  /** Aikido source id when useAikidoTracking — one tracker per Aikido workspace. */
  sourceId?: string;
}

/** Watched label for auto-injecting VAT template */
export interface WatchedLabel {
  id: string;
  name: string;
  color: string;
  description: string;
}

/** Asset — derived from findings; can be VM, repo, container, package, IaC, etc. Grouped by image or component. */
export interface Asset {
  id: string;
  name: string;
  type?: string;
  branch?: string;
  tag?: string;
  findings: Finding[];
  openCount: number;
  inReviewCount: number;
  statusBreakdown: Record<string, number>;
  worstSeverity: string;
  overdueCount: number;
  verifiedPct: number;
  /** ORA score 0–100; higher = safer. */
  oraPct: number;
}

/** Alert from computeAlerts */
export interface Alert {
  type: string;
  severity: string;
  fId?: string;
  msg: string;
  waiverRef?: string;
  d?: number;
}
