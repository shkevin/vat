/** VAT constants. */

export const ABC_TOOLTIP =
  "Acceptance Baseline Criteria (ABC): Compliance standards for container hardening and vulnerability management. Includes SLA timelines for justification and remediation, max open findings per severity, and CVE age tolerance.";

export const ORA_TOOLTIP =
  "Overall Risk Assessment (ORA): Score 0–100 (higher = safer). 90% from open findings (weighted penalties; mitigated count half), 10% from Maintained/Dependency Update (assumed best when unknown).";

export const SEV_ORDER = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Informational",
] as const;

// Chip fills sit at ~0.18 so the pill reads against near-black panel/table
// backgrounds; the Tag border (color @ ~35%) carries the crisp outline.
export const SEV: Record<string, { c: string; bg: string }> = {
  Critical: { c: "#f87060", bg: "rgba(248,112,96,0.18)" },
  High: { c: "#f5a623", bg: "rgba(245,166,35,0.18)" },
  Medium: { c: "#f5d020", bg: "rgba(245,208,32,0.18)" },
  Low: { c: "#50c878", bg: "rgba(80,200,120,0.18)" },
  Informational: { c: "#7b8fa1", bg: "rgba(123,143,161,0.18)" },
};

// Active states at ~0.16; terminal/muted states (FP, Suppressed, N/A,
// Duplicate) kept lower to stay de-emphasized while still visible.
export const ST: Record<string, { c: string; b: string }> = {
  Open: { c: "#94a3b8", b: "rgba(148,163,184,0.16)" },
  "Synced to Tracker": { c: "#38bdf8", b: "rgba(56,189,248,0.16)" },
  "In Review": { c: "#818cf8", b: "rgba(129,140,248,0.18)" },
  Approved: { c: "#50c878", b: "rgba(80,200,120,0.16)" },
  Rejected: { c: "#f87060", b: "rgba(248,112,96,0.16)" },
  "Risk Accepted": { c: "#c084fc", b: "rgba(192,132,252,0.16)" },
  "False Positive": { c: "#64748b", b: "rgba(100,116,139,0.12)" },
  Suppressed: { c: "#475569", b: "rgba(71,85,105,0.12)" },
  "Not Applicable": { c: "#334155", b: "rgba(51,65,85,0.12)" },
  Mitigated: { c: "#fbbf24", b: "rgba(251,191,36,0.16)" },
  Resolved: { c: "#34d399", b: "rgba(52,211,153,0.16)" },
  Duplicate: { c: "#1e293b", b: "rgba(30,41,59,0.12)" },
  Reopened: { c: "#fb923c", b: "rgba(251,146,60,0.18)" },
};

export const FINDING_TYPES: Record<
  string,
  { icon: string; color: string; label: string; desc: string }
> = {
  SCA: {
    icon: "🛡",
    color: "#38bdf8",
    label: "SCA / Dependency",
    desc: "Package vulnerability identified by scanner",
  },
  Secret: {
    icon: "🔑",
    color: "#f87060",
    label: "Leaked Secret",
    desc: "Credential, token, or key detected in code/config",
  },
  IaC: {
    icon: "⚙️",
    color: "#f5a623",
    label: "IaC Misconfiguration",
    desc: "Insecure infrastructure-as-code configuration",
  },
  SAST: {
    icon: "🔬",
    color: "#818cf8",
    label: "SAST Finding",
    desc: "Static analysis code-level security issue",
  },
  License: {
    icon: "📜",
    color: "#50c878",
    label: "License Risk",
    desc: "Package license incompatible with usage terms",
  },
};

export const SLA_DAYS: Record<string, Record<string, number>> = {
  Secret: { Critical: 1, High: 1, Medium: 1, Low: 3, Informational: 7 },
  SCA: { Critical: 3, High: 14, Medium: 30, Low: 90, Informational: 180 },
  IaC: { Critical: 1, High: 7, Medium: 14, Low: 30, Informational: 90 },
  SAST: { Critical: 7, High: 21, Medium: 60, Low: 90, Informational: 180 },
  License: { Critical: 14, High: 30, Medium: 30, Low: 90, Informational: 180 },
};

/** Asset types — derived from finding fields. No fallback; every asset has a proper type. */
export const ASSET_TYPES = ["node", "repo", "container", "package", "path"] as const;
export type AssetType = (typeof ASSET_TYPES)[number];

export const ASSET_TYPE_LABELS: Record<AssetType, string> = {
  node: "Node",
  repo: "Repo",
  container: "Container",
  package: "Package",
  path: "Path",
};

export const LICENSE_RISK: Record<string, string> = {
  "AGPL-3.0": "Critical",
  "SSPL-1.0": "Critical",
  "GPL-3.0": "High",
  "GPL-2.0": "High",
  "LGPL-2.1": "Medium",
  "LGPL-3.0": "Medium",
  "MPL-2.0": "Medium",
  "CDDL-1.0": "Medium",
  MIT: "Low",
  "Apache-2.0": "Low",
  "BSD-2-Clause": "Low",
  "BSD-3-Clause": "Low",
  ISC: "Low",
  Unlicense: "Low",
  "CC0-1.0": "Low",
};

/** Available source integration types — maps adapter key to display info */
export const SOURCE_TYPES: Record<
  string,
  {
    label: string;
    adapter: string;
    color: string;
    hasSettingsPage: boolean;
    parser?: string;
  }
> = {
  aikido: {
    label: "Aikido",
    adapter: "aikido",
    color: "#06b6d4",
    hasSettingsPage: true,
  },
  manual: {
    label: "Manual",
    adapter: "manual",
    color: "#94a3b8",
    hasSettingsPage: true,
  },
};

/** Default colors for manual source nodes by parser (user can override via color picker) */
export const PARSER_COLORS: Record<string, string> = {
  trivy: "#00c853",
  snyk: "#4caf50",
  semgrep: "#2196f3",
  gitleaks: "#ff9800",
  sarif: "#9c27b0",
  canonical: "#94a3b8",
  npm_audit: "#e91e63",
  pip_audit: "#3776ab",
  grype: "#00bcd4",
  cyclonedx: "#673ab7",
  openscap: "#0066cc",
  openscap_oval: "#3385d6",
};

/** Available tracker integration types */
export const TRACKER_TYPES: Record<
  string,
  {
    label: string;
    type: string;
    color: string;
    icon: string;
    hasSettingsPage: boolean;
  }
> = {
  linear: {
    label: "Linear",
    type: "linear",
    color: "#818cf8",
    icon: "◈",
    hasSettingsPage: true,
  },
};

export const DEFAULT_SOURCES = [
  {
    id: "s-1",
    name: "Aikido",
    color: "#06b6d4",
    type: "scanner",
    adapter: "aikido",
    description: "Container, SCA, SAST, IaC, secrets scanner. Webhooks + REST.",
  },
  {
    id: "s-2",
    name: "Manual",
    color: "#94a3b8",
    type: "manual",
    adapter: "manual",
    description:
      "Manually entered findings and push sources (Trivy, Semgrep, etc.).",
  },
];

export const DEFAULT_ISSUE_TEMPLATE = `[VAT] {finding_id}

---
### Vulnerability Assessment Response
Post the block below as a **comment** to update this finding in VAT.

| Field | Value |
|-------|-------|
| status | \`false-positive\` \\| \`not-applicable\` \\| \`risk-accepted\` \\| \`mitigated\` \\| \`duplicate\` |
| justification | _(required — explain why; cite evidence for false-positive)_ |
| compensating-controls | _(optional — e.g. WAF, network segmentation, monitoring)_ |

**Copy-paste and fill in:**
\`\`\`
[VAT] {finding_id}
status:
justification:
compensating-controls:
\`\`\``;

export const DEFAULT_TRACKER = {
  name: "Linear",
  type: "linear",
  baseUrl: "https://linear.app/yourteam/issue/",
  icon: "◈",
  description: "Engineers receive issues with auto-injected [VAT] template.",
  commentPrefix: "[VAT]",
  issueTemplate: DEFAULT_ISSUE_TEMPLATE,
  pushMode: "groups" as const,
  pushMinSeverity: "high" as const,
};

export const DEFAULT_LABELS: {
  id: string;
  name: string;
  color: string;
  description: string;
}[] = [];

export const SAMPLE_SBOM = [
  {
    id: "sb-1",
    name: "log4j-core",
    version: "2.17.1",
    license: "Apache-2.0",
    component: "worker:v2.3",
    language: "Java",
  },
  {
    id: "sb-2",
    name: "spring-boot",
    version: "3.2.1",
    license: "Apache-2.0",
    component: "api-server:latest",
    language: "Java",
  },
  {
    id: "sb-3",
    name: "react",
    version: "18.2.0",
    license: "MIT",
    component: "web-frontend:v1.2",
    language: "JS",
  },
  {
    id: "sb-4",
    name: "express",
    version: "4.18.2",
    license: "MIT",
    component: "web-frontend:v1.2",
    language: "JS",
  },
  {
    id: "sb-5",
    name: "libexpat",
    version: "2.5.0",
    license: "MIT",
    component: "auth-service:v3.1",
    language: "C",
  },
  {
    id: "sb-6",
    name: "openssl",
    version: "3.0.11",
    license: "Apache-2.0",
    component: "api-server:latest",
    language: "C",
  },
  {
    id: "sb-7",
    name: "gpl-helper",
    version: "1.0.0",
    license: "GPL-3.0",
    component: "worker:v2.3",
    language: "Python",
  },
  {
    id: "sb-8",
    name: "agpl-client",
    version: "2.3.1",
    license: "AGPL-3.0",
    component: "api-server:latest",
    language: "Python",
  },
  {
    id: "sb-9",
    name: "mpllib",
    version: "0.9.4",
    license: "MPL-2.0",
    component: "ci-runner:ubuntu22",
    language: "Rust",
  },
  {
    id: "sb-10",
    name: "tomcat-embed",
    version: "10.1.31",
    license: "Apache-2.0",
    component: "legacy-api:v1.8",
    language: "Java",
  },
  {
    id: "sb-11",
    name: "xz-utils",
    version: "5.6.0",
    license: "LGPL-2.1",
    component: "base-alpine:3.19",
    language: "C",
  },
  {
    id: "sb-12",
    name: "wget",
    version: "1.21.3",
    license: "GPL-3.0",
    component: "ci-runner:ubuntu22",
    language: "C",
  },
  {
    id: "sb-13",
    name: "runc",
    version: "1.1.11",
    license: "Apache-2.0",
    component: "api-server:latest",
    language: "Go",
  },
  {
    id: "sb-14",
    name: "nginx",
    version: "1.25.1",
    license: "BSD-2-Clause",
    component: "ingress:v1.9",
    language: "C",
  },
];
