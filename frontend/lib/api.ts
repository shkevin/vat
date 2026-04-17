/**
 * VAT API client — fetches findings from backend.
 */

import { triggerUnauthorized } from "@/lib/onUnauthorized";
import type {
  FeedRecordsResponse,
  FeedRunsResponse,
  FeedSummaryResponse,
} from "@/types/feeds";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "/api";

/** Auth for API calls: JWT Bearer token required for protected endpoints */
export type Auth = { token?: string | null; userEmail?: string | null };

/** Fetch wrapper: on 401 with auth, clears session so AuthGuard redirects to login */
async function vatFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
  auth?: Auth,
): Promise<Response> {
  const res = await fetch(input, init);
  if (res.status === 401 && (auth?.token || auth?.userEmail)) {
    triggerUnauthorized();
  }
  return res;
}

export interface FindingsParams {
  archived?: boolean;
  status?: string | string[];
  severity?: string | string[];
  source?: string | string[];
  type?: string | string[];
  asset?: string;
  search?: string;
  search_fields?: string | string[];
  limit?: number;
  page?: number;
  page_size?: number;
  include_assets?: boolean;
  include_zero_assets?: boolean;
  include_asset_findings?: boolean;
  full?: boolean;
}

export async function fetchFindings(
  params?: FindingsParams,
  auth?: Auth,
): Promise<ApiFinding[]> {
  const search = new URLSearchParams();
  if (params?.archived !== undefined)
    search.set("archived", String(params.archived));
  if (params?.status)
    search.set(
      "status",
      Array.isArray(params.status) ? params.status.join(",") : params.status,
    );
  if (params?.severity)
    search.set(
      "severity",
      Array.isArray(params.severity)
        ? params.severity.join(",")
        : params.severity,
    );
  if (params?.source)
    search.set(
      "source",
      Array.isArray(params.source) ? params.source.join(",") : params.source,
    );
  if (params?.type)
    search.set(
      "type",
      Array.isArray(params.type) ? params.type.join(",") : params.type,
    );
  if (params?.asset) search.set("asset", params.asset);
  if (params?.search) search.set("search", params.search);
  if (params?.search_fields) {
    const v = Array.isArray(params.search_fields)
      ? params.search_fields.join(",")
      : params.search_fields;
    search.set("search_fields", v);
  }
  if (params?.limit !== undefined) search.set("limit", String(params.limit));

  const url = `${API_BASE}/findings${search.toString() ? `?${search}` : ""}`;
  const res = await vatFetch(
    url,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export interface VATDataResponse {
  findings: ApiFinding[];
  assets: Array<{
    id: string;
    name: string;
    tag?: string;
    findings: ApiFinding[];
    findingIds?: string[];
    openCount: number;
    inReviewCount: number;
    statusBreakdown: Record<string, number>;
    worstSeverity: string;
    overdueCount: number;
    verifiedPct: number;
    oraPct: number;
    observedTags?: Array<{
      tag: string;
      firstSeenAt?: string | null;
      lastSeenAt?: string | null;
      observationCount?: number;
      lastDigest?: string | null;
    }>;
    digestConflictOpen?: boolean;
    digestConflicts?: Array<{
      tag: string;
      digests: string[];
      firstSeenAt?: string | null;
      lastSeenAt?: string | null;
    }>;
  }>;
  meta?: {
    page: number;
    pageSize: number;
    hasMore: boolean;
    includeAssets: boolean;
    includeZeroAssets: boolean;
  };
}

export interface AuditEventsParams {
  limit?: number;
  eventType?: string;
  dateFrom?: string;
  dateTo?: string;
}

export interface ApiAuditEvent {
  eventId: string;
  traceId: string;
  eventType: string;
  createdAt: string | null;
  sourceId?: string | null;
  parserId?: string | null;
  assetId?: string | null;
  findingId?: string | null;
  decisionName?: string | null;
  decisionReasonCode?: string | null;
  decisionConfidence?: string | null;
  decisionResult?: string | null;
  recordHash?: string | null;
  prevRecordHash?: string | null;
  data?: Record<string, unknown>;
}

/** Fetch findings and assets in one call. Assets include integration-created records (e.g. Aikido repos with 0 findings). */
export async function fetchVATData(
  params?: FindingsParams,
  auth?: Auth,
): Promise<VATDataResponse> {
  const search = new URLSearchParams();
  if (params?.archived !== undefined)
    search.set("archived", String(params.archived));
  if (params?.status)
    search.set(
      "status",
      Array.isArray(params.status) ? params.status.join(",") : params.status,
    );
  if (params?.severity)
    search.set(
      "severity",
      Array.isArray(params.severity)
        ? params.severity.join(",")
        : params.severity,
    );
  if (params?.source)
    search.set(
      "source",
      Array.isArray(params.source) ? params.source.join(",") : params.source,
    );
  if (params?.type)
    search.set(
      "type",
      Array.isArray(params.type) ? params.type.join(",") : params.type,
    );
  if (params?.asset) search.set("asset", params.asset);
  if (params?.search) search.set("search", params.search);
  if (params?.search_fields) {
    const v = Array.isArray(params.search_fields)
      ? params.search_fields.join(",")
      : params.search_fields;
    search.set("search_fields", v);
  }
  if (params?.limit !== undefined) search.set("limit", String(params.limit));
  if (params?.page !== undefined) search.set("page", String(params.page));
  if (params?.page_size !== undefined)
    search.set("page_size", String(params.page_size));
  if (params?.include_assets !== undefined)
    search.set("include_assets", String(params.include_assets));
  if (params?.include_zero_assets !== undefined)
    search.set("include_zero_assets", String(params.include_zero_assets));
  if (params?.include_asset_findings !== undefined)
    search.set("include_asset_findings", String(params.include_asset_findings));
  if (params?.full !== undefined) search.set("full", String(params.full));

  const url = `${API_BASE}/vat-data${search.toString() ? `?${search}` : ""}`;
  const res = await vatFetch(
    url,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/** Fetch system audit events. Endpoint requires admin permissions. */
export async function fetchAuditEvents(
  params?: AuditEventsParams,
  auth?: Auth,
): Promise<{
  count: number;
  events: ApiAuditEvent[];
}> {
  const search = new URLSearchParams();
  if (params?.limit != null) search.set("limit", String(params.limit));
  if (params?.eventType) search.set("event_type", params.eventType);
  if (params?.dateFrom) search.set("date_from", params.dateFrom);
  if (params?.dateTo) search.set("date_to", params.dateTo);
  const url = `${API_BASE}/audit/events${search.toString() ? `?${search}` : ""}`;
  const res = await vatFetch(
    url,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function fetchVulnFeedSummary(
  auth?: Auth,
): Promise<FeedSummaryResponse> {
  const res = await vatFetch(
    `${API_BASE}/vuln-feeds/summary`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function fetchVulnFeedRuns(
  params?: { source?: string; limit?: number },
  auth?: Auth,
): Promise<FeedRunsResponse> {
  const search = new URLSearchParams();
  if (params?.source) search.set("source", params.source);
  if (params?.limit != null) search.set("limit", String(params.limit));
  const url = `${API_BASE}/vuln-feeds/runs${search.toString() ? `?${search}` : ""}`;
  const res = await vatFetch(
    url,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function fetchVulnFeedRecords(
  params?: {
    source?: string;
    severity?: string;
    search?: string;
    limit?: number;
    offset?: number;
  },
  auth?: Auth,
): Promise<FeedRecordsResponse> {
  const search = new URLSearchParams();
  if (params?.source) search.set("source", params.source);
  if (params?.severity) search.set("severity", params.severity);
  if (params?.search) search.set("search", params.search);
  if (params?.limit != null) search.set("limit", String(params.limit));
  if (params?.offset != null) search.set("offset", String(params.offset));
  const url = `${API_BASE}/vuln-feeds/records${search.toString() ? `?${search}` : ""}`;
  const res = await vatFetch(
    url,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function triggerVulnFeedRefresh(
  options?: { use_celery?: boolean },
  auth?: Auth,
): Promise<{ dispatched: boolean; message?: string }> {
  const search = new URLSearchParams();
  if (options?.use_celery != null) {
    search.set("use_celery", options.use_celery ? "true" : "false");
  }
  const url = `${API_BASE}/vuln-feeds/refresh${search.toString() ? `?${search}` : ""}`;
  const res = await vatFetch(
    url,
    {
      method: "POST",
      headers: authHeaders(auth?.token, auth?.userEmail),
    },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function updateFinding(
  id: string,
  data: Partial<ApiFinding>,
  auth?: Auth,
): Promise<ApiFinding> {
  const body: Record<string, unknown> = {};
  if (data.status != null) body.status = data.status;
  if (data.justification != null) body.justification = data.justification;
  if (data.compensatingControls != null)
    body.compensating_controls = data.compensatingControls;
  if (data.reviewerNote != null) body.reviewer_note = data.reviewerNote;
  if (data.suppressionScope != null)
    body.suppression_scope = data.suppressionScope;
  if (data.attestation != null) body.attestation = data.attestation;

  const res = await vatFetch(
    `${API_BASE}/findings/${id}`,
    {
      method: "PATCH",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify(body),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function archiveFinding(
  id: string,
  reason: string,
  auth?: Auth,
): Promise<ApiFinding> {
  const res = await vatFetch(
    `${API_BASE}/findings/${id}/archive`,
    {
      method: "POST",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify({ reason }),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function unarchiveFinding(
  id: string,
  auth?: Auth,
): Promise<ApiFinding> {
  const res = await vatFetch(
    `${API_BASE}/findings/${id}/unarchive`,
    { method: "POST", headers: apiHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

/** Enqueue a single finding for sync to Linear. For dev/troubleshooting. */
export async function syncFindingToTracker(
  findingId: string,
  auth?: Auth,
): Promise<{ enqueued: boolean; message: string }> {
  const res = await vatFetch(
    `${API_BASE}/findings/${encodeURIComponent(findingId)}/sync-to-tracker`,
    { method: "POST", headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function revertFinding(
  id: string,
  reason: string,
  auth?: Auth,
): Promise<ApiFinding> {
  const res = await vatFetch(
    `${API_BASE}/findings/${id}/revert`,
    {
      method: "POST",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify({ reason }),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function overrideFindingFingerprint(
  id: string,
  auth?: Auth,
): Promise<ApiFinding> {
  const res = await vatFetch(
    `${API_BASE}/findings/${id}/override-fingerprint`,
    { method: "POST", headers: apiHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function bulkUpdateFindings(
  ids: string[],
  status: string,
  justification: string,
  auth?: Auth,
): Promise<{ updated: number }> {
  const res = await vatFetch(
    `${API_BASE}/findings/bulk`,
    {
      method: "POST",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify({ ids, status, justification }),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function fetchSettings(auth?: Auth): Promise<{
  sources: Array<Record<string, unknown>>;
  tracker: Record<string, unknown>;
  trackers?: Array<Record<string, unknown>>;
  labels: Array<Record<string, unknown>>;
}> {
  const res = await vatFetch(
    `${API_BASE}/settings`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

/** Integration schemas for diagram styling — brand_color per adapter, flow_types for edges. Admin only. */
export interface IntegrationSchemas {
  sources: Array<{ adapter_key: string; brand_color?: string }>;
  trackers: Array<{ adapter_key: string; brand_color?: string }>;
  flow_types: Record<string, { color: string; style: string; label?: string }>;
}

export async function fetchIntegrationSchemas(
  auth?: Auth,
): Promise<IntegrationSchemas> {
  const res = await vatFetch(
    `${API_BASE}/settings/integration-schemas`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function fetchParsers(auth?: Auth): Promise<{
  parsers: Array<{
    id: string;
    name: string;
    label: string;
    description?: string;
  }>;
}> {
  const res = await vatFetch(
    `${API_BASE}/settings/parsers`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function putSettingsSources(
  sources: Array<Record<string, unknown>>,
  auth?: Auth,
): Promise<void> {
  const res = await vatFetch(
    `${API_BASE}/settings/sources`,
    {
      method: "PUT",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify(sources),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
}

export async function putSettingsTracker(
  tracker: Record<string, unknown>,
  auth?: Auth,
): Promise<void> {
  const res = await vatFetch(
    `${API_BASE}/settings/tracker`,
    {
      method: "PUT",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify(tracker),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
}

export async function removeSettingsTracker(auth?: Auth): Promise<void> {
  const res = await vatFetch(
    `${API_BASE}/settings/tracker`,
    {
      method: "PUT",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify([]),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
}

export async function putSettingsLabels(
  labels: Array<Record<string, unknown>>,
  auth?: Auth,
): Promise<void> {
  const res = await vatFetch(
    `${API_BASE}/settings/labels`,
    {
      method: "PUT",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify(labels),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
}

export async function fetchAikidoStatus(
  auth?: Auth,
  sourceId?: string | null,
): Promise<{
  clientIdConfigured: boolean;
  clientSecretConfigured: boolean;
  region: string;
  oauthConfigured: boolean;
  webhookSecretConfigured: boolean;
  webhookUrl: string;
  syncBackEnabled?: boolean;
}> {
  const params = new URLSearchParams();
  if (sourceId != null) params.set("source_id", sourceId);
  const url = `${API_BASE}/settings/aikido/status${
    params.toString() ? `?${params}` : ""
  }`;
  const res = await vatFetch(
    url,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function putAikidoCredentials(
  credentials: {
    sourceId?: string;
    clientId?: string;
    clientSecret?: string;
    region?: string;
    webhookSecret?: string;
    syncBackEnabled?: boolean;
  },
  auth?: Auth,
): Promise<void> {
  const res = await vatFetch(
    `${API_BASE}/settings/aikido/credentials`,
    {
      method: "PUT",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify(credentials),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
}

export async function pullAikidoData(
  options?: { createTrackerIssues?: boolean },
  auth?: Auth,
): Promise<{
  message: string;
  fetched: number;
  created: number;
  merged: number;
}> {
  const params = new URLSearchParams();
  if (options?.createTrackerIssues) params.set("create_tracker_issues", "true");
  const url = `${API_BASE}/aikido/bootstrap${
    params.toString() ? `?${params}` : ""
  }`;
  const res = await vatFetch(
    url,
    { method: "POST", headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/** Get current Aikido sync status for the given source. Each source tracks independently. */
export async function fetchAikidoSyncStatus(
  auth?: Auth,
  sourceId?: string | null,
): Promise<{
  status: "idle" | "running" | "success" | "error";
  message?: string | null;
  started_at?: string | null;
  step?: number;
  total?: number;
  label?: string | null;
  source_id?: string | null;
  lastSyncedAt?: string | null;
}> {
  const params = new URLSearchParams();
  if (sourceId != null) params.set("source_id", sourceId);
  const url = `${API_BASE}/aikido/sync-status${
    params.toString() ? `?${params}` : ""
  }`;
  const res = await vatFetch(
    url,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/** Start full sync (pull + dashboard + backfill) in background. Returns immediately to avoid timeout. */
export async function syncAikido(
  auth?: Auth,
  sourceId?: string | null,
): Promise<{
  status: string;
  message: string;
}> {
  const res = await vatFetch(
    `${API_BASE}/aikido/sync`,
    {
      method: "POST",
      headers: {
        ...authHeaders(auth?.token, auth?.userEmail),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ source_id: sourceId ?? null }),
    },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/** Sync data from Aikido to VAT (issues, groups, containers, VMs, activity, CI scans, etc.). */
export async function syncAikidoDashboard(auth?: Auth): Promise<{
  message: string;
  issues: number;
  issueGroups: number;
  containers: number;
  vms: number;
  fetchedAt?: string;
}> {
  const res = await vatFetch(
    `${API_BASE}/aikido/sync-dashboard`,
    { method: "POST", headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/** Get cached Aikido data synced to VAT. Returns null if not synced. */
export async function fetchAikidoDashboardData(auth?: Auth): Promise<{
  issues: unknown[];
  issueGroups: unknown[];
  repos: unknown[];
  containers: unknown[];
  vms: unknown[];
  workspace: { id: string; name: string; plan: string };
  issueCounts?: unknown;
  activityLog?: unknown[];
  ciScans?: unknown[];
  taskProjects?: unknown[];
  reachabilityByIssueId?: Record<number, unknown>;
  tasksByGroupId?: Record<string, unknown[]>;
  cveDetailsByCveId?: Record<string, { epss_score?: number; in_kev?: boolean }>;
  fetchedAt: string;
} | null> {
  const res = await vatFetch(
    `${API_BASE}/aikido/dashboard-data`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (res.status === 404) return null;
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/** Backfill first_detected_at from Aikido for report trend alignment with vulnerability-dashboard. */
export async function backfillFirstDetectedAt(auth?: Auth): Promise<{
  message: string;
  fetched: number;
  updated: number;
  skipped_no_first_detected: number;
  skipped_already_has: number;
}> {
  const res = await vatFetch(
    `${API_BASE}/aikido/backfill-first-detected`,
    { method: "POST", headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function fetchLinearStatus(auth?: Auth): Promise<{
  apiKeyConfigured: boolean;
  teamIdConfigured: boolean;
  webhookSecretConfigured: boolean;
  webhookUrl: string;
}> {
  const res = await vatFetch(
    `${API_BASE}/settings/linear/status`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

/** Full sync between VAT and Linear: link existing issues, retry failed, process queue, backfill, and optionally poll for inbound updates. */
export async function syncLinear(auth?: Auth): Promise<{
  dispatched?: boolean;
  linked?: number;
  fetched?: number;
  reset?: number;
  processed?: number;
  backfill_enqueued?: number;
  poll_dispatched?: boolean;
}> {
  const res = await vatFetch(
    `${API_BASE}/sync`,
    { method: "POST", headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function putLinearCredentials(
  credentials: { apiKey?: string; teamId?: string; webhookSecret?: string },
  auth?: Auth,
): Promise<{ ok: boolean; labels?: { created: number; errors: string[] } }> {
  const res = await vatFetch(
    `${API_BASE}/settings/linear/credentials`,
    {
      method: "PUT",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify(credentials),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function fetchVatStatus(auth?: Auth): Promise<{
  databaseConfigured: boolean;
  secretKeyConfigured: boolean;
  publicUrl: string;
  aikidoWebhookUrl: string;
  linearWebhookUrl: string;
  ingestUrl?: string;
  ingestSarifUrl?: string;
}> {
  const res = await vatFetch(
    `${API_BASE}/settings/vat/status`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function fetchIngestKeys(auth?: Auth): Promise<{
  keys: Array<{
    sourceId: string;
    keyPrefix: string;
    configured: boolean;
    authType?: string;
    createdAt?: string;
    rotatedAt?: string;
  }>;
  oauthClients?: Array<{
    sourceId: string;
    clientId: string;
    createdAt?: string;
    rotatedAt?: string;
  }>;
}> {
  const res = await vatFetch(
    `${API_BASE}/settings/ingest-keys`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function createIngestKey(
  sourceId: string,
  auth?: Auth,
): Promise<{
  sourceId: string;
  key: string;
  keyPrefix: string;
  message: string;
}> {
  const res = await vatFetch(
    `${API_BASE}/settings/ingest-keys`,
    {
      method: "POST",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify({ sourceId }),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function regenerateIngestKey(
  sourceId: string,
  auth?: Auth,
): Promise<{
  sourceId: string;
  key: string;
  keyPrefix: string;
  message: string;
}> {
  const res = await vatFetch(
    `${API_BASE}/settings/ingest-keys/${encodeURIComponent(
      sourceId,
    )}/regenerate`,
    { method: "POST", headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function revokeIngestKey(
  sourceId: string,
  auth?: Auth,
): Promise<{ ok: boolean; revoked: boolean }> {
  const res = await vatFetch(
    `${API_BASE}/settings/ingest-keys/${encodeURIComponent(sourceId)}`,
    { method: "DELETE", headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function createOAuthClient(
  sourceId: string,
  auth?: Auth,
): Promise<{
  sourceId: string;
  clientId: string;
  clientSecret: string;
  message: string;
}> {
  const res = await vatFetch(
    `${API_BASE}/settings/oauth-clients`,
    {
      method: "POST",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify({ sourceId }),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function rotateOAuthClient(
  sourceId: string,
  auth?: Auth,
): Promise<{
  sourceId: string;
  clientId: string;
  clientSecret: string;
  message: string;
}> {
  const res = await vatFetch(
    `${API_BASE}/settings/oauth-clients/${encodeURIComponent(sourceId)}/rotate`,
    { method: "POST", headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function revokeOAuthClient(
  sourceId: string,
  auth?: Auth,
): Promise<{ ok: boolean; revoked: boolean }> {
  const res = await vatFetch(
    `${API_BASE}/settings/oauth-clients/${encodeURIComponent(sourceId)}`,
    { method: "DELETE", headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

/** Admin API keys — for automation (scripts, CI). Use as VAT_ADMIN_TOKEN. */
export async function fetchAdminKeys(auth?: Auth): Promise<{
  keys: Array<{ id: string; keyPrefix: string; createdAt?: string }>;
}> {
  const res = await vatFetch(
    `${API_BASE}/settings/admin-keys`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function createAdminKey(auth?: Auth): Promise<{
  id: string;
  key: string;
  keyPrefix: string;
  message: string;
}> {
  const res = await vatFetch(
    `${API_BASE}/settings/admin-keys`,
    { method: "POST", headers: apiHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function revokeAdminKey(
  keyId: string,
  auth?: Auth,
): Promise<{ ok: boolean; revoked: boolean }> {
  const res = await vatFetch(
    `${API_BASE}/settings/admin-keys/${encodeURIComponent(keyId)}`,
    { method: "DELETE", headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

/** Download full export bundle (assets, findings, SBOM, Executive Summary). Triggers browser download. */
export async function downloadExportBundle(
  auth?: Auth,
  options?: { includeAuditEvents?: boolean },
): Promise<void> {
  const params = new URLSearchParams();
  if (options?.includeAuditEvents === false) {
    params.set("include_audit_events", "false");
  }
  const qs = params.toString();
  const url = `${API_BASE}/export/bundle${qs ? `?${qs}` : ""}`;
  const res = await vatFetch(
    url,
    {
      headers: authHeaders(auth?.token, auth?.userEmail),
      signal:
        typeof AbortSignal !== "undefined" &&
        typeof AbortSignal.timeout === "function"
          ? AbortSignal.timeout(300_000)
          : undefined,
    },
    auth,
  );
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    const ct = res.headers.get("content-type") || "";
    try {
      if (ct.includes("application/json")) {
        const j = (await res.json()) as {
          detail?: string | Array<{ msg?: string; loc?: unknown }>;
        };
        if (typeof j.detail === "string") {
          detail = j.detail;
        } else if (Array.isArray(j.detail)) {
          detail = j.detail
            .map((d) => (typeof d === "object" && d && "msg" in d ? String(d.msg) : String(d)))
            .join("; ");
        }
      } else {
        const t = await res.text();
        if (t) detail = t.slice(0, 400);
      }
    } catch {
      /* keep detail */
    }
    throw new Error(`Export failed: ${detail}`);
  }
  const disposition = res.headers.get("Content-Disposition");
  const match = disposition?.match(/filename="?([^";\n]+)"?/);
  const filename =
    match?.[1] ?? `vat-export-${new Date().toISOString().slice(0, 10)}.zip`;
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

/** Fetch SBOM packages from the API (for UI and export). */
export async function fetchSbomPackages(
  options?: { component?: string; limit?: number },
  auth?: Auth,
): Promise<
  Array<{
    id: string;
    name: string;
    version: string;
    licenseId?: string;
    licenseRisk?: string;
    component?: string;
    language?: string;
  }>
> {
  const params = new URLSearchParams();
  if (options?.component) params.set("component", options.component);
  if (options?.limit != null) params.set("limit", String(options.limit));
  const url = `${API_BASE}/sbom/packages${
    params.toString() ? `?${params}` : ""
  }`;
  const res = await vatFetch(
    url,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`Failed to fetch SBOM: ${res.status}`);
  return res.json();
}

/** Download SBOM packages for an asset as CSV or JSON. Triggers browser download. */
export async function downloadSbomPackages(
  options: { component?: string; format?: "csv" | "json" },
  auth?: Auth,
): Promise<void> {
  const params = new URLSearchParams();
  if (options.component) params.set("component", options.component);
  params.set("format", options.format ?? "csv");
  const url = `${API_BASE}/sbom/packages/download?${params}`;
  const res = await vatFetch(
    url,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`Download failed: ${res.status}`);
  const disposition = res.headers.get("Content-Disposition");
  const match = disposition?.match(/filename="?([^";\n]+)"?/);
  const filename =
    match?.[1] ??
    `sbom-${options.component ?? "all"}-${new Date()
      .toISOString()
      .slice(0, 10)}.${options.format ?? "csv"}`;
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

/** Fetch auth config (which IdP options are available). Public, no auth required. */
export async function fetchAuthConfig(): Promise<{ google_enabled: boolean }> {
  const res = await fetch(`${API_BASE}/auth/config`);
  if (!res.ok) return { google_enabled: false };
  return res.json();
}

/** Exchange OAuth callback code for JWT. Code is short-lived, single-use. */
export async function exchangeCode(code: string): Promise<{
  user: { id: string; email: string; role: string; tenant_id: string | null };
  token: string;
}> {
  const res = await fetch(`${API_BASE}/auth/exchange-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  });
  if (!res.ok) {
    const text = await res.text();
    let msg = "Invalid or expired sign-in code";
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
  return res.json();
}

/** Login with username/password. Returns user + JWT. */
export async function login(
  username: string,
  password: string,
): Promise<{
  user: { id: string; email: string; role: string; tenant_id: string | null };
  token: string;
}> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    const text = await res.text();
    let msg = `Login failed: ${res.status}`;
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
  return res.json();
}

/** Auth: prefer JWT Bearer; fallback to X-VAT-User for legacy */
export function apiHeaders(
  token?: string | null,
  userEmail?: string | null,
): HeadersInit {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (token) h["Authorization"] = `Bearer ${token}`;
  else if (userEmail) h["X-VAT-User"] = userEmail;
  return h;
}

/** Headers for GET requests (no Content-Type needed) */
function authHeaders(
  token?: string | null,
  userEmail?: string | null,
): HeadersInit {
  if (token) return { Authorization: `Bearer ${token}` };
  return userEmail ? { "X-VAT-User": userEmail } : {};
}

export async function fetchTenants(
  auth?: Auth,
): Promise<Array<{ id: string; name: string; auth_method?: string }>> {
  const res = await vatFetch(
    `${API_BASE}/tenants`,
    { headers: apiHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function fetchUsers(
  auth?: Auth,
  tenantId?: string,
): Promise<
  Array<{ id: string; tenant_id: string | null; email: string; role: string }>
> {
  const url = tenantId
    ? `${API_BASE}/users?tenant_id=${encodeURIComponent(tenantId)}`
    : `${API_BASE}/users`;
  const res = await vatFetch(
    url,
    { headers: apiHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function createTenant(
  body: { id: string; name: string; auth_method?: string },
  auth?: Auth,
): Promise<{ id: string; name: string; auth_method?: string }> {
  const res = await vatFetch(
    `${API_BASE}/tenants`,
    {
      method: "POST",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify(body),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function updateTenant(
  tenantId: string,
  body: { auth_method?: string },
  auth?: Auth,
): Promise<{ id: string; name: string; auth_method: string }> {
  const res = await vatFetch(
    `${API_BASE}/tenants/${encodeURIComponent(tenantId)}`,
    {
      method: "PATCH",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify(body),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function createUser(
  body: { id: string; tenant_id?: string | null; email: string; role: string },
  auth?: Auth,
): Promise<{
  id: string;
  tenant_id: string | null;
  email: string;
  role: string;
}> {
  const res = await vatFetch(
    `${API_BASE}/users`,
    {
      method: "POST",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify(body),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function updateUser(
  userId: string,
  body: { tenant_id?: string | null; role?: string },
  auth?: Auth,
): Promise<{
  id: string;
  tenant_id: string | null;
  email: string;
  role: string;
}> {
  const res = await vatFetch(
    `${API_BASE}/users/${encodeURIComponent(userId)}`,
    {
      method: "PATCH",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify(body),
    },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function deleteUser(userId: string, auth?: Auth): Promise<void> {
  const res = await vatFetch(
    `${API_BASE}/users/${encodeURIComponent(userId)}`,
    { method: "DELETE", headers: apiHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
}

export async function deleteTenant(
  tenantId: string,
  auth?: Auth,
): Promise<void> {
  const res = await vatFetch(
    `${API_BASE}/tenants/${encodeURIComponent(tenantId)}`,
    { method: "DELETE", headers: apiHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
}

export async function deleteAsset(assetId: string, auth?: Auth): Promise<void> {
  const res = await vatFetch(
    `${API_BASE}/assets/${encodeURIComponent(assetId)}`,
    { method: "DELETE", headers: apiHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
}

export async function groupAssetInto(
  sourceAssetId: string,
  targetAssetId: string,
  auth?: Auth,
): Promise<{
  source_asset_id: string;
  target_asset_id: string;
  findings_updated: number;
}> {
  const res = await vatFetch(
    `${API_BASE}/assets/${encodeURIComponent(sourceAssetId)}/group`,
    {
      method: "POST",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify({
        target_asset_id: targetAssetId,
        reassign_existing_findings: true,
      }),
    },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
  return res.json();
}

export async function fetchAssetAliases(
  canonicalAssetId: string,
  auth?: Auth,
): Promise<{
  canonical_asset_id: string;
  aliases: Array<{
    source_asset_id: string;
    canonical_asset_id: string;
    created_by?: string | null;
    created_at?: string | null;
  }>;
}> {
  const res = await vatFetch(
    `${API_BASE}/assets/${encodeURIComponent(canonicalAssetId)}/aliases`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
  return res.json();
}

export async function unmergeAssetFrom(
  canonicalAssetId: string,
  sourceAssetId: string,
  auth?: Auth,
): Promise<{
  canonical_asset_id: string;
  source_asset_id: string;
  alias_removed: boolean;
  restored_findings: number;
}> {
  const res = await vatFetch(
    `${API_BASE}/assets/${encodeURIComponent(canonicalAssetId)}/unmerge`,
    {
      method: "POST",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify({ source_asset_id: sourceAssetId }),
    },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
  return res.json();
}

export interface AssetMergeSuggestion {
  source_asset_id: string;
  target_asset_id: string;
  strategy: "digest" | "exact_ref" | "sbom_similarity" | "name_heuristic";
  score: number;
  confidence: "high" | "medium" | "low";
  requires_review: boolean;
  auto_merge_eligible: boolean;
  details: Record<string, unknown>;
  review_status?: "pending" | "approved" | "denied";
  review_note?: string | null;
  review_updated_at?: string | null;
}

export async function fetchAssetMergeSuggestions(
  sourceAssetId: string,
  auth?: Auth,
  limit = 10,
  includeReviewed = false,
): Promise<{
  source_asset_id: string;
  count: number;
  suggestions: AssetMergeSuggestion[];
}> {
  const res = await vatFetch(
    `${API_BASE}/assets/${encodeURIComponent(
      sourceAssetId,
    )}/merge-suggestions?limit=${encodeURIComponent(
      String(limit),
    )}&include_reviewed=${includeReviewed ? "true" : "false"}`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
  return res.json();
}

export interface AssetMergeReviewRecord {
  id: number;
  source_asset_id: string;
  target_asset_id: string;
  status: "pending" | "approved" | "denied";
  note?: string | null;
  strategy?: string | null;
  score?: number | null;
  confidence?: "high" | "medium" | "low" | string | null;
  details: Record<string, unknown>;
  created_by?: string | null;
  updated_by?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface AssetDigestConflictRecord {
  id: number;
  asset_id: string;
  tag: string;
  status: "open" | "acknowledged" | string;
  digests: string[];
  acknowledged_by?: string | null;
  acknowledged_at?: string | null;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
}

export async function fetchAssetMergeReviews(
  sourceAssetId: string,
  auth?: Auth,
): Promise<{
  source_asset_id: string;
  count: number;
  reviews: AssetMergeReviewRecord[];
}> {
  const res = await vatFetch(
    `${API_BASE}/assets/${encodeURIComponent(sourceAssetId)}/merge-reviews`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
  return res.json();
}

export async function upsertAssetMergeReview(
  sourceAssetId: string,
  targetAssetId: string,
  body: {
    status: "pending" | "approved" | "denied";
    note?: string;
    strategy?: "digest" | "exact_ref" | "sbom_similarity" | "name_heuristic";
    score?: number;
    confidence?: "high" | "medium" | "low";
    details?: Record<string, unknown>;
  },
  auth?: Auth,
): Promise<AssetMergeReviewRecord> {
  const res = await vatFetch(
    `${API_BASE}/assets/${encodeURIComponent(
      sourceAssetId,
    )}/merge-reviews/${encodeURIComponent(targetAssetId)}`,
    {
      method: "PUT",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify(body),
    },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
  return res.json();
}

export async function deleteAssetMergeReview(
  sourceAssetId: string,
  targetAssetId: string,
  auth?: Auth,
): Promise<{ deleted: boolean }> {
  const res = await vatFetch(
    `${API_BASE}/assets/${encodeURIComponent(
      sourceAssetId,
    )}/merge-reviews/${encodeURIComponent(targetAssetId)}`,
    { method: "DELETE", headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
  return res.json();
}

export async function fetchAssetDigestConflicts(
  assetId: string,
  auth?: Auth,
): Promise<{
  asset_id: string;
  count: number;
  conflicts: AssetDigestConflictRecord[];
}> {
  const res = await vatFetch(
    `${API_BASE}/assets/${encodeURIComponent(assetId)}/digest-conflicts`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
  return res.json();
}

export async function acknowledgeAssetDigestConflict(
  assetId: string,
  tag: string,
  acknowledged: boolean,
  auth?: Auth,
): Promise<AssetDigestConflictRecord> {
  const res = await vatFetch(
    `${API_BASE}/assets/${encodeURIComponent(
      assetId,
    )}/digest-conflicts/${encodeURIComponent(tag)}/ack`,
    {
      method: "PUT",
      headers: apiHeaders(auth?.token, auth?.userEmail),
      body: JSON.stringify({ acknowledged }),
    },
    auth,
  );
  if (!res.ok) {
    const text = await res.text();
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const j = JSON.parse(text);
      if (j.detail)
        msg = typeof j.detail === "string" ? j.detail : String(j.detail);
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
  return res.json();
}

export async function fetchTrivyStatus(auth?: Auth): Promise<{
  ingestUrl: string;
  ingestUrlJson: string;
  apiKeyConfigured: boolean;
  keys: Array<{ sourceId: string; keyPrefix: string }>;
}> {
  const res = await vatFetch(
    `${API_BASE}/settings/trivy/status`,
    { headers: authHeaders(auth?.token, auth?.userEmail) },
    auth,
  );
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

/** Finding shape from API (camelCase) */
export interface ApiFinding {
  id: string;
  findingType: string;
  fingerprintId: string;
  cveId: string;
  severity: string;
  status: string;
  componentBase?: string | null;
  component?: string | null;
  image?: string | null;
  branch?: string | null;
  tag?: string | null;
  title?: string | null;
  description?: string | null;
  source?: string | null;
  team?: string | null;
  owner?: string | null;
  trackerId?: string | null;
  controlRef?: string | null;
  slaDue?: string | null;
  cvss?: string | null;
  epss?: string | null;
  justification?: string | null;
  compensatingControls?: string | null;
  reviewerNote?: string | null;
  trackerComment?: boolean;
  sources: Array<{ name: string; importedAt: string }>;
  suppressionScope?: string | null;
  attestation?: Record<string, unknown> | null;
  regressionOf?: string[] | null;
  regressionCount?: number;
  audit: Array<{
    ts: string;
    user: string;
    action: string;
    note: string | null;
  }>;
  archived?: boolean;
  archivedAt?: string | null;
  archivedReason?: string | null;
  created?: string | null;
}
