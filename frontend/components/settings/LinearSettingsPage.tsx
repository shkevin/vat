"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { mono, sans } from "@/lib/styles";
import { fetchLinearStatus, putLinearCredentials, syncLinear } from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";
import { DEFAULT_ISSUE_TEMPLATE, TRACKER_TYPES } from "@/lib/constants";
import type { Tracker } from "@/types";
import type { WatchedLabel } from "@/types";

const TRACKER_URL_PRESETS: Record<string, string> = {
  linear: "https://linear.app/yourteam/issue/",
  jira: "https://yourorg.atlassian.net/browse/",
  github: "https://github.com/yourorg/repo/issues/",
};

interface LinearStatus {
  apiKeyConfigured: boolean;
  teamIdConfigured: boolean;
  webhookSecretConfigured: boolean;
  webhookUrl: string;
}

interface LinearSettingsPageProps {
  tracker: Tracker;
  labels: WatchedLabel[];
  onTrackerChange?: (tracker: Tracker) => void;
  onLabelsChange?: (labels: WatchedLabel[]) => void;
  onRemoveTracker?: () => void;
}

export function LinearSettingsPage({ tracker, labels, onTrackerChange, onLabelsChange, onRemoveTracker }: LinearSettingsPageProps) {
  const { token } = useAuth();
  const auth = { token };
  const [status, setStatus] = useState<LinearStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [teamId, setTeamId] = useState("");
  const [webhookSecret, setWebhookSecret] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveResult, setSaveResult] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<string | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);
  const isLinear = tracker?.type === "linear";

  const load = useCallback(async () => {
    if (!isLinear) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const s = await fetchLinearStatus(auth);
      setStatus(s);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load status");
      setStatus(null);
    } finally {
      setLoading(false);
    }
  }, [isLinear, token]);

  useEffect(() => {
    load();
  }, [load]);

  const copyWebhookUrl = () => {
    if (!status?.webhookUrl) return;
    navigator.clipboard.writeText(status.webhookUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSaveCredentials = useCallback(async () => {
    setSaving(true);
    setSaveError(null);
    setSaveResult(null);
    try {
      const res = await putLinearCredentials(
        {
          apiKey: apiKey || undefined,
          teamId: teamId || undefined,
          webhookSecret: webhookSecret || undefined,
        },
        auth
      );
      setApiKey("");
      setTeamId("");
      setWebhookSecret("");
      await load();
      if (res.labels?.errors?.length) {
        setSaveError(res.labels.errors.join("; "));
      } else if (res.labels && res.labels.created > 0) {
        setSaveResult("Credentials saved. Labels ensured in Linear.");
      } else {
        setSaveResult("Credentials saved.");
      }
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  }, [apiKey, teamId, webhookSecret, load, token]);

  const handleSync = useCallback(async () => {
    setSyncing(true);
    setSyncError(null);
    setSyncResult(null);
    try {
      const res = await syncLinear(auth);
      const parts: string[] = [];
      if (res.dispatched) {
        parts.push("Sync queued. VAT and Linear will sync in the background.");
      } else {
        if (res.linked != null && res.linked > 0) parts.push(`Linked ${res.linked} findings.`);
        if (res.reset != null && res.reset > 0) parts.push(`Retrying ${res.reset} failed events.`);
        if (res.processed != null && res.processed > 0) parts.push(`Processed ${res.processed} events.`);
        if (res.backfill_enqueued != null && res.backfill_enqueued > 0) parts.push(`Enqueued ${res.backfill_enqueued} for sync.`);
      }
      setSyncResult(parts.length > 0 ? parts.join(" ") : "Sync complete.");
    } catch (e) {
      setSyncError(e instanceof Error ? e.message : "Failed to sync with Linear");
    } finally {
      setSyncing(false);
    }
  }, [token]);

  return (
    <div>
      {/* Config on top — standardized with Aikido source integration */}
      <TrackerConfigForm tracker={tracker} onTrackerChange={onTrackerChange} onRemoveTracker={onRemoveTracker} />
      <LabelsConfigForm labels={labels} onLabelsChange={onLabelsChange} />

      {isLinear && (
        <>
          <div
            style={{
              ...mono,
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: "0.12em",
              color: "var(--app-muted)",
              textTransform: "uppercase",
              marginBottom: 16,
              marginTop: 24,
            }}
          >
            Linear Integration
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 12,
              marginBottom: 20,
              padding: "12px 16px",
              background: "var(--app-card-bg)",
              border: "1px solid var(--app-border)",
              borderRadius: 6,
            }}
          >
            <label style={{ ...sans, fontSize: 12, color: "var(--app-fg)", flex: 1, cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={!!tracker.useAikidoTracking}
                onChange={async (e) => {
                  const next = { ...tracker, useAikidoTracking: e.target.checked };
                  await onTrackerChange?.(next);
                }}
                style={{ marginRight: 10 }}
              />
              Use Aikido&apos;s Linear integration for tracking
            </label>
            <span style={{ ...mono, fontSize: 9, color: "var(--app-muted)" }}>
              VAT pulls linked tasks from Aikido; canvas shows Aikido Tracker node
            </span>
          </div>

          {loading ? (
            <div style={{ ...sans, fontSize: 12, color: "var(--app-muted)", padding: 20, marginBottom: 20 }}>
              Loading Linear status…
            </div>
          ) : error ? (
            <div
              style={{
                background: "var(--app-input-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 6,
                padding: 16,
                marginBottom: 20,
              }}
            >
              <div style={{ ...sans, fontSize: 12, color: "var(--app-danger)" }}>{error}</div>
              <button
                onClick={load}
                style={{
                  ...mono,
                  marginTop: 10,
                  padding: "6px 12px",
                  background: "var(--app-border)",
                  border: "1px solid var(--app-border)",
                  borderRadius: 4,
                  color: "var(--app-muted)",
                  cursor: "pointer",
                  fontSize: 10,
                }}
              >
                Retry
              </button>
            </div>
          ) : status ? (
            <div
              style={{
                background: "var(--app-card-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 6,
                padding: 20,
                marginBottom: 20,
              }}
            >
              <div style={{ ...sans, fontSize: 12, color: "var(--app-muted)", marginBottom: 16, lineHeight: 1.5 }}>
                VAT creates issues in Linear and syncs [VAT] comments bidirectionally. <strong>Webhook</strong> (real-time): register the webhook URL in Linear and enter the secret below — polling is disabled. <strong>API polling</strong>: when no webhook secret is set, VAT polls every few minutes. A reconciliation job runs every 6 hours (configurable) to catch missed webhooks. For watched label auto-inject, subscribe to <strong>Issue</strong> → <strong>Update</strong> in addition to <strong>Comment</strong> → <strong>Create</strong>.
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Push mode</label>
                <select
                  value={tracker.pushMode ?? "groups"}
                  onChange={async (e) => {
                    const next = { ...tracker, pushMode: e.target.value as "groups" | "instances" };
                    await onTrackerChange?.(next);
                  }}
                  style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
                >
                  <option value="groups">Groups — one ticket per VAT group (backend-calculated)</option>
                  <option value="instances">Instances — one ticket per finding</option>
                </select>
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Push minimum severity</label>
                <select
                  value={tracker.pushMinSeverity ?? "high"}
                  onChange={async (e) => {
                    const val = e.target.value as "all" | "critical" | "high" | "medium" | "low" | "informational";
                    const next = { ...tracker, pushMinSeverity: val };
                    await onTrackerChange?.(next);
                  }}
                  style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
                >
                  <option value="all">All severities</option>
                  <option value="critical">Critical only</option>
                  <option value="high">High and above</option>
                  <option value="medium">Medium and above</option>
                  <option value="low">Low and above</option>
                </select>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                <div>
                  <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>API key</label>
                  <input
                    type="password"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder={status.apiKeyConfigured ? "•••••••• (leave blank to keep)" : "Enter API key"}
                    autoComplete="off"
                    style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
                  />
                </div>
                <div>
                  <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Team ID</label>
                  <input
                    type="text"
                    value={teamId}
                    onChange={(e) => setTeamId(e.target.value)}
                    placeholder={status.teamIdConfigured ? "•••••••• (leave blank to keep)" : "Enter Linear team ID"}
                    autoComplete="off"
                    style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
                  />
                </div>
                <div>
                  <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Webhook secret</label>
                  <input
                    type="password"
                    value={webhookSecret}
                    onChange={(e) => setWebhookSecret(e.target.value)}
                    placeholder={status.webhookSecretConfigured ? "•••••••• (leave blank to keep)" : "Enter webhook secret"}
                    autoComplete="off"
                    style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
                  />
                </div>
                {(apiKey || teamId || webhookSecret) && (
                  <>
                    {saveError && <div style={{ ...sans, fontSize: 12, color: "var(--app-danger)" }}>{saveError}</div>}
                    {saveResult && !saveError && <div style={{ ...sans, fontSize: 12, color: "var(--app-success, #22c55e)" }}>{saveResult}</div>}
                    <button
                      onClick={handleSaveCredentials}
                      disabled={saving}
                      style={{
                        ...mono,
                        padding: "8px 16px",
                        background: saving ? "var(--app-border)" : "var(--app-accent)",
                        border: "none",
                        borderRadius: 6,
                        color: "var(--app-fg)",
                        cursor: saving ? "not-allowed" : "pointer",
                        fontSize: 11,
                        fontWeight: 600,
                      }}
                    >
                      {saving ? "Saving…" : "Save credentials"}
                    </button>
                  </>
                )}
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  <span style={{ ...mono, fontSize: 10, color: "var(--app-muted)" }}>
                    Webhook URL
                  </span>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                    <code
                      style={{
                        ...mono,
                        fontSize: 10,
                        color: "var(--app-accent)",
                        background: "var(--app-input-bg)",
                        padding: "6px 10px",
                        borderRadius: 4,
                        flex: "1 1 0",
                        minWidth: 0,
                        overflowWrap: "break-word",
                        wordBreak: "break-all",
                      }}
                    >
                      {status.webhookUrl}
                    </code>
                    <button
                      onClick={copyWebhookUrl}
                      style={{
                        ...mono,
                        padding: "6px 12px",
                        background: copied ? "var(--app-success)" : "var(--app-border)",
                        border: "1px solid var(--app-border)",
                        borderRadius: 4,
                        color: copied ? "var(--app-bg)" : "var(--app-muted)",
                        cursor: "pointer",
                        fontSize: 10,
                      }}
                    >
                      {copied ? "Copied" : "Copy"}
                    </button>
                  </div>
                </div>
              </div>

              {status.apiKeyConfigured && status.teamIdConfigured && (
                <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 16 }}>
                  <span style={{ ...mono, fontSize: 10, color: "var(--app-muted)" }}>
                    Sync
                  </span>
                  <div style={{ ...sans, fontSize: 11, color: "var(--app-muted)", lineHeight: 1.5 }}>
                    Sync states between VAT and Linear: link existing issues, create new ones, retry failed events, and pull [VAT] updates from Linear (when polling is enabled).
                  </div>
                  <button
                    onClick={handleSync}
                    disabled={syncing}
                    style={{
                      ...mono,
                      padding: "8px 16px",
                      background: syncing ? "var(--app-border)" : "var(--app-accent)",
                      border: "none",
                      borderRadius: 6,
                      color: "var(--app-fg)",
                      cursor: syncing ? "not-allowed" : "pointer",
                      fontSize: 11,
                      fontWeight: 600,
                      opacity: syncing ? 0.6 : 1,
                      alignSelf: "flex-start",
                    }}
                  >
                    {syncing ? "Syncing…" : "Sync VAT ↔ Linear"}
                  </button>
                  {syncResult && (
                    <span style={{ ...sans, fontSize: 11, color: "var(--app-success)" }}>
                      {syncResult}
                    </span>
                  )}
                  {syncError && (
                    <span style={{ ...sans, fontSize: 11, color: "var(--app-danger)" }}>
                      {syncError}
                    </span>
                  )}
                </div>
              )}

              <div style={{ marginTop: 16 }}>
                <a
                  href="https://developers.linear.app"
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    ...mono,
                    fontSize: 10,
                    color: "var(--app-accent)",
                    textDecoration: "none",
                  }}
                >
                  Linear API docs →
                </a>
              </div>
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}

function IssueTemplateField({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(value);
  const preview = value.slice(0, 80) + (value.length > 80 ? "…" : "");
  useEffect(() => {
    if (!open) setDraft(value);
  }, [value, open]);

  const openModal = () => {
    setDraft(value);
    setOpen(true);
  };
  const closeModal = () => setOpen(false);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeModal();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);
  const apply = () => {
    onChange(draft);
    closeModal();
  };

  return (
    <div>
      <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>
        Issue template
      </label>
      <div
        onClick={openModal}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => e.key === "Enter" && openModal()}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "10px 12px",
          background: "var(--app-input-bg)",
          border: "1px solid var(--app-border)",
          borderRadius: 6,
          cursor: "pointer",
          minHeight: 44,
        }}
      >
        <span style={{ ...mono, fontSize: 11, color: "var(--app-muted)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {preview}
        </span>
        <span style={{ ...mono, fontSize: 10, color: "var(--app-accent)", fontWeight: 600 }}>Edit</span>
      </div>
      <div style={{ ...sans, fontSize: 10, color: "var(--app-muted)", marginTop: 4 }}>
        Injected into new Linear issues. Placeholders: <code style={{ ...mono, color: "var(--app-muted)" }}>{`{finding_id}`}</code>, <code style={{ ...mono, color: "var(--app-muted)" }}>{`{file_path}`}</code>, <code style={{ ...mono, color: "var(--app-muted)" }}>{`{line}`}</code>, <code style={{ ...mono, color: "var(--app-muted)" }}>{`{source_file_url}`}</code> (Aikido code link), <code style={{ ...mono, color: "var(--app-muted)" }}>{`{source_issue_url}`}</code> (link to finding in source).
      </div>

      {open && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 1000,
            background: "rgba(0,0,0,0.5)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: 24,
          }}
          onClick={closeModal}
        >
          <div
            style={{
              background: "var(--app-card-bg)",
              border: "1px solid var(--app-border)",
              borderRadius: 8,
              boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
              width: "100%",
              maxWidth: 640,
              maxHeight: "85vh",
              display: "flex",
              flexDirection: "column",
              overflow: "hidden",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--app-border)" }}>
              <div style={{ ...mono, fontSize: 11, fontWeight: 700, letterSpacing: "0.08em", color: "var(--app-muted)", textTransform: "uppercase" }}>
                Issue Template
              </div>
              <div style={{ ...sans, fontSize: 12, color: "var(--app-muted)", marginTop: 4 }}>
                Edit the template injected into new Linear issues. Use <code style={{ ...mono, color: "var(--app-accent)" }}>{`{cve_id}`}</code> as placeholder.
              </div>
            </div>
            <div style={{ flex: 1, overflow: "auto", padding: 20 }}>
              <textarea
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                placeholder={placeholder}
                rows={16}
                autoFocus
                style={{
                  ...mono,
                  width: "100%",
                  minHeight: 320,
                  background: "var(--app-bg)",
                  border: "1px solid var(--app-border)",
                  borderRadius: 6,
                  padding: "12px 14px",
                  color: "var(--app-fg)",
                  fontSize: 12,
                  lineHeight: 1.5,
                  resize: "vertical",
                }}
              />
            </div>
            <div style={{ padding: "14px 20px", borderTop: "1px solid var(--app-border)", display: "flex", justifyContent: "flex-end", gap: 10 }}>
              <button
                onClick={closeModal}
                style={{
                  ...mono,
                  padding: "8px 16px",
                  background: "transparent",
                  border: "1px solid var(--app-border)",
                  borderRadius: 6,
                  color: "var(--app-muted)",
                  cursor: "pointer",
                  fontSize: 11,
                }}
              >
                Cancel
              </button>
              <button
                onClick={apply}
                style={{
                  ...mono,
                  padding: "8px 16px",
                  background: "var(--app-accent)",
                  border: "none",
                  borderRadius: 6,
                  color: "var(--app-fg)",
                  cursor: "pointer",
                  fontSize: 11,
                  fontWeight: 600,
                }}
              >
                Apply
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function TrackerConfigForm({
  tracker,
  onTrackerChange,
  onRemoveTracker,
}: {
  tracker: Tracker;
  onTrackerChange?: (tracker: Tracker) => void;
  onRemoveTracker?: () => void;
}) {
  const [edit, setEdit] = useState<Tracker>({ ...tracker });
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const prevTrackerRef = useRef(tracker);
  const trackerTypeEntries = Object.entries(TRACKER_TYPES);

  useEffect(() => {
    if (prevTrackerRef.current !== tracker) {
      prevTrackerRef.current = tracker;
      setEdit({ ...tracker });
    }
  }, [tracker]);

  const handleSave = useCallback(async () => {
    if (!onTrackerChange) return;
    setSaving(true);
    setSaveError(null);
    try {
      const toSave = { ...edit, issueTemplate: edit.issueTemplate ?? DEFAULT_ISSUE_TEMPLATE };
      await onTrackerChange(toSave);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  }, [edit, onTrackerChange]);

  if (!onTrackerChange) {
    return (
      <div style={{ marginTop: 24 }}>
        <div style={{ ...mono, fontSize: 9, fontWeight: 700, letterSpacing: "0.12em", color: "var(--app-muted)", textTransform: "uppercase", marginBottom: 10 }}>Display Config</div>
        <div style={{ background: "var(--app-card-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: 14 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ ...mono, fontSize: 14 }}>{tracker.icon}</span>
            <span style={{ ...sans, fontSize: 14, fontWeight: 600, color: "var(--app-fg)" }}>{tracker.name}</span>
          </div>
          <div style={{ ...mono, fontSize: 11, color: "var(--app-muted)", marginTop: 8 }}>Base URL: {tracker.baseUrl}</div>
          <div style={{ ...mono, fontSize: 11, color: "var(--app-muted)" }}>Comment prefix: {tracker.commentPrefix}</div>
        </div>
      </div>
    );
  }

  const handleRemove = useCallback(async () => {
    if (!onRemoveTracker || !confirm("Remove the task tracker? You can add it again later.")) return;
    try {
      await onTrackerChange?.({} as Tracker);
      onRemoveTracker();
    } catch {
      // ignore
    }
  }, [onTrackerChange, onRemoveTracker]);

  return (
    <div style={{ marginTop: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
        <div style={{ ...mono, fontSize: 9, fontWeight: 700, letterSpacing: "0.12em", color: "var(--app-muted)", textTransform: "uppercase" }}>Display Config</div>
        {onRemoveTracker && (
          <button
            onClick={handleRemove}
            style={{
              ...mono,
              padding: "6px 12px",
              background: "transparent",
              border: "1px solid var(--app-danger)",
              borderRadius: 4,
              color: "var(--app-danger)",
              cursor: "pointer",
              fontSize: 10,
            }}
          >
            Remove tracker
          </button>
        )}
      </div>
      <div style={{ background: "var(--app-card-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: 16 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div>
              <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Tracker Type</label>
              <select
                value={edit.type}
                onChange={(e) => {
                  const t = e.target.value;
                  setEdit((p) => ({ ...p, type: t, baseUrl: TRACKER_URL_PRESETS[t] ?? p.baseUrl }));
                }}
                style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
              >
                {trackerTypeEntries.map(([k, v]) => (
                  <option key={k} value={v.type}>{v.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Display Name</label>
              <input
                value={edit.name}
                onChange={(e) => setEdit((p) => ({ ...p, name: e.target.value }))}
                placeholder="Linear"
                style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
              />
            </div>
          </div>
          <div>
            <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Issue Base URL</label>
            <input
              value={edit.baseUrl}
              onChange={(e) => setEdit((p) => ({ ...p, baseUrl: e.target.value }))}
              style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
            />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div>
              <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Icon</label>
              <input
                value={edit.icon}
                onChange={(e) => setEdit((p) => ({ ...p, icon: e.target.value }))}
                placeholder="◈"
                style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
              />
            </div>
            <div>
              <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Comment prefix</label>
              <input
                value={edit.commentPrefix}
                onChange={(e) => setEdit((p) => ({ ...p, commentPrefix: e.target.value }))}
                placeholder="[VAT]"
                style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
              />
            </div>
          </div>
          <div>
            <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Description</label>
            <input
              value={edit.description}
              onChange={(e) => setEdit((p) => ({ ...p, description: e.target.value }))}
              placeholder="Optional"
              style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
            />
          </div>
          <IssueTemplateField
            value={edit.issueTemplate ?? DEFAULT_ISSUE_TEMPLATE}
            onChange={(v) => setEdit((p) => ({ ...p, issueTemplate: v }))}
            placeholder="Placeholders: {finding_id}, {file_path}, {line}, {source_file_url}, {source_issue_url}"
          />
          {saveError && (
            <div style={{ ...sans, fontSize: 12, color: "var(--app-danger)", marginBottom: 8 }}>
              {saveError}
            </div>
          )}
          <button
            onClick={handleSave}
            disabled={!edit.name?.trim() || saving}
            style={{
              ...mono,
              padding: "8px 16px",
              background: edit.name?.trim() && !saving ? "var(--app-accent)" : "var(--app-border)",
              border: "none",
              borderRadius: 6,
              color: "var(--app-fg)",
              cursor: edit.name?.trim() && !saving ? "pointer" : "not-allowed",
              fontSize: 11,
              fontWeight: 600,
            }}
          >
            {saving ? "Saving…" : "Save Tracker Config"}
          </button>
        </div>
      </div>
    </div>
  );
}

function LabelsConfigForm({
  labels,
  onLabelsChange,
}: {
  labels: WatchedLabel[];
  onLabelsChange?: (labels: WatchedLabel[]) => void;
}) {
  const [newName, setNewName] = useState("");
  const [newColor, setNewColor] = useState("#38bdf8");
  const [newDesc, setNewDesc] = useState("");
  const [editId, setEditId] = useState<string | null>(null);
  const [editState, setEditState] = useState<{ name: string; color: string; description: string }>({ name: "", color: "#38bdf8", description: "" });

  const add = useCallback(() => {
    if (!newName.trim() || !onLabelsChange) return;
    const name = newName.trim().toLowerCase().replace(/\s+/g, "-");
    onLabelsChange([
      ...labels,
      { id: "l-" + Math.random().toString(36).slice(2, 7), name, color: newColor, description: newDesc.trim() },
    ]);
    setNewName("");
    setNewDesc("");
    setNewColor("#38bdf8");
  }, [newName, newColor, newDesc, labels, onLabelsChange]);

  const remove = useCallback(
    (id: string) => {
      if (!onLabelsChange) return;
      onLabelsChange(labels.filter((l) => l.id !== id));
    },
    [labels, onLabelsChange]
  );

  const startEdit = useCallback((l: WatchedLabel) => {
    setEditId(l.id);
    setEditState({ name: l.name, color: l.color || "#E53935", description: l.description || "" });
  }, []);

  const saveEdit = useCallback(() => {
    if (!onLabelsChange || !editId) return;
    onLabelsChange(
      labels.map((l) => (l.id === editId ? { ...l, ...editState } : l))
    );
    setEditId(null);
  }, [editId, editState, labels, onLabelsChange]);

  return (
    <div style={{ marginTop: 24 }}>
      <div style={{ ...mono, fontSize: 9, fontWeight: 700, letterSpacing: "0.12em", color: "var(--app-muted)", textTransform: "uppercase", marginBottom: 10 }}>Labels on New Issues</div>
      <div style={{ ...sans, fontSize: 12, color: "var(--app-muted)", marginBottom: 12, lineHeight: 1.5 }}>
        These labels are applied when VAT creates new Linear issues. If a label does not exist in your Linear team, VAT will auto-create it (requires API key with Write or Admin permission).
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 16 }}>
        {labels.map((l) =>
          editId === l.id ? (
            <div key={l.id} style={{ background: "var(--app-card-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: 12 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 80px", gap: 8, marginBottom: 8 }}>
                <div>
                  <label style={{ ...mono, fontSize: 9, color: "var(--app-muted)", textTransform: "uppercase" }}>Label name</label>
                  <input
                    value={editState.name}
                    onChange={(e) => setEditState((p) => ({ ...p, name: e.target.value }))}
                    style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 4, padding: "6px 10px", color: "var(--app-fg)", fontSize: 12, marginTop: 4 }}
                  />
                </div>
                <div>
                  <label style={{ ...mono, fontSize: 9, color: "var(--app-muted)", textTransform: "uppercase" }}>Color</label>
                  <input type="color" value={editState.color} onChange={(e) => setEditState((p) => ({ ...p, color: e.target.value }))} style={{ width: "100%", height: 32, marginTop: 4, background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 4, cursor: "pointer" }} />
                </div>
              </div>
              <div style={{ marginBottom: 8 }}>
                <label style={{ ...mono, fontSize: 9, color: "var(--app-muted)", textTransform: "uppercase" }}>Description</label>
                <input
                  value={editState.description}
                  onChange={(e) => setEditState((p) => ({ ...p, description: e.target.value }))}
                  style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 4, padding: "6px 10px", color: "var(--app-fg)", fontSize: 12, marginTop: 4 }}
                />
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button onClick={saveEdit} disabled={!editState.name?.trim()} style={{ ...mono, padding: "6px 12px", background: "var(--app-accent)", border: "none", borderRadius: 4, color: "var(--app-fg)", cursor: "pointer", fontSize: 10 }}>Save</button>
                <button onClick={() => setEditId(null)} style={{ ...mono, padding: "6px 12px", background: "transparent", border: "1px solid var(--app-border)", borderRadius: 4, color: "var(--app-muted)", cursor: "pointer", fontSize: 10 }}>Cancel</button>
              </div>
            </div>
          ) : (
            <div key={l.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: 10, background: "var(--app-card-bg)", borderRadius: 6, border: "1px solid var(--app-border)" }}>
              <div style={{ width: 8, height: 8, borderRadius: 4, background: l.color || "#E53935" }} />
              <span style={{ ...mono, fontSize: 12, fontWeight: 600, color: l.color || "#E53935" }}>{l.name}</span>
              {l.description && <span style={{ ...sans, fontSize: 12, color: "var(--app-muted)", flex: 1 }}>{l.description}</span>}
              {onLabelsChange && (
                <div style={{ display: "flex", gap: 6, marginLeft: "auto" }}>
                  <button onClick={() => startEdit(l)} style={{ ...mono, padding: "4px 10px", background: "transparent", border: "1px solid var(--app-border)", borderRadius: 4, color: "var(--app-muted)", cursor: "pointer", fontSize: 10 }}>Edit</button>
                  <button onClick={() => remove(l.id)} style={{ ...mono, padding: "4px 10px", background: "transparent", border: "1px solid var(--app-border)", borderRadius: 4, color: "var(--app-danger)", cursor: "pointer", fontSize: 10 }}>Remove</button>
                </div>
              )}
            </div>
          )
        )}
      </div>
      {onLabelsChange && (
        <div style={{ background: "var(--app-card-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: 14 }}>
          <div style={{ ...mono, fontSize: 9, fontWeight: 700, color: "var(--app-muted)", textTransform: "uppercase", marginBottom: 10 }}>Add Label to Apply</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 80px", gap: 8, marginBottom: 8 }}>
            <div>
              <label style={{ ...mono, fontSize: 9, color: "var(--app-muted)", textTransform: "uppercase" }}>Label name</label>
              <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="security-bug" style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 4, padding: "6px 10px", color: "var(--app-fg)", fontSize: 12, marginTop: 4 }} />
            </div>
            <div>
              <label style={{ ...mono, fontSize: 9, color: "var(--app-muted)", textTransform: "uppercase" }}>Color</label>
              <input type="color" value={newColor} onChange={(e) => setNewColor(e.target.value)} style={{ width: "100%", height: 32, marginTop: 4, background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 4, cursor: "pointer" }} />
            </div>
          </div>
          <div style={{ marginBottom: 10 }}>
            <label style={{ ...mono, fontSize: 9, color: "var(--app-muted)", textTransform: "uppercase" }}>Description</label>
            <input value={newDesc} onChange={(e) => setNewDesc(e.target.value)} placeholder="Optional" style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 4, padding: "6px 10px", color: "var(--app-fg)", fontSize: 12, marginTop: 4 }} />
          </div>
          <button onClick={add} disabled={!newName.trim()} style={{ ...mono, padding: "8px 16px", background: newName.trim() ? "var(--app-accent)" : "var(--app-border)", border: "none", borderRadius: 6, color: "var(--app-fg)", cursor: newName.trim() ? "pointer" : "not-allowed", fontSize: 11, fontWeight: 600 }}>+ Add Label</button>
        </div>
      )}
    </div>
  );
}
