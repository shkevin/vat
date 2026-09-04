"use client";

import { useState, useEffect, useCallback } from "react";
import { mono, sans } from "@/lib/styles";
import {
  fetchAikidoStatus,
  fetchAikidoSyncStatus,
  fetchAikidoTeams,
  putAikidoCredentials,
  syncAikido,
} from "@/lib/api";
import { resolveAssetIdsByName } from "@/lib/assetUtils";
import { useAuth } from "@/contexts/AuthContext";
import { useVATData } from "@/contexts/VATDataContext";
import {
  getAikidoSyncPollDelayMs,
  hasRestorableAikidoSyncProgress,
  shouldKeepAikidoSyncingAfterPollError,
  shouldPauseAikidoSyncPolling,
} from "@/lib/aikidoSyncStatusGate";
import type { Tracker } from "@/types";

interface AikidoStatus {
  clientIdConfigured: boolean;
  clientSecretConfigured: boolean;
  region: string;
  oauthConfigured: boolean;
  webhookSecretConfigured: boolean;
  webhookUrl: string;
  syncBackEnabled?: boolean;
}

interface AikidoSettingsPageProps {
  /** Source ID scopes sync status to this node (multiple Aikido sources = different workspaces).
   * When undefined, the source is not yet on the canvas — sync is disabled until the integration is created. */
  sourceId?: string | null;
  /** Tracker config — used for useAikidoTracking toggle. When enabled, VAT pulls linked Linear tasks from Aikido. */
  tracker?: Tracker;
  onTrackerChange?: (tracker: Tracker) => void;
}

export function AikidoSettingsPage({
  sourceId,
  tracker,
  onTrackerChange,
}: AikidoSettingsPageProps) {
  const { token } = useAuth();
  const { refetch, allAssets, loadouts, saveLoadout } = useVATData();
  const auth = { token };
  const [status, setStatus] = useState<AikidoStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [region, setRegion] = useState("");
  const [webhookSecret, setWebhookSecret] = useState("");
  const [syncBackEnabled, setSyncBackEnabled] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<string | null>(null);
  const [importingTeams, setImportingTeams] = useState(false);
  const [teamImportResult, setTeamImportResult] = useState<string | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [syncStep, setSyncStep] = useState<{
    step: number;
    total: number;
    label: string;
  } | null>(null);
  const [lastSyncedAt, setLastSyncedAt] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!sourceId) return;
    setLoading(true);
    setError(null);
    try {
      const s = await fetchAikidoStatus(auth, sourceId);
      setStatus(s);
      setSyncBackEnabled(s?.syncBackEnabled ?? true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load status");
      setStatus(null);
    } finally {
      setLoading(false);
    }
  }, [token, sourceId]);

  useEffect(() => {
    if (sourceId) load();
    else setLoading(false);
  }, [load, sourceId]);

  // Check sync status on load — each source tracks independently
  useEffect(() => {
    if (!sourceId) return;
    let cancelled = false;
    fetchAikidoSyncStatus(auth, sourceId)
      .then((s) => {
        if (cancelled) return;
        if (s.lastSyncedAt) setLastSyncedAt(s.lastSyncedAt);
        // Status is per-source; we requested this source's status
        if (s.status === "running") {
          setSyncing(true);
          setSyncResult(s.message ?? "Sync running in background…");
          if (hasRestorableAikidoSyncProgress(s)) {
            setSyncStep({ step: s.step, total: s.total, label: s.label });
          } else {
            setSyncStep(null);
          }
        } else if (s.status === "success" || s.status === "error") {
          setSyncing(false);
          setSyncStep(null);
          setSyncResult(
            s.status === "success" ? s.message ?? "Sync complete." : null,
          );
          setSyncError(
            s.status === "error" ? s.message ?? "Sync failed" : null,
          );
          if (s.status === "success") refetch({ silent: true });
        }
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [sourceId, token, refetch]);

  // Poll sync status while syncing — each source tracks independently
  useEffect(() => {
    if (!syncing) return;
    let cancelled = false;
    let timeout: ReturnType<typeof setTimeout> | null = null;
    let consecutiveFailures = 0;

    const schedule = () => {
      if (cancelled) return;
      if (
        typeof document !== "undefined" &&
        shouldPauseAikidoSyncPolling(document.visibilityState)
      ) {
        return;
      }
      timeout = setTimeout(poll, getAikidoSyncPollDelayMs(consecutiveFailures));
    };

    const poll = async () => {
      timeout = null;
      try {
        const s = await fetchAikidoSyncStatus(auth, sourceId);
        consecutiveFailures = 0;
        if (s.lastSyncedAt) setLastSyncedAt(s.lastSyncedAt);
        if (s.status === "success") {
          if (cancelled) return;
          setSyncing(false);
          setSyncStep(null);
          setSyncResult(s.message ?? "Sync complete.");
          refetch({ silent: true });
        } else if (s.status === "error") {
          if (cancelled) return;
          setSyncing(false);
          setSyncStep(null);
          setSyncError(s.message ?? "Sync failed");
          setSyncResult(null);
        } else if (s.status === "running") {
          if (cancelled) return;
          setSyncResult(s.message ?? "Sync running in background…");
          setSyncError(null);
          if (hasRestorableAikidoSyncProgress(s)) {
            setSyncStep({ step: s.step, total: s.total, label: s.label });
          }
          schedule();
        }
      } catch {
        consecutiveFailures += 1;
        if (shouldKeepAikidoSyncingAfterPollError(syncing)) {
          setSyncResult((prev) => prev ?? "Sync running in background…");
          schedule();
        }
      }
    };

    schedule();
    const onVisibilityChange = () => {
      if (
        !cancelled &&
        typeof document !== "undefined" &&
        !shouldPauseAikidoSyncPolling(document.visibilityState) &&
        !timeout
      ) {
        poll();
      }
    };
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", onVisibilityChange);
    }
    return () => {
      cancelled = true;
      if (timeout) clearTimeout(timeout);
      if (typeof document !== "undefined") {
        document.removeEventListener("visibilitychange", onVisibilityChange);
      }
    };
  }, [syncing, sourceId, token, refetch]);

  const copyWebhookUrl = () => {
    if (!status?.webhookUrl) return;
    navigator.clipboard.writeText(status.webhookUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSaveCredentials = useCallback(async () => {
    if (!sourceId) return;
    setSaving(true);
    setSaveError(null);
    try {
      await putAikidoCredentials(
        {
          sourceId,
          clientId: clientId || undefined,
          clientSecret: clientSecret || undefined,
          region: region || undefined,
          webhookSecret: webhookSecret || undefined,
        },
        auth,
      );
      setClientId("");
      setClientSecret("");
      setRegion("");
      setWebhookSecret("");
      await load();
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  }, [sourceId, clientId, clientSecret, region, webhookSecret, load, token]);

  // Save each Aikido team as a loadout of the VAT assets it owns. Teams whose
  // repos/containers were never ingested resolve to nothing and are skipped
  // rather than saved empty. Existing loadouts with the same name are
  // overwritten so a re-import tracks team membership changes.
  const handleImportTeams = useCallback(async () => {
    setImportingTeams(true);
    setTeamImportResult(null);
    try {
      const teams = await fetchAikidoTeams(auth, sourceId);
      const byName = new Map(loadouts.map((l) => [l.name.toLowerCase(), l.id]));
      let imported = 0;
      let skipped = 0;
      for (const team of teams) {
        const assetIds = resolveAssetIdsByName(team.assetNames, allAssets);
        if (assetIds.length === 0) {
          skipped++;
          continue;
        }
        await saveLoadout(
          byName.get(team.name.toLowerCase()) ?? null,
          team.name,
          assetIds.map((assetId) => ({ assetId })),
        );
        imported++;
      }
      setTeamImportResult(
        imported === 0
          ? "No Aikido team matched a known asset."
          : `Imported ${imported} team${imported === 1 ? "" : "s"} as loadouts${skipped > 0 ? ` · ${skipped} skipped with no matching assets` : ""}. Find them in the sidebar under Loadouts.`,
      );
    } catch {
      setTeamImportResult("Aikido team import failed.");
    } finally {
      setImportingTeams(false);
    }
  }, [allAssets, loadouts, saveLoadout, sourceId, token]);

  const handleSync = useCallback(async () => {
    setSyncing(true);
    setSyncError(null);
    setSyncResult(null);
    setSyncStep(null);
    try {
      const res = await syncAikido(auth, sourceId ?? undefined);
      setSyncResult(res.message);
      // Sync runs in background; fetch status immediately to show first progress step
      fetchAikidoSyncStatus(auth, sourceId)
        .then((s) => {
          if (s.status === "running" && hasRestorableAikidoSyncProgress(s)) {
            setSyncStep({ step: s.step, total: s.total, label: s.label });
          }
        })
        .catch(() => {});
    } catch (e) {
      setSyncError(
        e instanceof Error ? e.message : "Failed to sync with Aikido",
      );
      setSyncing(false);
    }
  }, [token, sourceId]);

  if (loading) {
    return (
      <div
        style={{
          ...sans,
          fontSize: 12,
          color: "var(--app-muted)",
          padding: 20,
        }}
      >
        Loading Aikido status…
      </div>
    );
  }

  if (error) {
    return (
      <div
        style={{
          background: "var(--app-input-bg)",
          border: "1px solid var(--app-border)",
          borderRadius: 6,
          padding: 16,
          marginBottom: 20,
        }}
      >
        <div style={{ ...sans, fontSize: 12, color: "var(--app-danger)" }}>
          {error}
        </div>
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
    );
  }

  if (!status) return null;

  return (
    <div>
      <div
        style={{
          ...mono,
          fontSize: 9,
          fontWeight: 700,
          letterSpacing: "0.12em",
          color: "var(--app-muted)",
          textTransform: "uppercase",
          marginBottom: 16,
        }}
      >
        Aikido Integration
      </div>

      <div
        style={{
          background: "var(--app-card-bg)",
          border: "1px solid var(--app-border)",
          borderRadius: 6,
          padding: 20,
        }}
      >
        <div
          style={{
            ...sans,
            fontSize: 12,
            color: "var(--app-muted)",
            marginBottom: 16,
            lineHeight: 1.5,
          }}
        >
          Aikido pushes findings to VAT via webhook. Configure the webhook in
          your Aikido dashboard and enter credentials below.
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div>
            <label
              style={{
                ...mono,
                fontSize: 9,
                fontWeight: 600,
                color: "var(--app-muted)",
                textTransform: "uppercase",
                display: "block",
                marginBottom: 6,
              }}
            >
              Client ID (OAuth)
            </label>
            <input
              type="password"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              placeholder={
                status.clientIdConfigured
                  ? "•••••••• (leave blank to keep)"
                  : "AIK_CLIENT_xxx"
              }
              autoComplete="off"
              style={{
                ...mono,
                width: "100%",
                background: "var(--app-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 6,
                padding: "8px 12px",
                color: "var(--app-fg)",
                fontSize: 12,
              }}
            />
          </div>
          <div>
            <label
              style={{
                ...mono,
                fontSize: 9,
                fontWeight: 600,
                color: "var(--app-muted)",
                textTransform: "uppercase",
                display: "block",
                marginBottom: 6,
              }}
            >
              Client secret (OAuth)
            </label>
            <input
              type="password"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              placeholder={
                status.clientSecretConfigured
                  ? "•••••••• (leave blank to keep)"
                  : "AIK_SECRET_xxx"
              }
              autoComplete="off"
              style={{
                ...mono,
                width: "100%",
                background: "var(--app-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 6,
                padding: "8px 12px",
                color: "var(--app-fg)",
                fontSize: 12,
              }}
            />
          </div>
          <div>
            <label
              style={{
                ...mono,
                fontSize: 9,
                fontWeight: 600,
                color: "var(--app-muted)",
                textTransform: "uppercase",
                display: "block",
                marginBottom: 6,
              }}
            >
              Region
            </label>
            <select
              value={region || status.region || "eu"}
              onChange={(e) => setRegion(e.target.value)}
              style={{
                ...mono,
                width: "100%",
                background: "var(--app-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 6,
                padding: "8px 12px",
                color: "var(--app-fg)",
                fontSize: 12,
              }}
            >
              <option value="eu">EU (app.aikido.dev)</option>
              <option value="us">US (app.us.aikido.dev)</option>
              <option value="me">ME (app.me.aikido.dev)</option>
            </select>
          </div>
          <div>
            <label
              style={{
                ...mono,
                fontSize: 9,
                fontWeight: 600,
                color: "var(--app-muted)",
                textTransform: "uppercase",
                display: "block",
                marginBottom: 6,
              }}
            >
              Webhook secret
            </label>
            <input
              type="password"
              value={webhookSecret}
              onChange={(e) => setWebhookSecret(e.target.value)}
              placeholder={
                status.webhookSecretConfigured
                  ? "•••••••• (leave blank to keep)"
                  : "Enter webhook secret"
              }
              autoComplete="off"
              style={{
                ...mono,
                width: "100%",
                background: "var(--app-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 6,
                padding: "8px 12px",
                color: "var(--app-fg)",
                fontSize: 12,
              }}
            />
          </div>
          {(clientId || clientSecret || region || webhookSecret) && (
            <>
              {saveError && (
                <div
                  style={{ ...sans, fontSize: 12, color: "var(--app-danger)" }}
                >
                  {saveError}
                </div>
              )}
              <button
                onClick={handleSaveCredentials}
                disabled={saving}
                style={{
                  ...mono,
                  padding: "8px 16px",
                  background: saving
                    ? "var(--app-border)"
                    : "var(--app-accent)",
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
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
              marginTop: 16,
              paddingTop: 16,
              borderTop: "1px solid var(--app-border)",
            }}
          >
            <div>
              <span
                style={{
                  ...mono,
                  fontSize: 10,
                  fontWeight: 600,
                  color: "var(--app-fg)",
                  display: "block",
                }}
              >
                Sync VAT status back to Aikido
              </span>
              <span
                style={{ ...sans, fontSize: 10, color: "var(--app-muted)" }}
              >
                When enabled, status changes (e.g. false-positive, mitigated) in
                VAT are sent to Aikido (ignore/unignore).
              </span>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={syncBackEnabled}
              onClick={async () => {
                if (!sourceId) return;
                const next = !syncBackEnabled;
                setSyncBackEnabled(next);
                try {
                  await putAikidoCredentials(
                    { sourceId, syncBackEnabled: next },
                    auth,
                  );
                  setStatus((s) => (s ? { ...s, syncBackEnabled: next } : s));
                } catch {
                  setSyncBackEnabled(syncBackEnabled);
                }
              }}
              style={{
                flexShrink: 0,
                width: 40,
                height: 22,
                borderRadius: 11,
                border: "none",
                background: syncBackEnabled
                  ? "var(--app-accent)"
                  : "var(--app-border)",
                cursor: "pointer",
                position: "relative",
              }}
            >
              <span
                style={{
                  position: "absolute",
                  top: 2,
                  left: syncBackEnabled ? 20 : 2,
                  width: 18,
                  height: 18,
                  borderRadius: 9,
                  background: "var(--app-fg)",
                  transition: "left 0.15s ease",
                }}
              />
            </button>
          </div>
          {onTrackerChange && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                marginTop: 16,
                paddingTop: 16,
                borderTop: "1px solid var(--app-border)",
              }}
            >
              <label
                style={{
                  ...sans,
                  fontSize: 12,
                  color: "var(--app-fg)",
                  flex: 1,
                  cursor: "pointer",
                }}
              >
                <input
                  type="checkbox"
                  checked={!!tracker?.useAikidoTracking}
                  onChange={async (e) => {
                    const next = {
                      ...(tracker || {}),
                      useAikidoTracking: e.target.checked,
                    } as Tracker;
                    await onTrackerChange?.(next);
                  }}
                  style={{ marginRight: 10 }}
                />
                Use Aikido&apos;s Linear integration for tracking
              </label>
              <span style={{ ...mono, fontSize: 9, color: "var(--app-muted)" }}>
                VAT pulls linked Linear tasks from Aikido during sync; findings
                show tracker links.
              </span>
            </div>
          )}
          {status.oauthConfigured && (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: 8,
                marginTop: 8,
              }}
            >
              <span
                style={{ ...mono, fontSize: 10, color: "var(--app-muted)" }}
              >
                Sync data from Aikido to VAT
              </span>
              {sourceId == null && (
                <div
                  style={{
                    ...sans,
                    fontSize: 11,
                    color: "var(--app-muted)",
                    padding: "8px 12px",
                    background: "var(--app-input-bg)",
                    borderRadius: 6,
                    border: "1px solid var(--app-border)",
                  }}
                >
                  Add the Aikido source to the canvas first to enable sync.
                </div>
              )}
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 16,
                    flexWrap: "wrap",
                  }}
                >
                  <button
                    onClick={handleSync}
                    disabled={syncing || sourceId == null}
                    style={{
                      ...mono,
                      padding: "8px 16px",
                      background:
                        syncing || sourceId == null
                          ? "var(--app-border)"
                          : "var(--app-accent)",
                      border: "none",
                      borderRadius: 6,
                      color: "var(--app-fg)",
                      cursor:
                        syncing || sourceId == null ? "not-allowed" : "pointer",
                      fontSize: 11,
                      fontWeight: 600,
                      opacity: syncing || sourceId == null ? 0.6 : 1,
                    }}
                  >
                    {syncing ? "Syncing…" : "Sync"}
                  </button>
                  <button
                    onClick={handleImportTeams}
                    disabled={importingTeams || sourceId == null}
                    title="Create one loadout per Aikido team, from the repos and containers that team owns"
                    style={{
                      ...mono,
                      padding: "8px 16px",
                      background: "none",
                      border: "1px solid var(--app-border)",
                      borderRadius: 6,
                      color: "var(--app-fg)",
                      cursor:
                        importingTeams || sourceId == null
                          ? "not-allowed"
                          : "pointer",
                      fontSize: 11,
                      fontWeight: 600,
                      opacity: importingTeams || sourceId == null ? 0.6 : 1,
                    }}
                  >
                    {importingTeams
                      ? "Importing teams…"
                      : "Import teams as loadouts"}
                  </button>
                  {lastSyncedAt && (
                    <span
                      style={{
                        ...sans,
                        fontSize: 11,
                        color: "var(--app-muted)",
                      }}
                    >
                      Last synced: {new Date(lastSyncedAt).toLocaleString()}
                    </span>
                  )}
                </div>
                {syncing && (
                  <>
                    {syncStep ? (
                      <div style={{ width: "100%", maxWidth: 280 }}>
                        <div
                          className="sync-progress-bar"
                          style={{ marginBottom: 6 }}
                        >
                          <div
                            className="sync-progress-bar-indicator"
                            style={{
                              width: `${
                                (syncStep.step / syncStep.total) * 100
                              }%`,
                              animation: "none",
                            }}
                          />
                        </div>
                        <span
                          style={{
                            ...sans,
                            fontSize: 11,
                            color: "var(--app-muted)",
                          }}
                        >
                          {syncStep.step}/{syncStep.total} {syncStep.label}
                        </span>
                      </div>
                    ) : (
                      <div
                        className="sync-progress-bar"
                        style={{ width: "100%", maxWidth: 280 }}
                      >
                        <div className="sync-progress-bar-indicator" />
                      </div>
                    )}
                    {syncResult && !syncStep && (
                      <span
                        style={{
                          ...sans,
                          fontSize: 11,
                          color: "var(--app-muted)",
                        }}
                      >
                        {syncResult}
                      </span>
                    )}
                  </>
                )}
                {!syncing && syncResult && (
                  <span
                    style={{
                      ...sans,
                      fontSize: 11,
                      color: "var(--app-success)",
                    }}
                  >
                    {syncResult}
                  </span>
                )}
                {!syncing && syncError && (
                  <span
                    style={{
                      ...sans,
                      fontSize: 11,
                      color: "var(--app-danger)",
                    }}
                  >
                    {syncError}
                  </span>
                )}
                {!importingTeams && teamImportResult && (
                  <span
                    role="status"
                    style={{
                      ...sans,
                      fontSize: 11,
                      color: teamImportResult.endsWith("failed.")
                        ? "var(--app-danger)"
                        : "var(--app-muted)",
                    }}
                  >
                    {teamImportResult}
                  </span>
                )}
              </div>
            </div>
          )}
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 8,
              marginTop: 8,
            }}
          >
            <span style={{ ...mono, fontSize: 10, color: "var(--app-muted)" }}>
              Webhook URL
            </span>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                flexWrap: "wrap",
              }}
            >
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
                  background: copied
                    ? "var(--app-success)"
                    : "var(--app-border)",
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

        <div
          style={{
            ...sans,
            fontSize: 10,
            color: "var(--app-muted)",
            marginTop: 20,
            paddingTop: 16,
            borderTop: "1px solid var(--app-border)",
          }}
        >
          <strong style={{ color: "var(--app-muted)" }}>
            Supported events:
          </strong>{" "}
          issue.created, issue.updated, issue.closed
        </div>

        <div style={{ marginTop: 12 }}>
          <a
            href="https://developers.aikido.dev"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              ...mono,
              fontSize: 10,
              color: "var(--app-accent)",
              textDecoration: "none",
            }}
          >
            Aikido API docs →
          </a>
        </div>
      </div>
    </div>
  );
}
