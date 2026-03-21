"use client";

import { useCallback, useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { mono, sans } from "@/lib/styles";
import { useAuth } from "@/contexts/AuthContext";
import { useTheme } from "@/contexts/ThemeContext";
import { useUserPreferences } from "@/contexts/UserPreferencesContext";
import { useVATData } from "@/contexts/VATDataContext";
import { REPORT_THEMES } from "@/lib/report/report-engine";
import {
  loadUserSettingsSummary,
  type UserPreferences,
  type UserSettingsSummary,
} from "@/lib/userSettings";

interface UserPreferencesPaneProps {
  open: boolean;
  onClose: () => void;
  onPreferencesChange?: (prefs: UserPreferences) => void;
  onNavigateToReport?: () => void;
  onNavigateToFindings?: () => void;
}

export function UserPreferencesPane({
  open,
  onClose,
  onPreferencesChange,
  onNavigateToReport,
  onNavigateToFindings,
}: UserPreferencesPaneProps) {
  const { user, setUser } = useAuth();
  const { themeId, setThemeId } = useTheme();
  const { setPreferences } = useUserPreferences();
  const { favoriteAssetIds } = useVATData();
  const [summary, setSummary] = useState<UserSettingsSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [prefs, setPrefs] = useState<UserPreferences | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const s = await loadUserSettingsSummary();
      setSummary(s);
      setPrefs(s.preferences);
    } catch {
      setSummary(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) refresh();
  }, [open, refresh]);

  const updatePref = useCallback(
    (updates: Partial<UserPreferences>) => {
      if (!prefs) return;
      const next = { ...prefs, ...updates };
      setPrefs(next);
      setPreferences(next);
      onPreferencesChange?.(next);
      setSummary((s) => (s ? { ...s, preferences: next } : null));
    },
    [prefs, setPreferences, onPreferencesChange],
  );

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const content = (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="preferences-title"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 9999,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 24,
      }}
    >
      {/* Backdrop */}
      <div
        role="presentation"
        onClick={onClose}
        style={{
          position: "absolute",
          inset: 0,
          background: "rgba(0,0,0,0.6)",
          cursor: "pointer",
        }}
      />

      {/* Centered panel */}
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          position: "relative",
          width: "100%",
          maxWidth: 480,
          maxHeight: "90vh",
          overflow: "auto",
          background: "var(--app-input-bg)",
          border: "1px solid var(--app-border)",
          borderRadius: 12,
          boxShadow: "0 25px 50px -12px rgba(0,0,0,0.5)",
        }}
      >
        {/* Header */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "16px 20px",
            borderBottom: "1px solid var(--app-border)",
          }}
        >
          <h2
            id="preferences-title"
            style={{
              ...mono,
              fontSize: 16,
              fontWeight: 600,
              color: "var(--app-fg)",
              margin: 0,
            }}
          >
            Preferences
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            style={{
              background: "none",
              border: "none",
              color: "var(--app-muted)",
              fontSize: 20,
              cursor: "pointer",
              padding: 4,
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </div>

        <div style={{ padding: 20 }}>
          {/* User info */}
          {user && (
            <section style={{ marginBottom: 24 }}>
              <span
                style={{
                  ...sans,
                  fontSize: 11,
                  color: "#64748b",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                }}
              >
                Signed in as
              </span>
              <div
                style={{
                  ...mono,
                  fontSize: 14,
                  color: "var(--app-fg)",
                  marginTop: 4,
                  wordBreak: "break-all",
                }}
              >
                {user.email}
              </div>
              {user.role && (
                <span
                  style={{
                    ...mono,
                    fontSize: 12,
                    color: "var(--app-muted)",
                    marginTop: 2,
                    display: "block",
                  }}
                >
                  {user.role}
                </span>
              )}
            </section>
          )}

          {/* Display preferences */}
          <section style={{ marginBottom: 24 }}>
            <span
              style={{
                ...sans,
                fontSize: 11,
                color: "#64748b",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
              }}
            >
              Display
            </span>
            <div
              style={{
                marginTop: 12,
                display: "flex",
                flexDirection: "column",
                gap: 12,
              }}
            >
              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  ...sans,
                  fontSize: 13,
                  color: "var(--app-muted)",
                  cursor: "pointer",
                }}
              >
                <span>Theme</span>
                <select
                  value={themeId}
                  onChange={(e) => {
                    const id = (e.target.value ||
                      REPORT_THEMES[0].id) as UserPreferences["themeId"];
                    setThemeId(id as NonNullable<UserPreferences["themeId"]>);
                    updatePref({ themeId: id });
                  }}
                  style={{
                    ...mono,
                    background: "var(--app-bg)",
                    border: "1px solid var(--app-border)",
                    borderRadius: 4,
                    padding: "6px 10px",
                    color: "var(--app-fg)",
                    fontSize: 12,
                    cursor: "pointer",
                    minWidth: 140,
                  }}
                >
                  {REPORT_THEMES.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))}
                </select>
              </label>
              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  ...sans,
                  fontSize: 13,
                  color: "var(--app-muted)",
                  cursor: "pointer",
                }}
              >
                <span>Table density</span>
                <select
                  value={prefs?.tableDensity ?? "default"}
                  onChange={(e) =>
                    updatePref({
                      tableDensity: e.target
                        .value as UserPreferences["tableDensity"],
                    })
                  }
                  style={{
                    ...mono,
                    background: "var(--app-bg)",
                    border: "1px solid var(--app-border)",
                    borderRadius: 4,
                    padding: "6px 10px",
                    color: "var(--app-fg)",
                    fontSize: 12,
                    cursor: "pointer",
                  }}
                >
                  <option value="compact">Compact</option>
                  <option value="default">Default</option>
                  <option value="comfortable">Comfortable</option>
                </select>
              </label>
            </div>
          </section>

          {/* Saved data summary */}
          <section style={{ marginBottom: 24 }}>
            <span
              style={{
                ...sans,
                fontSize: 11,
                color: "#64748b",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
              }}
            >
              Your saved data
            </span>
            <p
              style={{
                ...sans,
                fontSize: 12,
                color: "var(--app-muted)",
                marginTop: 4,
                marginBottom: 12,
              }}
            >
              Stored in this browser. Manage from the respective views.
            </p>
            {loading ? (
              <div style={{ ...mono, fontSize: 12, color: "var(--app-muted)" }}>
                Loading…
              </div>
            ) : summary ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 12,
                    padding: "10px 12px",
                    background: "var(--app-bg)",
                    borderRadius: 6,
                    border: "1px solid var(--app-border)",
                  }}
                >
                  <span
                    style={{ ...sans, fontSize: 13, color: "var(--app-fg)" }}
                  >
                    Favorites
                  </span>
                  <span
                    style={{
                      ...mono,
                      fontSize: 12,
                      color: "var(--app-muted)",
                      flex: 1,
                      textAlign: "right",
                    }}
                  >
                    {favoriteAssetIds.size} asset
                    {favoriteAssetIds.size !== 1 ? "s" : ""}
                  </span>
                  {onNavigateToFindings && (
                    <button
                      type="button"
                      onClick={() => {
                        onClose();
                        onNavigateToFindings();
                      }}
                      style={{
                        ...mono,
                        fontSize: 11,
                        padding: "4px 8px",
                        background: "transparent",
                        border: "1px solid var(--app-border)",
                        borderRadius: 4,
                        color: "var(--app-muted)",
                        cursor: "pointer",
                      }}
                    >
                      View
                    </button>
                  )}
                </div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 12,
                    padding: "10px 12px",
                    background: "var(--app-bg)",
                    borderRadius: 6,
                    border: "1px solid var(--app-border)",
                  }}
                >
                  <span
                    style={{ ...sans, fontSize: 13, color: "var(--app-fg)" }}
                  >
                    Loadouts
                  </span>
                  <span
                    style={{
                      ...mono,
                      fontSize: 12,
                      color: "var(--app-muted)",
                      flex: 1,
                      textAlign: "right",
                    }}
                  >
                    {summary.loadoutCount} loadout
                    {summary.loadoutCount !== 1 ? "s" : ""}
                  </span>
                  {onNavigateToFindings && (
                    <button
                      type="button"
                      onClick={() => {
                        onClose();
                        onNavigateToFindings();
                      }}
                      style={{
                        ...mono,
                        fontSize: 11,
                        padding: "4px 8px",
                        background: "transparent",
                        border: "1px solid var(--app-border)",
                        borderRadius: 4,
                        color: "var(--app-muted)",
                        cursor: "pointer",
                      }}
                    >
                      View
                    </button>
                  )}
                </div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 12,
                    padding: "10px 12px",
                    background: "var(--app-bg)",
                    borderRadius: 6,
                    border: "1px solid var(--app-border)",
                  }}
                >
                  <span
                    style={{ ...sans, fontSize: 13, color: "var(--app-fg)" }}
                  >
                    Report templates
                  </span>
                  <span
                    style={{
                      ...mono,
                      fontSize: 12,
                      color: "var(--app-muted)",
                      flex: 1,
                      textAlign: "right",
                    }}
                  >
                    {summary.reportPresetCount} preset
                    {summary.reportPresetCount !== 1 ? "s" : ""}
                  </span>
                  {onNavigateToReport && (
                    <button
                      type="button"
                      onClick={() => {
                        onClose();
                        onNavigateToReport();
                      }}
                      style={{
                        ...mono,
                        fontSize: 11,
                        padding: "4px 8px",
                        background: "transparent",
                        border: "1px solid var(--app-border)",
                        borderRadius: 4,
                        color: "var(--app-muted)",
                        cursor: "pointer",
                      }}
                    >
                      View
                    </button>
                  )}
                </div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 12,
                    padding: "10px 12px",
                    background: "var(--app-bg)",
                    borderRadius: 6,
                    border: "1px solid var(--app-border)",
                  }}
                >
                  <span
                    style={{ ...sans, fontSize: 13, color: "var(--app-fg)" }}
                  >
                    Saved reports
                  </span>
                  <span
                    style={{
                      ...mono,
                      fontSize: 12,
                      color: "var(--app-muted)",
                      flex: 1,
                      textAlign: "right",
                    }}
                  >
                    {summary.savedReportCount} report
                    {summary.savedReportCount !== 1 ? "s" : ""}
                  </span>
                  {onNavigateToReport && (
                    <button
                      type="button"
                      onClick={() => {
                        onClose();
                        onNavigateToReport();
                      }}
                      style={{
                        ...mono,
                        fontSize: 11,
                        padding: "4px 8px",
                        background: "transparent",
                        border: "1px solid var(--app-border)",
                        borderRadius: 4,
                        color: "var(--app-muted)",
                        cursor: "pointer",
                      }}
                    >
                      View
                    </button>
                  )}
                </div>
              </div>
            ) : null}
          </section>

          {/* Log out */}
          <div>
            <button
              type="button"
              onClick={() => {
                onClose();
                setUser(null);
              }}
              style={{
                ...mono,
                width: "100%",
                fontSize: 13,
                padding: "10px 14px",
                background: "transparent",
                border: "1px solid var(--app-border)",
                borderRadius: 6,
                color: "var(--app-muted)",
                cursor: "pointer",
                transition: "all 0.15s",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "var(--app-card-bg)";
                e.currentTarget.style.borderColor = "var(--app-border)";
                e.currentTarget.style.color = "var(--app-fg)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "transparent";
                e.currentTarget.style.borderColor = "var(--app-border)";
                e.currentTarget.style.color = "var(--app-muted)";
              }}
            >
              Log out
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  return typeof document !== "undefined"
    ? createPortal(content, document.body)
    : null;
}
