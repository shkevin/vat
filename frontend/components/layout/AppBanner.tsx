"use client";

import { useState, useCallback } from "react";
import { Bell, Download, Filter, Timer } from "lucide-react";
import { mono, sans } from "@/lib/styles";
import { downloadExportBundle } from "@/lib/api";

function isLogoImage(logo: string): boolean {
  return logo.startsWith("/") || logo.includes(".svg") || logo.includes(".png");
}
import { useAuth } from "@/contexts/AuthContext";
import { UserProfileMenu } from "@/components/layout/UserProfileMenu";
import type { AppConfig } from "@/config/app";

interface TabConfig {
  id: string;
  label: string;
  badge?: number;
  warn?: boolean;
}

interface AppBannerProps {
  config: AppConfig["banner"];
  tabs: TabConfig[];
  currentView: string;
  onViewChange: (id: string) => void;
  searchValue: string;
  onSearchChange: (v: string) => void;
  alertCount: number;
  /** PRD §5.5.2: Waivers expiring within 30 days — distinct badge */
  waiverExpiringCount?: number;
  /** When true, hides the search bar (e.g. when shown in main content). */
  hideSearch?: boolean;
  /** When true, shows a filter button (for mobile). Callback when clicked. */
  showFilterButton?: boolean;
  onFilterClick?: () => void;
}

export function AppBanner({
  config,
  tabs,
  currentView,
  onViewChange,
  searchValue,
  onSearchChange,
  alertCount,
  waiverExpiringCount = 0,
  hideSearch,
  showFilterButton,
  onFilterClick,
}: AppBannerProps) {
  const { user, token } = useAuth();
  const [exportLoading, setExportLoading] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const handleExport = useCallback(async () => {
    if (!user) return;
    setExportLoading(true);
    setExportError(null);
    try {
      await downloadExportBundle({ token, userEmail: user.email });
    } catch (e) {
      setExportError(e instanceof Error ? e.message : "Export failed");
    } finally {
      setExportLoading(false);
    }
  }, [user, token]);

  return (
    <div
      className="app-banner-modern"
      style={{
        padding: "0 20px",
        display: "flex",
        alignItems: "center",
        minHeight: 56,
        gap: 24,
        flexWrap: "wrap",
      }}
    >
      <button
        className="app-banner-brand"
        type="button"
        onClick={() => onViewChange("findings")}
        aria-label="Go to findings"
        style={{
          display: "flex",
          alignItems: "center",
          gap: 2,
          marginRight: 8,
          padding: 0,
          border: "none",
          background: "none",
          cursor: "pointer",
          textDecoration: "none",
          color: "inherit",
          font: "inherit",
        }}
      >
        {config.companyName && (
          <span
            className="app-banner-company"
            style={{
              ...mono,
              fontSize: 14,
              fontWeight: 700,
              color: "var(--app-accent-emerald)",
              letterSpacing: "0.08em",
            }}
          >
            {config.companyName}
          </span>
        )}
        {isLogoImage(config.logo) ? (
          <img
            className="app-banner-logo"
            src={config.logo}
            alt="VAT"
            style={{
              height: 52,
              width: "auto",
              display: "block",
              marginLeft: 2,
            }}
          />
        ) : (
          <span
            className="app-banner-logo-text"
            style={{
              ...mono,
              fontSize: 18,
              fontWeight: 700,
              color: "var(--app-accent-emerald)",
            }}
          >
            {config.logo}
          </span>
        )}
      </button>

      <nav className="app-banner-tabs">
        {tabs.map(({ id, label, badge = 0, warn }) => {
          const active = currentView === id;
          return (
            <button
              key={id}
              onClick={() => onViewChange(id)}
              className="app-banner-tab"
              data-active={active ? "true" : "false"}
              style={{
                ...sans,
                background: "none",
                border: "1px solid transparent",
                color: active
                  ? "var(--app-accent-emerald)"
                  : "var(--app-muted)",
                padding: "8px 14px",
                borderRadius: 4,
                cursor: "pointer",
                fontSize: 13,
                fontWeight: active ? 600 : 400,
                display: "flex",
                alignItems: "center",
                gap: 6,
              }}
            >
              {label}
              {badge > 0 && (
                <span
                  className="app-banner-tab-badge"
                  style={{
                    background: warn
                      ? "var(--app-danger)"
                      : "var(--app-accent-emerald)",
                    color: "#fff",
                    fontSize: 11,
                    fontWeight: 700,
                    padding: "1px 5px",
                    borderRadius: 10,
                  }}
                >
                  {badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div
        className="app-banner-actions"
        style={{
          marginLeft: "auto",
          display: "flex",
          alignItems: "center",
          gap: 12,
        }}
      >
        {showFilterButton && (
          <button
            className="app-banner-filter-btn"
            type="button"
            onClick={onFilterClick}
            aria-label="Open filters"
            style={{
              background: "var(--app-input-bg)",
              border: "1px solid var(--app-border)",
              borderRadius: 6,
              padding: "6px 10px",
              color: "var(--app-muted)",
              fontSize: 14,
              cursor: "pointer",
            }}
          >
            <Filter size={14} /> Filters
          </button>
        )}
        {!hideSearch && (
          <input
            type="search"
            value={searchValue}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder={config.searchPlaceholder}
            className="modern-input"
            style={{
              borderRadius: 6,
              padding: "6px 12px",
              width: 220,
              color: "var(--app-fg)",
              fontSize: 12,
              ...sans,
            }}
          />
        )}
        {waiverExpiringCount > 0 && (
          <button
            onClick={() => onViewChange("dash")}
            title="Waivers expiring within 30 days"
            className="modern-chip app-banner-waiver-pill"
            style={{
              ...sans,
              background: "var(--app-warning)",
              border: "none",
              borderRadius: 4,
              padding: "4px 10px",
              color: "var(--app-fg)",
              fontSize: 12,
              fontWeight: 700,
              cursor: "pointer",
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <Timer size={14} /> {waiverExpiringCount} waiver
            {waiverExpiringCount !== 1 ? "s" : ""} expiring
          </button>
        )}
        {alertCount > 0 && (
          <button
            onClick={() => onViewChange("dash")}
            className="modern-chip app-banner-alert-pill"
            style={{
              ...sans,
              background: "var(--app-danger)",
              border: "none",
              borderRadius: 4,
              padding: "4px 10px",
              color: "#fff",
              fontSize: 12,
              fontWeight: 700,
              cursor: "pointer",
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <Bell size={14} /> {alertCount}
          </button>
        )}
        {user && (
          <button
            className="app-banner-export-btn"
            type="button"
            onClick={handleExport}
            disabled={exportLoading}
            title="Download full export (assets, findings, SBOM, Executive Summary)"
            style={{
              ...sans,
              display: "flex",
              alignItems: "center",
              gap: 6,
              background: "var(--app-input-bg)",
              border: "1px solid var(--app-border)",
              borderRadius: 6,
              padding: "6px 12px",
              color: "var(--app-fg)",
              fontSize: 13,
              cursor: exportLoading ? "not-allowed" : "pointer",
              opacity: exportLoading ? 0.7 : 1,
            }}
          >
            <Download size={16} />
            {exportLoading ? "Exporting…" : "Export"}
          </button>
        )}
        {exportError && (
          <span
            style={{
              fontSize: 11,
              color: "var(--app-danger)",
              maxWidth: 320,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={exportError}
          >
            {exportError}
          </span>
        )}
        {config.envLabel && (
          <select
            className="app-banner-env-select"
            style={{
              background: "var(--app-input-bg)",
              border: "1px solid var(--app-border)",
              borderRadius: 4,
              padding: "4px 8px",
              color: "var(--app-muted)",
              fontSize: 11,
              ...mono,
            }}
          >
            <option>{config.envLabel}</option>
          </select>
        )}
        {user && <UserProfileMenu onViewChange={onViewChange} />}
      </div>
    </div>
  );
}
