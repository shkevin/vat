"use client";

import { useCallback, useRef, useState } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { useVATData } from "@/contexts/VATDataContext";
import { bulkDeleteAssets } from "@/lib/api";
import type { Asset } from "@/types/index";
import { ConfirmBulkDeleteModal } from "./ConfirmBulkDeleteModal";
import { LoadoutPickerPopover } from "./LoadoutPickerPopover";

interface AssetActionBarProps {
  selectedAssets: Asset[];
  onDeselect: () => void;
}

const SNAPSHOT_KEY = "vat:lastFindingsSnapshot:v2";

export function AssetActionBar({
  selectedAssets,
  onDeselect,
}: AssetActionBarProps) {
  const { token, user } = useAuth();
  // Derive admin status from the user object directly — the AuthContext's
  // `isAdmin` is only populated by AccessSettingsPage when that page runs,
  // so it stays null on a normal session and the Delete control would
  // never render. user.role === "admin" is the canonical check used
  // throughout the rest of the app (VAT.tsx, useVulnFeeds.ts).
  const isAdmin = user?.role === "admin";
  const auth = { token: token ?? undefined, userEmail: user?.email ?? undefined };
  const { refetch } = useVATData();

  const addBtnRef = useRef<HTMLButtonElement>(null);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [pickerAnchor, setPickerAnchor] = useState<DOMRect | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [transientMsg, setTransientMsg] = useState<string | null>(null);

  const count = selectedAssets.length;
  const selectedAssetIds = selectedAssets.map((a) => a.id);

  const handleOpenPicker = useCallback(() => {
    if (!addBtnRef.current) return;
    setPickerAnchor(addBtnRef.current.getBoundingClientRect());
    setPickerOpen(true);
  }, []);

  const handlePickerSaved = useCallback(() => {
    setPickerOpen(false);
    setTransientMsg(`Added ${count} to loadout`);
    setTimeout(() => setTransientMsg(null), 2200);
    onDeselect();
  }, [count, onDeselect]);

  const handleConfirmDelete = useCallback(async () => {
    const result = await bulkDeleteAssets(selectedAssetIds, auth);
    try {
      window.localStorage.removeItem(SNAPSHOT_KEY);
    } catch {
      // ignore
    }
    await refetch();
    setConfirmOpen(false);
    const failed = result.failed + result.not_found;
    setTransientMsg(
      failed > 0
        ? `Deleted ${result.deleted}/${result.requested} (${failed} skipped)`
        : `Deleted ${result.deleted} asset${result.deleted === 1 ? "" : "s"}`,
    );
    setTimeout(() => setTransientMsg(null), 3500);
    onDeselect();
  }, [auth, refetch, selectedAssetIds, onDeselect]);

  const handleExportCsv = useCallback(() => {
    const rows = [
      [
        "asset_id",
        "type",
        "tag",
        "open_findings",
        "in_review",
        "verified_pct",
        "ora_pct",
        "worst_severity",
      ].join(","),
      ...selectedAssets.map((a) => {
        const cells = [
          a.id,
          (a.type ?? "").toString(),
          (a.tag ?? "").toString(),
          String(a.openCount ?? 0),
          String(a.inReviewCount ?? 0),
          String(a.verifiedPct ?? 0),
          String(a.oraPct ?? 0),
          (a.worstSeverity ?? "").toString(),
        ].map((v) =>
          /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v,
        );
        return cells.join(",");
      }),
    ];
    const blob = new Blob([rows.join("\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `vat-assets-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setTransientMsg(`Exported ${count} asset${count === 1 ? "" : "s"}`);
    setTimeout(() => setTransientMsg(null), 2200);
  }, [selectedAssets, count]);

  if (count === 0) return null;

  // Pill action bar — uses the app's --ui-* theme tokens so it tracks the
  // active theme (light / dark / variants) the same way the rest of the
  // surface does, instead of hardcoded fallbacks that flashed wrong on
  // non-default themes.
  const pillBtnBase: React.CSSProperties = {
    padding: "6px 14px",
    borderRadius: 999,
    fontSize: 13,
    fontWeight: 600,
    cursor: "pointer",
    transition: "background var(--motion-fast, 150ms) ease, color var(--motion-fast, 150ms) ease",
    display: "inline-flex",
    alignItems: "center",
    gap: 6,
    whiteSpace: "nowrap",
  };

  return (
    <>
      <div
        role="region"
        aria-label="Bulk asset actions"
        style={{
          position: "fixed",
          left: "50%",
          bottom: 24,
          transform: "translateX(-50%)",
          minWidth: 480,
          maxWidth: "calc(100vw - 32px)",
          background: "var(--ui-surface-1)",
          color: "var(--ui-text-primary)",
          border: "1px solid var(--ui-border)",
          borderRadius: 999,
          boxShadow: "0 12px 32px color-mix(in srgb, var(--ui-text-primary) 28%, transparent)",
          padding: "8px 8px 8px 16px",
          display: "flex",
          alignItems: "center",
          gap: 12,
          zIndex: 900,
          fontSize: 13,
        }}
      >
        {/* Selection indicator + clear */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            paddingRight: 12,
            borderRight: "1px solid var(--ui-border-subtle)",
            color: "var(--ui-text-primary)",
          }}
        >
          <strong>{count} selected</strong>
          <button
            type="button"
            onClick={onDeselect}
            aria-label="Clear selection"
            title="Clear selection (Esc)"
            style={{
              background: "transparent",
              border: "none",
              cursor: "pointer",
              padding: "2px 6px",
              fontSize: 16,
              color: "var(--ui-text-muted)",
              borderRadius: 4,
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </div>

        {/* Primary action — accent-tinted pill matching Btn primary variant */}
        <button
          ref={addBtnRef}
          type="button"
          onClick={handleOpenPicker}
          style={{
            ...pillBtnBase,
            background:
              "color-mix(in srgb, var(--ui-accent) 24%, transparent)",
            color: "var(--ui-accent)",
            border:
              "1px solid color-mix(in srgb, var(--ui-accent) 45%, transparent)",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background =
              "color-mix(in srgb, var(--ui-accent) 34%, transparent)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background =
              "color-mix(in srgb, var(--ui-accent) 24%, transparent)";
          }}
        >
          + Add to loadout
        </button>

        {/* Secondary action — ghost pill */}
        <button
          type="button"
          onClick={handleExportCsv}
          style={{
            ...pillBtnBase,
            background: "transparent",
            color: "var(--ui-text-secondary)",
            border: "1px solid var(--ui-border-subtle)",
            fontWeight: 500,
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background =
              "color-mix(in srgb, var(--ui-surface-2) 80%, transparent)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = "transparent";
          }}
        >
          Export CSV
        </button>

        {/* Destructive group: separated and right-aligned */}
        {isAdmin && (
          <div
            style={{
              marginLeft: "auto",
              paddingLeft: 12,
              borderLeft: "1px solid var(--ui-border-subtle)",
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <button
              type="button"
              onClick={() => setConfirmOpen(true)}
              style={{
                ...pillBtnBase,
                background:
                  "color-mix(in srgb, var(--ui-danger) 22%, transparent)",
                color: "var(--ui-danger)",
                border:
                  "1px solid color-mix(in srgb, var(--ui-danger) 45%, transparent)",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background =
                  "color-mix(in srgb, var(--ui-danger) 30%, transparent)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background =
                  "color-mix(in srgb, var(--ui-danger) 22%, transparent)";
              }}
            >
              Delete…
            </button>
          </div>
        )}

        {transientMsg && (
          <span
            style={{
              fontSize: 12,
              color: "var(--ui-text-muted)",
              marginLeft: 8,
            }}
          >
            {transientMsg}
          </span>
        )}
      </div>

      {pickerOpen && (
        <LoadoutPickerPopover
          anchorRect={pickerAnchor}
          selectedAssetIds={selectedAssetIds}
          onClose={() => setPickerOpen(false)}
          onSaved={handlePickerSaved}
        />
      )}
      {confirmOpen && (
        <ConfirmBulkDeleteModal
          assets={selectedAssets}
          onCancel={() => setConfirmOpen(false)}
          onConfirm={handleConfirmDelete}
        />
      )}
    </>
  );
}
