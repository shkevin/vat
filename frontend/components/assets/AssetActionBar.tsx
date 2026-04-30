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
  const { token, user, isAdmin } = useAuth();
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
          background: "var(--app-surface, #ffffff)",
          color: "var(--app-fg)",
          border: "1px solid var(--app-border, #ccc)",
          borderRadius: 999,
          boxShadow: "0 12px 32px rgba(0,0,0,0.22)",
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
            borderRight: "1px solid var(--app-border-subtle, #e5e5e5)",
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
              color: "var(--app-muted, #888)",
              borderRadius: 4,
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </div>

        {/* Primary action */}
        <button
          ref={addBtnRef}
          type="button"
          onClick={handleOpenPicker}
          style={{
            padding: "6px 14px",
            border: "none",
            borderRadius: 999,
            background: "var(--app-accent, #2563eb)",
            color: "var(--app-accent-fg, #fff)",
            fontWeight: 600,
            fontSize: 13,
            cursor: "pointer",
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
          }}
        >
          + Add to loadout
        </button>

        {/* Secondary actions */}
        <button
          type="button"
          onClick={handleExportCsv}
          style={{
            padding: "6px 12px",
            border: "1px solid var(--app-border, #ccc)",
            borderRadius: 999,
            background: "transparent",
            color: "inherit",
            fontSize: 13,
            cursor: "pointer",
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
              borderLeft: "1px solid var(--app-border-subtle, #e5e5e5)",
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <button
              type="button"
              onClick={() => setConfirmOpen(true)}
              style={{
                padding: "6px 12px",
                border: "1px solid var(--app-danger, #b00020)",
                borderRadius: 999,
                background: "transparent",
                color: "var(--app-danger, #b00020)",
                fontSize: 13,
                fontWeight: 600,
                cursor: "pointer",
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
              color: "var(--app-muted, #666)",
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
