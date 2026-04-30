"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { Asset } from "@/types/index";

interface ConfirmBulkDeleteModalProps {
  assets: Asset[];
  onCancel: () => void;
  onConfirm: () => void | Promise<void>;
}

const TYPED_CONFIRM_THRESHOLD = 5;

export function ConfirmBulkDeleteModal({
  assets,
  onCancel,
  onConfirm,
}: ConfirmBulkDeleteModalProps) {
  const requiresTypedConfirm = assets.length > TYPED_CONFIRM_THRESHOLD;
  const requiredText = `delete ${assets.length} assets`;
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  const findingTotal = useMemo(
    () =>
      assets.reduce((sum, a) => sum + (a.findings?.length ?? 0), 0),
    [assets],
  );

  useEffect(() => {
    cancelRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onCancel]);

  const canConfirm =
    !busy && (requiresTypedConfirm ? typed.trim() === requiredText : true);

  const handleConfirm = async () => {
    if (!canConfirm) return;
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed");
      setBusy(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="bulk-delete-title"
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.5)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 2000,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div
        style={{
          background: "var(--app-surface, #fff)",
          borderRadius: 8,
          padding: 20,
          width: "min(560px, 92vw)",
          maxHeight: "80vh",
          display: "flex",
          flexDirection: "column",
          boxShadow: "0 16px 48px rgba(0,0,0,0.28)",
        }}
      >
        <h2
          id="bulk-delete-title"
          style={{
            margin: "0 0 8px",
            fontSize: 16,
            fontWeight: 700,
            color: "var(--app-fg)",
          }}
        >
          Delete {assets.length} asset{assets.length === 1 ? "" : "s"}?
        </h2>
        <p
          style={{
            margin: "0 0 12px",
            fontSize: 13,
            color: "var(--app-muted, #555)",
          }}
        >
          This will also delete <strong>{findingTotal} finding{findingTotal === 1 ? "" : "s"}</strong>{" "}
          attached to {assets.length === 1 ? "this asset" : "these assets"}. This
          action cannot be undone.
        </p>

        <ul
          style={{
            listStyle: "none",
            margin: 0,
            padding: "8px 12px",
            border: "1px solid var(--app-border-subtle, #eee)",
            borderRadius: 4,
            background: "var(--app-input-bg, #fafafa)",
            overflowY: "auto",
            maxHeight: 220,
            fontSize: 12,
          }}
        >
          {assets.map((a) => (
            <li
              key={a.id}
              style={{
                display: "flex",
                justifyContent: "space-between",
                gap: 12,
                padding: "2px 0",
              }}
            >
              <span style={{ fontFamily: "var(--font-mono, monospace)" }}>
                {a.id}
              </span>
              <span style={{ color: "var(--app-muted, #888)" }}>
                {a.findings?.length ?? 0} finding
                {(a.findings?.length ?? 0) === 1 ? "" : "s"}
              </span>
            </li>
          ))}
        </ul>

        {requiresTypedConfirm && (
          <div style={{ marginTop: 12 }}>
            <label
              style={{
                display: "block",
                fontSize: 12,
                color: "var(--app-muted)",
                marginBottom: 4,
              }}
            >
              Type <code>{requiredText}</code> to confirm:
            </label>
            <input
              type="text"
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              disabled={busy}
              style={{
                width: "100%",
                padding: "6px 8px",
                border: "1px solid var(--app-border, #ccc)",
                borderRadius: 4,
                fontSize: 13,
                fontFamily: "var(--font-mono, monospace)",
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" && canConfirm) handleConfirm();
              }}
            />
          </div>
        )}

        {error && (
          <div
            style={{
              marginTop: 8,
              padding: "6px 8px",
              fontSize: 12,
              color: "var(--app-error, #b00020)",
              background: "rgba(176,0,32,0.06)",
              borderRadius: 4,
            }}
          >
            {error}
          </div>
        )}

        <div
          style={{
            marginTop: 16,
            display: "flex",
            gap: 8,
            justifyContent: "flex-end",
          }}
        >
          <button
            ref={cancelRef}
            type="button"
            onClick={onCancel}
            disabled={busy}
            style={{
              padding: "8px 16px",
              border: "1px solid var(--app-border, #ccc)",
              borderRadius: 4,
              background: "transparent",
              color: "inherit",
              fontSize: 13,
              cursor: "pointer",
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleConfirm}
            disabled={!canConfirm}
            style={{
              padding: "8px 16px",
              border: "none",
              borderRadius: 4,
              background: canConfirm ? "var(--app-danger, #b00020)" : "#ccc",
              color: "#fff",
              fontSize: 13,
              fontWeight: 600,
              cursor: canConfirm ? "pointer" : "not-allowed",
            }}
          >
            {busy
              ? "Deleting…"
              : `Delete ${assets.length} asset${assets.length === 1 ? "" : "s"}`}
          </button>
        </div>
      </div>
    </div>
  );
}
