"use client";

import { useState } from "react";
import { Btn, Field } from "@/components/atoms";

interface BulkBarProps {
  count: number;
  onAction: (status: string, justification: string) => void | Promise<void>;
  onDeselect: () => void;
  /** Called when bulk action fails. If not provided, error is shown inline. */
  onError?: (message: string) => void;
}

const BULK_STATUSES = ["False Positive", "Suppressed", "Duplicate", "Resolved"] as const;

export function BulkBar({ count, onAction, onDeselect, onError }: BulkBarProps) {
  const [justification, setJustification] = useState("");
  const [status, setStatus] = useState<string>("False Positive");
  const [open, setOpen] = useState(false);
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleApply = async () => {
    setApplying(true);
    setError(null);
    try {
      await onAction(status, justification);
      setOpen(false);
      setJustification("");
    } catch {
      const msg = "Bulk update failed";
      if (onError) onError(msg);
      else setError(msg);
    } finally {
      setApplying(false);
    }
  };

  return (
    <div
      style={{
        background: "#0a1830",
        border: "1px solid #1d4ed8",
        borderRadius: 6,
        padding: "12px 16px",
        marginBottom: 10,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          flexWrap: "wrap",
        }}
      >
        <span
          style={{
            fontFamily: "'JetBrains Mono',monospace",
            fontSize: 11,
            fontWeight: 700,
            color: "#38bdf8",
          }}
        >
          {count} selected
        </span>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {BULK_STATUSES.map((s) => (
            <Btn
              key={s}
              size="sm"
              variant={status === s ? "primary" : "ghost"}
              onClick={() => {
                setStatus(s);
                setOpen(true);
              }}
            >
              {s}
            </Btn>
          ))}
        </div>
        <div style={{ flex: 1 }} />
        <Btn size="sm" variant="ghost" onClick={onDeselect}>
          Deselect all
        </Btn>
      </div>
      {open && (
        <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 8 }}>
          {error && (
            <div style={{ color: "var(--app-warning)", fontSize: 12 }}>
              {error}
            </div>
          )}
          <Field
            label={`Shared justification for ${count} findings → "${status}"`}
            value={justification}
            onChange={(v) => { setJustification(v); setError(null); }}
            rows={3}
            placeholder="e.g. All flagged assets share the same runtime condition."
          />
          <div style={{ display: "flex", gap: 7 }}>
            <Btn onClick={handleApply} disabled={!justification.trim() || applying}>
              {applying ? "Applying…" : `Apply to ${count}`}
            </Btn>
            <Btn variant="ghost" onClick={() => setOpen(false)}>
              Cancel
            </Btn>
          </div>
        </div>
      )}
    </div>
  );
}
