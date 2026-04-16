"use client";

import { useEffect, useMemo, useState } from "react";
import { FindingRow } from "./FindingRow";
import { BulkBar } from "./BulkBar";
import { useUserPreferences } from "@/contexts/UserPreferencesContext";
import { mono, sans } from "@/lib/styles";

const HEADER_PADDING = {
  compact: "4px 14px",
  default: "6px 14px",
  comfortable: "10px 14px",
} as const;
import type { Finding } from "@/types";
import type { Source } from "@/types";

interface FindingsTableProps {
  displayed: Finding[];
  findings: Finding[];
  sources: Source[];
  selected: Finding | null;
  checked: Set<string>;
  showArchived: boolean;
  archivedCount: number;
  total: number;
  onSelect: (f: Finding) => void;
  onCheck: (id: string, val: boolean) => void;
  onBulkAction: (status: string, justification: string) => void;
  onDeselectAll: () => void;
}

export function FindingsTable({
  displayed,
  sources,
  selected,
  checked,
  showArchived,
  archivedCount,
  total,
  onSelect,
  onCheck,
  onBulkAction,
  onDeselectAll,
}: FindingsTableProps) {
  const { preferences } = useUserPreferences();
  const density = preferences.tableDensity ?? "default";
  const [visibleCount, setVisibleCount] = useState(250);
  useEffect(() => {
    setVisibleCount(250);
  }, [displayed.length, density]);
  const visibleRows = useMemo(
    () => displayed.slice(0, visibleCount),
    [displayed, visibleCount],
  );
  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 12,
        }}
      >
        <span style={{ ...mono, fontSize: 11, color: "var(--app-muted)" }}>
          {displayed.length} finding{displayed.length !== 1 ? "s" : ""}
          {showArchived ? ` (${archivedCount} archived)` : ` of ${total}`}
        </span>
      </div>

      {checked.size > 0 && (
        <BulkBar
          count={checked.size}
          onAction={onBulkAction}
          onDeselect={onDeselectAll}
        />
      )}

      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "26px 4px 32px 130px 1fr 160px 60px 100px 90px 80px",
          gap: 8,
          padding: HEADER_PADDING[density],
          background: "var(--app-pane-header-bg)",
          borderRadius: "4px 4px 0 0",
          border: "1px solid var(--app-border-subtle)",
          borderBottom: "none",
        }}
      >
        {[
          "",
          "",
          "",
          "CVE / ID",
          "Title / Component",
          "Status",
          "Tracked",
          "Severity",
          "Source",
          "SLA",
        ].map((h, i) => (
          <span
            key={i}
            style={{
              ...mono,
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: "0.1em",
              color: "var(--app-fg-group)",
              textTransform: "uppercase",
            }}
          >
            {h}
          </span>
        ))}
      </div>
      <div
        style={{
          border: "1px solid var(--app-border-subtle)",
          borderRadius: "0 0 4px 4px",
          overflow: "auto",
          maxHeight: "62vh",
        }}
        onScroll={(event) => {
          const target = event.currentTarget;
          if (target.scrollTop + target.clientHeight >= target.scrollHeight - 120) {
            setVisibleCount((prev) => Math.min(prev + 200, displayed.length));
          }
        }}
      >
        {displayed.length === 0 ? (
          <div
            style={{
              ...sans,
              fontSize: 12,
              color: "var(--app-muted)",
              padding: 40,
              textAlign: "center",
            }}
          >
            No findings match current filters.
          </div>
        ) : (
          visibleRows.map((f) => (
            <FindingRow
              key={f.id}
              finding={f}
              sources={sources}
              density={density}
              selected={selected?.id === f.id}
              checked={checked.has(f.id)}
              onCheck={(v) => onCheck(f.id, v)}
              onClick={() => onSelect(f)}
            />
          ))
        )}
        {displayed.length > visibleRows.length && (
          <div
            style={{
              ...mono,
              fontSize: 10,
              color: "var(--app-muted)",
              padding: "8px 14px",
              textAlign: "center",
            }}
          >
            Showing {visibleRows.length} of {displayed.length} findings. Scroll to
            load more.
          </div>
        )}
      </div>
    </div>
  );
}
