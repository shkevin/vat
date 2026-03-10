"use client";

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
        <span style={{ ...mono, fontSize: 11, color: "#475569" }}>
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
          gridTemplateColumns: "26px 4px 32px 130px 1fr 160px 60px 100px 90px 80px",
          gap: 8,
          padding: HEADER_PADDING[density],
          background: "#060c18",
          borderRadius: "4px 4px 0 0",
          border: "1px solid #0d1a2e",
          borderBottom: "none",
        }}
      >
        {["", "", "", "CVE / ID", "Title / Component", "Status", "Tracked", "Severity", "Source", "SLA"].map(
          (h, i) => (
            <span
              key={i}
              style={{
                ...mono,
                fontSize: 9,
                fontWeight: 700,
                letterSpacing: "0.1em",
                color: "#1e3a5f",
                textTransform: "uppercase",
              }}
            >
              {h}
            </span>
          )
        )}
      </div>
      <div
        style={{
          border: "1px solid #0d1a2e",
          borderRadius: "0 0 4px 4px",
          overflow: "hidden",
        }}
      >
        {displayed.length === 0 ? (
          <div
            style={{
              ...sans,
              fontSize: 12,
              color: "#1e3a5f",
              padding: 40,
              textAlign: "center",
            }}
          >
            No findings match current filters.
          </div>
        ) : (
          displayed.map((f) => (
            <FindingRow
              key={f.id}
              finding={f}
              sources={sources}
              selected={selected?.id === f.id}
              checked={checked.has(f.id)}
              onCheck={(v) => onCheck(f.id, v)}
              onClick={() => onSelect(f)}
            />
          ))
        )}
      </div>
    </div>
  );
}
