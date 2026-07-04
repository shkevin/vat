"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { FindingRow } from "./FindingRow";
import { BulkBar } from "./BulkBar";
import { useUserPreferences } from "@/contexts/UserPreferencesContext";
import { mono, sans } from "@/lib/styles";

const HEADER_PADDING = {
  compact: "4px 14px",
  default: "6px 14px",
  comfortable: "10px 14px",
} as const;

// Estimated row height per density. Padding (top+bottom) + the 24px
// content line. Used to compute the visible window and the top/bottom
// spacer heights that preserve scrollbar accuracy. If a row ends up
// slightly taller (e.g. an unusually long tag set wraps) the window
// just renders one extra row above/below — overscan absorbs the drift.
const ROW_HEIGHT = {
  compact: 32,
  default: 40,
  comfortable: 48,
} as const;

const OVERSCAN_ROWS = 8;
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
  const rowHeight = ROW_HEIGHT[density];

  // Virtualization state. scrollTop and containerHeight together determine
  // which rows are currently in (or near) the viewport. The previous
  // implementation mounted up to `visibleCount` rows growing-only, which
  // at 10k+ findings ballooned the DOM and pinned the main thread on
  // filter changes. Now the mounted DOM never exceeds viewport+overscan.
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(0);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => setContainerHeight(el.clientHeight);
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Reset scroll position when the underlying list changes shape, so a
  // filter change doesn't leave the user scrolled past the new end.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    if (el.scrollTop !== 0) {
      el.scrollTop = 0;
      setScrollTop(0);
    }
  }, [displayed.length, density]);

  const { windowRows, topSpacer, bottomSpacer } = useMemo(() => {
    const total = displayed.length;
    if (total === 0 || containerHeight === 0) {
      return { windowRows: displayed, topSpacer: 0, bottomSpacer: 0 };
    }
    const firstIdx = Math.max(
      0,
      Math.floor(scrollTop / rowHeight) - OVERSCAN_ROWS,
    );
    const lastIdx = Math.min(
      total,
      Math.ceil((scrollTop + containerHeight) / rowHeight) + OVERSCAN_ROWS,
    );
    return {
      windowRows: displayed.slice(firstIdx, lastIdx),
      topSpacer: firstIdx * rowHeight,
      bottomSpacer: Math.max(0, (total - lastIdx) * rowHeight),
    };
  }, [displayed, scrollTop, containerHeight, rowHeight]);

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
          borderRadius: "var(--radius-md) var(--radius-md) 0 0",
          border: "1px solid var(--app-border)",
          borderBottom: "none",
          boxShadow: "var(--app-elev-shadow)",
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
        ref={containerRef}
        style={{
          border: "1px solid var(--app-border)",
          borderTop: "none",
          borderRadius: "0 0 var(--radius-md) var(--radius-md)",
          overflow: "auto",
          maxHeight: "62vh",
          boxShadow: "var(--app-elev-shadow)",
        }}
        onScroll={(event) => {
          // Single setState per scroll frame; React batches the update and
          // the windowed slice recomputes via useMemo without forcing every
          // mounted row to reconcile.
          setScrollTop(event.currentTarget.scrollTop);
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
          <>
            {topSpacer > 0 && <div style={{ height: topSpacer }} />}
            {windowRows.map((f) => (
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
            ))}
            {bottomSpacer > 0 && <div style={{ height: bottomSpacer }} />}
          </>
        )}
      </div>
    </div>
  );
}
