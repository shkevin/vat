"use client";

import React, {
  useState,
  useMemo,
  useCallback,
  useEffect,
  useRef,
} from "react";
import type { ReportContext } from "@/lib/report/report-types";
import { useTheme } from "@/contexts/ThemeContext";
import { sans } from "@/lib/styles";
import {
  createDefaultReportDefinition,
  exportPdfFromDefinition,
  exportHtmlFromDefinition,
  exportCsvFromDefinition,
  REPORT_PRESETS,
  REPORT_THEMES,
  clonePresetDefinition,
  computeReportContext,
  buildReportHtmlFromDefinition,
} from "@/lib/report/report-engine";
import { validateReportDefinition } from "@/lib/report/report-types";
import {
  getReportPersistence,
  type SavedReportMeta,
} from "@/lib/report/report-persistence";
import type {
  ReportDefinition,
  ReportFilters,
  WidgetDefinition,
  WidgetType,
  WidgetLayout,
  DateRangePreset,
} from "@/lib/report/report-types";
import {
  WIDGET_TYPE_LABELS,
  WIDGET_DEFAULT_CONFIG,
  nextLayoutRow,
  widgetLayoutForSingleColumn,
  widgetLayoutFullWidth,
  normalizeReportDefinitionLayout,
  normalizeCanvasRowLayouts,
  CANVAS_GRID_COLS,
  CANVAS_MAX_COLUMNS,
  snapColToLayout,
  snapWidthToLayout,
  gridUnitsPerColumn,
} from "@/lib/report/report-types";
import { computeRepoRiskScores } from "@/lib/report/metrics";
import type { VATDashboardData } from "@/lib/report/vatReportAdapter";
import { getAssetTypeFromAsset } from "@/lib/assetUtils";
import { buildAndDownloadExportBundle } from "@/lib/exportBundle";
import { useAuth } from "@/contexts/AuthContext";
import type { Asset, Finding } from "@/types";
import {
  ChevronDown,
  ChevronUp,
  FileSpreadsheet,
  Globe,
  Mail,
  Package,
  Printer,
  Plus,
  Trash2,
  GripVertical,
  LayoutTemplate,
  Layers,
  Settings2,
  Save,
  Bookmark,
  RotateCcw,
  ZoomIn,
  ZoomOut,
  LayoutPanelTop,
  Move,
} from "lucide-react";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/ResizablePanels";
import type { ImperativePanelHandle } from "react-resizable-panels";

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"] as const;
const WIDGET_TYPES = Object.keys(WIDGET_TYPE_LABELS) as WidgetType[];

/** Report builder asset type buckets — maps from assetUtils types for UI grouping */
type ReportAssetType = "image" | "component" | "unknown";
const ASSET_TYPE_LABELS: Record<ReportAssetType, string> = {
  image: "Image (containers)",
  component: "Component (packages)",
  unknown: "Other",
};

function getAssetTypeForReport(asset: Asset): ReportAssetType {
  const t = getAssetTypeFromAsset(asset);
  if (t === "container" || t === "repo") return "image";
  if (t === "package") return "component";
  return "unknown";
}

function AssetTypeDropdown({
  type,
  label,
  assets,
  selected,
  onToggle,
  style,
}: {
  type: ReportAssetType;
  label: string;
  assets: Asset[];
  selected: Set<string>;
  onToggle: (name: string) => void;
  style: React.CSSProperties;
}) {
  const [open, setOpen] = useState(false);
  const selectedCount = assets.filter((a) => selected.has(a.name)).length;
  const summary =
    selectedCount === 0
      ? open
        ? "Select assets…"
        : "All"
      : selectedCount === assets.length
        ? "All"
        : `${selectedCount} selected`;

  return (
    <div style={{ position: "relative" }}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        style={{
          ...style,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          width: "100%",
          textAlign: "left",
        }}
      >
        <span
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          {label}
        </span>
        <span
          style={{ ...sans, fontSize: 11, color: "var(--app-fg-secondary)" }}
        >
          {summary}
        </span>
        <ChevronDown
          size={12}
          style={{ color: "var(--app-fg-secondary)", flexShrink: 0 }}
        />
      </button>
      {open && (
        <>
          <div
            style={{ position: "fixed", inset: 0, zIndex: 40 }}
            onClick={() => setOpen(false)}
            aria-hidden
          />
          <div
            style={{
              position: "absolute",
              top: "100%",
              left: 0,
              marginTop: 4,
              minWidth: 220,
              maxHeight: 200,
              overflowY: "auto",
              ...VAT_CARD,
              zIndex: 50,
            }}
          >
            <div
              style={{
                ...sans,
                fontSize: 11,
                color: "var(--app-fg-secondary)",
                marginBottom: 8,
                paddingBottom: 4,
                borderBottom: "1px solid var(--app-border)",
              }}
            >
              Select {label.toLowerCase()}
            </div>
            {assets.map((a) => (
              <label
                key={a.name}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  cursor: "pointer",
                  padding: "6px 8px",
                  borderRadius: 4,
                  ...sans,
                  fontSize: 12,
                }}
              >
                <input
                  type="checkbox"
                  checked={selected.has(a.name)}
                  onChange={() => onToggle(a.name)}
                />
                <span style={{ color: "var(--app-fg)" }}>{a.name}</span>
                <span
                  style={{ color: "var(--app-fg-secondary)", fontSize: 11 }}
                >
                  ({a.findings.length})
                </span>
              </label>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
const SAVED_PRESETS_STORAGE_KEY = "vat:report-saved-presets";
const CANVAS_GRID_ROW_HEIGHT = 72;
const CANVAS_GRID_GAP = 8;
const CANVAS_GRID_ROW_STEP = CANVAS_GRID_ROW_HEIGHT + CANVAS_GRID_GAP;
const PREVIEW_PAGE_WIDTH = 794;
const PREVIEW_PAGE_HEIGHT = 1123;

const VAT_CARD = {
  background: "var(--app-card-bg)",
  border: "1px solid var(--app-border)",
  borderRadius: 6,
  padding: 14,
};
const VAT_INPUT = {
  ...sans,
  background: "var(--app-bg)",
  border: "1px solid var(--app-border)",
  borderRadius: 6,
  padding: "8px 12px",
  color: "var(--app-fg)",
  fontSize: 13,
};
const VAT_BUTTON = {
  ...sans,
  background: "var(--app-card-bg)",
  border: "1px solid var(--app-border)",
  borderRadius: 6,
  padding: "8px 14px",
  color: "var(--app-fg-secondary)",
  fontSize: 13,
  cursor: "pointer",
};
const VAT_BUTTON_PRIMARY = {
  ...VAT_BUTTON,
  background: "var(--app-input-bg)",
  borderColor: "var(--app-accent)",
  color: "var(--app-accent)",
};

export interface SavedPreset {
  id: string;
  name: string;
  savedAt: string;
  definition: ReportDefinition;
}

function getSavedPresets(): SavedPreset[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(SAVED_PRESETS_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (p): p is SavedPreset =>
        p &&
        typeof p === "object" &&
        typeof (p as SavedPreset).id === "string" &&
        typeof (p as SavedPreset).name === "string" &&
        typeof (p as SavedPreset).savedAt === "string" &&
        typeof (p as SavedPreset).definition === "object",
    );
  } catch {
    return [];
  }
}

function writeSavedPresets(presets: SavedPreset[]): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(SAVED_PRESETS_STORAGE_KEY, JSON.stringify(presets));
  } catch {
    // ignore
  }
}

function genId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function effectiveColsForRow(
  targetRow: number,
  widgets: WidgetDefinition[],
  excludeId: string | null,
): 1 | 2 | 3 {
  const count = widgets.filter((w) => {
    if (w.id === excludeId) return false;
    const l = w.layout ?? widgetLayoutFullWidth(0);
    const r = l.row ?? 0;
    const h = l.height ?? 1;
    return targetRow >= r && targetRow < r + h;
  }).length;
  return (
    (Math.min(CANVAS_MAX_COLUMNS, Math.max(1, count + 1)) as 1 | 2 | 3) || 1
  );
}

function CanvasGrid({
  widgets,
  selectedWidgetId,
  onSelectWidget,
  onReorderWidget,
  onRemoveWidget,
  onLayoutChange,
  onBatchLayoutChange,
}: {
  widgets: WidgetDefinition[];
  selectedWidgetId: string | null;
  onSelectWidget: (id: string) => void;
  onReorderWidget: (id: string, direction: "up" | "down") => void;
  onRemoveWidget: (id: string) => void;
  onLayoutChange: (widgetId: string, patch: Partial<WidgetLayout>) => void;
  onBatchLayoutChange?: (
    patches: Array<{ widgetId: string; patch: Partial<WidgetLayout> }>,
  ) => void;
}) {
  const gridRef = useRef<HTMLDivElement>(null);
  const [draggingId, setDraggingId] = useState<string | null>(null);
  const [dropTarget, setDropTarget] = useState<{
    col: number;
    row: number;
    width: number;
    resizeOthers?: Array<{ widgetId: string; patch: Partial<WidgetLayout> }>;
  } | null>(null);

  const sortedWidgets = useMemo(() => {
    return [...widgets].sort((a, b) => {
      const ra = a.layout?.row ?? 0;
      const rb = b.layout?.row ?? 0;
      if (ra !== rb) return ra - rb;
      return (a.layout?.col ?? 0) - (b.layout?.col ?? 0);
    });
  }, [widgets]);

  const findDropSlotOrSplit = useCallback(
    (
      targetRow: number,
    ): {
      col: number;
      width: number;
      resizeOthers?: Array<{ widgetId: string; patch: Partial<WidgetLayout> }>;
    } | null => {
      const othersInRow = widgets.filter((w) => {
        if (w.id === draggingId) return false;
        const l = w.layout ?? widgetLayoutFullWidth(0);
        const r = l.row ?? 0;
        const h = l.height ?? 1;
        return targetRow >= r && targetRow < r + h;
      });
      if (othersInRow.length === 0) return { col: 0, width: CANVAS_GRID_COLS };
      const cols = Math.min(CANVAS_MAX_COLUMNS, othersInRow.length + 1) as
        | 1
        | 2
        | 3;
      const upc = gridUnitsPerColumn(cols);
      const occupied: Array<{ id: string; start: number; end: number }> =
        othersInRow.map((w) => {
          const l = w.layout ?? widgetLayoutFullWidth(0);
          return {
            id: w.id,
            start: l.col ?? 0,
            end: (l.col ?? 0) + (l.width ?? 12),
          };
        });
      for (let c = 0; c <= CANVAS_GRID_COLS - upc; c += upc) {
        const end = c + upc;
        const overlapping = occupied.filter((o) => o.start < end && o.end > c);
        if (overlapping.length === 0) return { col: c, width: upc };
        if (
          overlapping.length === 1 &&
          overlapping[0]!.end - overlapping[0]!.start === CANVAS_GRID_COLS
        ) {
          const fullWidth = overlapping[0]!;
          const resizeOthers = [
            {
              widgetId: fullWidth.id,
              patch: { col: 0, width: upc } as Partial<WidgetLayout>,
            },
          ];
          return { col: upc, width: upc, resizeOthers };
        }
      }
      return null;
    },
    [widgets, draggingId],
  );

  const findNextRowSingleCol = useCallback(
    (targetRow: number): number => {
      const occupiedRows = new Set<number>();
      for (const w of widgets) {
        if (w.id === draggingId) continue;
        const l = w.layout ?? widgetLayoutFullWidth(0);
        const r = l.row ?? 0;
        const h = l.height ?? 1;
        for (let row = r; row < r + h; row++) occupiedRows.add(row);
      }
      for (let row = targetRow; row < targetRow + 20; row++) {
        if (!occupiedRows.has(row)) return row;
      }
      return targetRow + 1;
    },
    [widgets, draggingId],
  );

  const handleDragStart = useCallback(
    (e: React.DragEvent, widgetId: string) => {
      setDraggingId(widgetId);
      setDropTarget(null);
      e.dataTransfer.setData("text/plain", widgetId);
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("application/x-widget-id", widgetId);
    },
    [],
  );

  const handleDragEnd = useCallback(() => {
    setDraggingId(null);
    setDropTarget(null);
  }, []);

  const handleDragOver = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      if (!gridRef.current || !draggingId) return;
      const rect = gridRef.current.getBoundingClientRect();
      const relX = e.clientX - rect.left;
      const relY = e.clientY - rect.top;
      const colWidth = rect.width / CANVAS_GRID_COLS;
      const rawCol = Math.min(
        CANVAS_GRID_COLS - 1,
        Math.max(0, Math.floor(relX / colWidth)),
      );
      const rawRow = Math.max(0, Math.floor(relY / CANVAS_GRID_ROW_STEP));
      const rowHasOthers = widgets.some(
        (w) =>
          w.id !== draggingId &&
          (w.layout?.row ?? 0) <= rawRow &&
          rawRow < (w.layout?.row ?? 0) + (w.layout?.height ?? 1),
      );
      const effectiveCols = effectiveColsForRow(rawRow, widgets, draggingId);
      const col = snapColToLayout(rawCol, effectiveCols);
      const draggedLayout = widgets.find((w) => w.id === draggingId)?.layout;
      const draggedWidth = draggedLayout?.width ?? 12;
      let snapCol: number;
      let snapRow: number;
      let snapWidth: number;
      let resizeOthers:
        | Array<{ widgetId: string; patch: Partial<WidgetLayout> }>
        | undefined;
      if (rowHasOthers) {
        const result = findDropSlotOrSplit(rawRow);
        if (result) {
          snapCol = result.col;
          snapRow = rawRow;
          snapWidth = result.width;
          resizeOthers = result.resizeOthers;
        } else {
          snapRow = findNextRowSingleCol(rawRow);
          snapCol = 0;
          snapWidth = CANVAS_GRID_COLS;
        }
      } else {
        snapCol = col;
        snapRow = rawRow;
        snapWidth = snapWidthToLayout(draggedWidth, effectiveCols);
      }
      setDropTarget({
        col: snapCol,
        row: snapRow,
        width: snapWidth,
        resizeOthers,
      });
    },
    [draggingId, widgets, findDropSlotOrSplit, findNextRowSingleCol],
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      const widgetId =
        e.dataTransfer.getData("application/x-widget-id") ||
        e.dataTransfer.getData("text/plain");
      if (!widgetId || !gridRef.current) {
        setDraggingId(null);
        setDropTarget(null);
        return;
      }
      if (dropTarget) {
        if (dropTarget.resizeOthers && onBatchLayoutChange) {
          onBatchLayoutChange([
            ...dropTarget.resizeOthers,
            {
              widgetId,
              patch: {
                col: dropTarget.col,
                row: dropTarget.row,
                width: dropTarget.width,
              },
            },
          ]);
        } else {
          onLayoutChange(widgetId, {
            col: dropTarget.col,
            row: dropTarget.row,
            width: dropTarget.width,
          });
        }
      } else {
        const rect = gridRef.current.getBoundingClientRect();
        const colWidth = rect.width / CANVAS_GRID_COLS;
        const relX = e.clientX - rect.left;
        const relY = e.clientY - rect.top;
        const rawCol = Math.min(
          CANVAS_GRID_COLS - 1,
          Math.max(0, Math.floor(relX / colWidth)),
        );
        const row = Math.max(0, Math.floor(relY / CANVAS_GRID_ROW_STEP));
        const effectiveCols = effectiveColsForRow(row, widgets, widgetId);
        const col = snapColToLayout(rawCol, effectiveCols);
        const w = widgets.find((x) => x.id === widgetId);
        const rowHasOthers = widgets.some(
          (x) =>
            x.id !== widgetId &&
            (x.layout?.row ?? 0) <= row &&
            row < (x.layout?.row ?? 0) + (x.layout?.height ?? 1),
        );
        let finalCol: number;
        let finalRow: number;
        let width: number;
        if (rowHasOthers) {
          const result = findDropSlotOrSplit(row);
          if (result) {
            finalCol = result.col;
            finalRow = row;
            width = result.width;
            if (result.resizeOthers && onBatchLayoutChange) {
              onBatchLayoutChange([
                ...result.resizeOthers,
                { widgetId, patch: { col: finalCol, row: finalRow, width } },
              ]);
            } else {
              onLayoutChange(widgetId, { col: finalCol, row: finalRow, width });
            }
          } else {
            finalRow = findNextRowSingleCol(row);
            finalCol = 0;
            width = CANVAS_GRID_COLS;
            onLayoutChange(widgetId, { col: finalCol, row: finalRow, width });
          }
        } else {
          finalCol = col;
          finalRow = row;
          width = snapWidthToLayout(
            w?.layout?.width ?? gridUnitsPerColumn(effectiveCols),
            effectiveCols,
          );
          onLayoutChange(widgetId, { col: finalCol, row: finalRow, width });
        }
      }
      setDraggingId(null);
      setDropTarget(null);
    },
    [
      onLayoutChange,
      onBatchLayoutChange,
      dropTarget,
      widgets,
      findDropSlotOrSplit,
      findNextRowSingleCol,
    ],
  );

  return (
    <div
      ref={gridRef}
      className="report-builder-canvas-grid"
      style={{
        gridTemplateColumns: `repeat(${CANVAS_GRID_COLS}, minmax(0, 1fr))`,
        gridAutoRows: `${CANVAS_GRID_ROW_HEIGHT}px`,
      }}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      {dropTarget && draggingId && (
        <div
          style={{
            position: "absolute",
            pointerEvents: "none",
            borderRadius: 6,
            border: "2px dashed var(--app-accent)",
            background: "rgba(56,189,248,0.1)",
            zIndex: 10,
            gridColumn: `${dropTarget.col + 1} / span ${dropTarget.width}`,
            gridRow: `${dropTarget.row + 1} / span 1`,
            minHeight: 0,
          }}
          aria-hidden
        />
      )}
      {sortedWidgets.map((widget, idx) => {
        const layout = widget.layout ?? widgetLayoutFullWidth(0);
        const col = layout.col ?? 0;
        const row = layout.row ?? 0;
        const w = Math.min(
          CANVAS_GRID_COLS - col,
          Math.max(1, layout.width ?? 1),
        );
        const h = Math.max(1, layout.height ?? 1);
        const isDragging = draggingId === widget.id;
        return (
          <div
            key={widget.id}
            draggable
            onDragStart={(e) => handleDragStart(e, widget.id)}
            onDragEnd={handleDragEnd}
            className={`report-builder-canvas-widget ${
              selectedWidgetId === widget.id ? "selected" : ""
            } ${isDragging ? "dragging" : ""}`}
            style={{
              gridColumn: `${col + 1} / span ${w}`,
              gridRow: `${row + 1} / span ${h}`,
              minHeight: 0,
            }}
            onClick={() => onSelectWidget(widget.id)}
          >
            <GripVertical
              size={14}
              style={{ color: "var(--app-fg-secondary)", flexShrink: 0 }}
            />
            <span
              style={{
                ...sans,
                fontSize: 13,
                color: "var(--app-fg)",
                flex: 1,
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {WIDGET_TYPE_LABELS[widget.type]}
            </span>
            <div style={{ display: "flex", gap: 2, flexShrink: 0 }}>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onReorderWidget(widget.id, "up");
                }}
                disabled={idx === 0}
                style={{ ...VAT_BUTTON, padding: "4px 6px" }}
                aria-label="Move up"
              >
                <ChevronUp size={14} />
              </button>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onReorderWidget(widget.id, "down");
                }}
                disabled={idx === sortedWidgets.length - 1}
                style={{ ...VAT_BUTTON, padding: "4px 6px" }}
                aria-label="Move down"
              >
                <ChevronDown size={14} />
              </button>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onRemoveWidget(widget.id);
                }}
                style={{
                  ...VAT_BUTTON,
                  padding: "4px 6px",
                  color: "var(--app-danger)",
                }}
                aria-label="Remove"
              >
                <Trash2 size={14} />
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function WidgetConfigForm({
  widget,
  onUpdate,
}: {
  widget: WidgetDefinition;
  onUpdate: (patch: Record<string, unknown>) => void;
}) {
  const { type, config } = widget;
  const c = config as Record<string, unknown>;

  if (type === "summary") {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <label
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          Variant
        </label>
        <select
          value={String(c.variant ?? "default")}
          onChange={(e) => onUpdate({ variant: e.target.value })}
          style={{ ...VAT_INPUT, width: "100%" }}
        >
          <option value="default">Default</option>
          <option value="board">Board</option>
          <option value="weekly">Weekly</option>
          <option value="compliance">Compliance</option>
        </select>
      </div>
    );
  }

  const limitTypes: WidgetType[] = [
    "repoTable",
    "topVulnsTable",
    "topVulnsList",
    "topVulnsAdvisory",
    "issueList",
  ];
  if (limitTypes.includes(type)) {
    const limit = Number(c.limit) || 25;
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <label
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          Limit
        </label>
        <input
          type="number"
          min={1}
          max={type === "issueList" ? 1000 : 100}
          value={limit}
          onChange={(e) =>
            onUpdate({ limit: Math.max(1, parseInt(e.target.value, 10) || 1) })
          }
          style={{ ...VAT_INPUT, width: "100%" }}
        />
      </div>
    );
  }

  if (
    type === "severityDonut" ||
    type === "riskGauge" ||
    type === "scannerDonut"
  ) {
    const size = Number(c.size) || (type === "riskGauge" ? 120 : 100);
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <label
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          Size (px)
        </label>
        <input
          type="number"
          min={40}
          max={200}
          value={size}
          onChange={(e) =>
            onUpdate({ size: Math.max(40, parseInt(e.target.value, 10) || 40) })
          }
          style={{ ...VAT_INPUT, width: "100%" }}
        />
      </div>
    );
  }

  if (type === "repoBars" || type === "containerBars") {
    const maxRepos = Number(c.maxRepos ?? c.maxContainers) || 8;
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <label
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          Max items
        </label>
        <input
          type="number"
          min={1}
          max={30}
          value={maxRepos}
          onChange={(e) =>
            onUpdate(
              type === "containerBars"
                ? {
                    maxContainers: Math.max(
                      1,
                      parseInt(e.target.value, 10) || 1,
                    ),
                  }
                : { maxRepos: Math.max(1, parseInt(e.target.value, 10) || 1) },
            )
          }
          style={{ ...VAT_INPUT, width: "100%" }}
        />
      </div>
    );
  }

  if (type === "trendStacked") {
    const periodDays = Number(c.periodDays) || 90;
    const width = Number(c.width) || 560;
    const height = Number(c.height) || 160;
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <label
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          Period
        </label>
        <select
          value={String(periodDays)}
          onChange={(e) =>
            onUpdate({ periodDays: parseInt(e.target.value, 10) })
          }
          style={{ ...VAT_INPUT, width: "100%" }}
        >
          <option value="30">Last 30 days</option>
          <option value="90">Last 90 days</option>
          <option value="365">Last 12 months</option>
        </select>
        <label
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          Width (px)
        </label>
        <input
          type="number"
          min={120}
          max={800}
          value={width}
          onChange={(e) =>
            onUpdate({
              width: Math.max(120, parseInt(e.target.value, 10) || 120),
            })
          }
          style={{ ...VAT_INPUT, width: "100%" }}
        />
        <label
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          Height (px)
        </label>
        <input
          type="number"
          min={32}
          max={200}
          value={height}
          onChange={(e) =>
            onUpdate({
              height: Math.max(32, parseInt(e.target.value, 10) || 32),
            })
          }
          style={{ ...VAT_INPUT, width: "100%" }}
        />
      </div>
    );
  }

  if (type === "complianceScoreCard") {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <label
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          Framework
        </label>
        <select
          value={String(c.framework ?? "soc2")}
          onChange={(e) => onUpdate({ framework: e.target.value })}
          style={{ ...VAT_INPUT, width: "100%" }}
        >
          <option value="soc2">SOC 2</option>
          <option value="nis2">NIS 2</option>
          <option value="iso27001">ISO 27001</option>
        </select>
      </div>
    );
  }

  if (type === "slaCompliance") {
    const criticalDays = Number(c.criticalDays) || 7;
    const highDays = Number(c.highDays) || 30;
    const mediumDays = Number(c.mediumDays) || 90;
    const lowDays = Number(c.lowDays) || 180;
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <label
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          Critical SLA (days)
        </label>
        <input
          type="number"
          min={1}
          max={90}
          value={criticalDays}
          onChange={(e) =>
            onUpdate({
              criticalDays: Math.max(1, parseInt(e.target.value, 10) || 7),
            })
          }
          style={{ ...VAT_INPUT, width: "100%" }}
        />
        <label
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          High SLA (days)
        </label>
        <input
          type="number"
          min={1}
          max={180}
          value={highDays}
          onChange={(e) =>
            onUpdate({
              highDays: Math.max(1, parseInt(e.target.value, 10) || 30),
            })
          }
          style={{ ...VAT_INPUT, width: "100%" }}
        />
        <label
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          Medium SLA (days)
        </label>
        <input
          type="number"
          min={1}
          max={365}
          value={mediumDays}
          onChange={(e) =>
            onUpdate({
              mediumDays: Math.max(1, parseInt(e.target.value, 10) || 90),
            })
          }
          style={{ ...VAT_INPUT, width: "100%" }}
        />
        <label
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          Low SLA (days)
        </label>
        <input
          type="number"
          min={1}
          max={365}
          value={lowDays}
          onChange={(e) =>
            onUpdate({
              lowDays: Math.max(1, parseInt(e.target.value, 10) || 180),
            })
          }
          style={{ ...VAT_INPUT, width: "100%" }}
        />
      </div>
    );
  }

  if (type === "text") {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <label
          style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}
        >
          Content (Markdown)
        </label>
        <textarea
          value={String(c.content ?? "")}
          onChange={(e) => onUpdate({ content: e.target.value })}
          rows={4}
          style={{ ...VAT_INPUT, width: "100%", resize: "vertical" }}
        />
      </div>
    );
  }

  return (
    <p style={{ ...sans, fontSize: 12, color: "var(--app-fg-secondary)" }}>
      No options for this widget type.
    </p>
  );
}

function Modal({
  open,
  onClose,
  title,
  desc,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  desc?: string;
  children: React.ReactNode;
}) {
  if (!open) return null;
  return (
    <div className="report-builder-modal-overlay" onClick={onClose}>
      <div
        className="report-builder-modal"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="report-builder-modal-title">{title}</h2>
        {desc && <p className="report-builder-modal-desc">{desc}</p>}
        <div className="report-builder-modal-body">{children}</div>
      </div>
    </div>
  );
}

interface ReportBuilderViewProps {
  data: VATDashboardData;
  allAssets: Asset[];
  /** Findings behind `data`, already narrowed by the sidebar (and so by any
   *  applied team loadout). Used for the full export bundle. */
  exportFindings?: Finding[];
  /** Default count mode when creating new reports. "instances" = each finding counts (matches Findings tab). */
  defaultCountMode?: "groups" | "instances";
  /** When true, report is filtered to current favorites. Toggle is shown when favoriteCount > 0. */
  useFavoritesOnly?: boolean;
  onUseFavoritesOnlyToggle?: () => void;
  favoriteCount?: number;
}

export function ReportBuilderView({
  data,
  allAssets,
  exportFindings,
  defaultCountMode = "groups",
  useFavoritesOnly = false,
  onUseFavoritesOnlyToggle,
  favoriteCount = 0,
}: ReportBuilderViewProps) {
  const { themeId: userThemeId } = useTheme();
  const [definition, setDefinition] = useState<ReportDefinition>(() =>
    createDefaultReportDefinition(
      data.workspace.name,
      undefined,
      userThemeId,
      defaultCountMode,
    ),
  );
  const [selectedCanvasId, setSelectedCanvasId] = useState<string | null>(
    () => definition.canvases[0]?.id ?? null,
  );
  const [selectedWidgetId, setSelectedWidgetId] = useState<string | null>(null);
  const [savedPresets, setSavedPresets] = useState<SavedPreset[]>([]);
  const [savePresetOpen, setSavePresetOpen] = useState(false);
  const [savePresetName, setSavePresetName] = useState("");
  const [savedReports, setSavedReports] = useState<SavedReportMeta[]>([]);
  const [saveReportOpen, setSaveReportOpen] = useState(false);
  const [saveReportName, setSaveReportName] = useState("");
  const [emailDialogOpen, setEmailDialogOpen] = useState(false);
  const [emailRecipients, setEmailRecipients] = useState("");
  const [emailSending, setEmailSending] = useState(false);
  const [previewZoom, setPreviewZoom] = useState<"fit" | number>("fit");
  const [previewMode, setPreviewMode] = useState<"dock" | "float">("dock");
  const [measuredReportHeight, setMeasuredReportHeight] = useState<
    number | null
  >(null);
  const [measuredReportWidth, setMeasuredReportWidth] = useState<number | null>(
    null,
  );
  const [assetTypeFilter, setAssetTypeFilter] = useState<ReportAssetType[]>(
    () => ["image", "component", "unknown"] as ReportAssetType[],
  );
  const previewContainerRef = useRef<HTMLDivElement>(null);
  const [previewSize, setPreviewSize] = useState({
    width: PREVIEW_PAGE_WIDTH,
    height: 400,
  });
  const floatWindowRef = useRef<Window | null>(null);
  const previewPanelRef = useRef<ImperativePanelHandle>(null);

  useEffect(() => setSavedPresets(getSavedPresets()), []);

  const refreshSavedReports = useCallback(async () => {
    const list = await getReportPersistence().list();
    setSavedReports(list);
  }, []);

  useEffect(() => {
    refreshSavedReports();
  }, [refreshSavedReports]);

  // Preserve report definition count mode when explicitly set (for presets like
  // "All Instances"). Fall back to sidebar preference only when count mode is
  // missing from the current definition.
  const effectiveFilters = useMemo(
    () => ({
      ...definition.filters,
      countMode: definition.filters.countMode ?? defaultCountMode ?? "groups",
    }),
    [definition.filters, defaultCountMode],
  );
  const countMode = effectiveFilters.countMode ?? "groups";
  const assetsByType = useMemo(() => {
    const byType: Record<ReportAssetType, Asset[]> = {
      image: [],
      component: [],
      unknown: [],
    };
    for (const a of allAssets) {
      const t = getAssetTypeForReport(a);
      byType[t].push(a);
    }
    return byType;
  }, [allAssets]);
  const toggleAssetType = useCallback((t: ReportAssetType) => {
    setAssetTypeFilter((prev) =>
      prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t],
    );
  }, []);
  const repos = useMemo(
    () =>
      computeRepoRiskScores(
        data.issues,
        data.repos,
        data.issueGroups,
        countMode,
      ),
    [data, countMode],
  );
  const currentCanvas = useMemo(
    () => definition.canvases.find((c) => c.id === selectedCanvasId) ?? null,
    [definition.canvases, selectedCanvasId],
  );
  const selectedWidget = useMemo(() => {
    if (!currentCanvas || !selectedWidgetId) return null;
    return currentCanvas.widgets.find((w) => w.id === selectedWidgetId) ?? null;
  }, [currentCanvas, selectedWidgetId]);
  const validation = useMemo(
    () => validateReportDefinition(definition),
    [definition],
  );

  // Defer heavy report computation to avoid freezing the browser with large datasets
  const [reportState, setReportState] = useState<{
    reportContext: ReportContext;
    previewHtml: string;
  } | null>(null);

  const [reportError, setReportError] = useState(false);

  useEffect(() => {
    setReportError(false);
    let cancelled = false;
    const run = () => {
      if (cancelled) return;
      try {
        const reportContext = computeReportContext(data, effectiveFilters, {
          allIssuesForPeriodComparison: data.issues,
        });
        if (cancelled) return;
        const defWithFilters = { ...definition, filters: effectiveFilters };
        const previewHtml = buildReportHtmlFromDefinition(
          reportContext,
          defWithFilters,
          { preview: true },
        );
        if (cancelled) return;
        setReportState({ reportContext, previewHtml });
      } catch {
        if (!cancelled) {
          setReportState(null);
          setReportError(true);
        }
      }
    };
    // Use setTimeout(0) so preview updates immediately when toggle changes.
    // requestIdleCallback can delay indefinitely and made the preview appear stuck.
    const id = setTimeout(run, 0);
    return () => {
      cancelled = true;
      clearTimeout(id);
    };
  }, [data, effectiveFilters, definition]);

  const reportContext = reportState?.reportContext ?? null;
  const previewHtml = reportState?.previewHtml ?? null;

  useEffect(() => {
    setMeasuredReportHeight(null);
    setMeasuredReportWidth(null);
  }, [previewHtml]);

  useEffect(() => {
    if (previewMode !== "dock") return;
    const handler = (e: MessageEvent) => {
      const d = e.data;
      if (
        d?.type === "vat-report-size" &&
        typeof d.height === "number" &&
        d.height > 0
      ) {
        setMeasuredReportHeight(d.height);
        if (typeof d.width === "number" && d.width > 0)
          setMeasuredReportWidth(d.width);
      }
    };
    window.addEventListener("message", handler);
    return () => window.removeEventListener("message", handler);
  }, [previewMode]);

  useEffect(() => {
    if (previewMode !== "dock") return;
    const el = previewContainerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      const w = el.clientWidth;
      const h = el.clientHeight;
      if (w > 0 && h > 0)
        setPreviewSize((prev) =>
          prev.width === w && prev.height === h
            ? prev
            : { width: w, height: h },
        );
    });
    ro.observe(el);
    const w = el.clientWidth;
    const h = el.clientHeight;
    if (w > 0 && h > 0) setPreviewSize({ width: w, height: h });
    return () => ro.disconnect();
  }, [previewHtml, previewMode]);

  const previewPageCount = Math.max(1, definition.canvases.length);
  const previewContentHeight = previewPageCount * PREVIEW_PAGE_HEIGHT;
  const iframeHeight = measuredReportHeight ?? previewContentHeight;
  const iframeWidth = Math.max(
    PREVIEW_PAGE_WIDTH,
    measuredReportWidth ?? PREVIEW_PAGE_WIDTH,
  );
  const containerW = Math.max(previewSize.width, 1);
  const containerH = Math.max(previewSize.height, 1);
  const fitScale = containerW / Math.max(iframeWidth, 1);
  const zoomMultiplier = typeof previewZoom === "number" ? previewZoom : 1;
  const previewScale = Math.min(fitScale, fitScale * zoomMultiplier);
  const previewInnerHeight = Math.ceil(previewContentHeight * previewScale);

  const openFloatPreviewWindow = useCallback(() => {
    if (!previewHtml) return;
    const name = "report-preview-window";
    const features =
      "width=900,height=800,scrollbars=yes,resizable=yes,menubar=no,toolbar=no,location=no";
    let w = floatWindowRef.current;
    if (!w || w.closed) {
      w = window.open("about:blank", name, features);
      floatWindowRef.current = w ?? null;
    }
    if (w && !w.closed) {
      w.document.write(previewHtml);
      w.document.close();
      w.focus();
    }
  }, [previewHtml]);

  useEffect(() => {
    if (previewMode !== "float" || !previewHtml) return;
    const w = floatWindowRef.current;
    if (w && !w.closed) {
      w.document.open();
      w.document.write(previewHtml);
      w.document.close();
    }
  }, [previewMode, previewHtml]);

  useEffect(() => {
    if (previewMode === "float") {
      previewPanelRef.current?.collapse();
    } else {
      previewPanelRef.current?.expand(40);
    }
  }, [previewMode]);

  useEffect(() => {
    if (previewMode !== "float") return;
    const id = setInterval(() => {
      const w = floatWindowRef.current;
      if (w?.closed) {
        floatWindowRef.current = null;
        setPreviewMode("dock");
      }
    }, 400);
    return () => clearInterval(id);
  }, [previewMode]);

  useEffect(() => {
    const exists = definition.canvases.some((c) => c.id === selectedCanvasId);
    if (!exists && definition.canvases.length > 0) {
      setSelectedCanvasId(definition.canvases[0]!.id);
      setSelectedWidgetId(null);
    }
  }, [definition.canvases, selectedCanvasId]);

  const updateDefinition = useCallback(
    (updater: (d: ReportDefinition) => ReportDefinition) => {
      setDefinition((prev) => updater(prev));
    },
    [],
  );

  const updateFilters = useCallback(
    (patch: Partial<ReportFilters>) => {
      updateDefinition((d) => ({ ...d, filters: { ...d.filters, ...patch } }));
    },
    [updateDefinition],
  );

  const toggleSeverity = useCallback((sev: string) => {
    setDefinition((d) => ({
      ...d,
      filters: {
        ...d.filters,
        severityFilter: d.filters.severityFilter.includes(sev)
          ? d.filters.severityFilter.filter((s) => s !== sev)
          : [...d.filters.severityFilter, sev],
      },
    }));
  }, []);

  const addCanvas = useCallback(() => {
    const id = genId("c");
    const name = `Page ${definition.canvases.length + 1}`;
    updateDefinition((d) => ({
      ...d,
      canvases: [...d.canvases, { id, name, widgets: [] }],
    }));
    setSelectedCanvasId(id);
    setSelectedWidgetId(null);
  }, [definition.canvases.length, updateDefinition]);

  const removeCanvas = useCallback(
    (canvasId: string) => {
      const idx = definition.canvases.findIndex((c) => c.id === canvasId);
      if (idx < 0) return;
      updateDefinition((d) => ({
        ...d,
        canvases: d.canvases.filter((c) => c.id !== canvasId),
      }));
      if (selectedCanvasId === canvasId) {
        const next =
          definition.canvases[idx + 1] ?? definition.canvases[idx - 1];
        setSelectedCanvasId(next?.id ?? null);
        setSelectedWidgetId(null);
      }
    },
    [definition.canvases, selectedCanvasId, updateDefinition],
  );

  const reorderCanvas = useCallback(
    (canvasId: string, direction: "up" | "down") => {
      const idx = definition.canvases.findIndex((c) => c.id === canvasId);
      if (idx < 0) return;
      const nextIdx = direction === "up" ? idx - 1 : idx + 1;
      if (nextIdx < 0 || nextIdx >= definition.canvases.length) return;
      const copy = [...definition.canvases];
      [copy[idx], copy[nextIdx]] = [copy[nextIdx]!, copy[idx]!];
      updateDefinition((d) => ({ ...d, canvases: copy }));
    },
    [definition.canvases, updateDefinition],
  );

  const updateCanvasName = useCallback(
    (canvasId: string, name: string) => {
      updateDefinition((d) => ({
        ...d,
        canvases: d.canvases.map((c) =>
          c.id === canvasId ? { ...c, name } : c,
        ),
      }));
    },
    [updateDefinition],
  );

  const addWidget = useCallback(
    (type: WidgetType) => {
      if (!currentCanvas) return;
      const id = genId("w");
      const config = { ...WIDGET_DEFAULT_CONFIG[type] };
      const row = nextLayoutRow(currentCanvas.widgets);
      const layout = widgetLayoutFullWidth(row);
      updateDefinition((d) => ({
        ...d,
        canvases: d.canvases.map((c) =>
          c.id === currentCanvas.id
            ? { ...c, widgets: [...c.widgets, { id, type, config, layout }] }
            : c,
        ),
      }));
      setSelectedWidgetId(id);
    },
    [currentCanvas, updateDefinition],
  );

  const removeWidget = useCallback(
    (widgetId: string) => {
      if (!currentCanvas) return;
      updateDefinition((d) => {
        const canvas = d.canvases.find((c) => c.id === currentCanvas.id);
        if (!canvas) return d;
        const filtered = canvas.widgets.filter((w) => w.id !== widgetId);
        const normalized = normalizeCanvasRowLayouts(filtered);
        return {
          ...d,
          canvases: d.canvases.map((c) =>
            c.id === currentCanvas.id ? { ...c, widgets: normalized } : c,
          ),
        };
      });
      if (selectedWidgetId === widgetId) setSelectedWidgetId(null);
    },
    [currentCanvas, selectedWidgetId, updateDefinition],
  );

  const reorderWidget = useCallback(
    (widgetId: string, direction: "up" | "down") => {
      if (!currentCanvas) return;
      const idx = currentCanvas.widgets.findIndex((w) => w.id === widgetId);
      if (idx < 0) return;
      const nextIdx = direction === "up" ? idx - 1 : idx + 1;
      if (nextIdx < 0 || nextIdx >= currentCanvas.widgets.length) return;
      const copy = [...currentCanvas.widgets];
      [copy[idx], copy[nextIdx]] = [copy[nextIdx]!, copy[idx]!];
      updateDefinition((d) => ({
        ...d,
        canvases: d.canvases.map((c) =>
          c.id === currentCanvas.id ? { ...c, widgets: copy } : c,
        ),
      }));
    },
    [currentCanvas, updateDefinition],
  );

  const updateWidgetLayout = useCallback(
    (widgetId: string, patch: Partial<WidgetLayout>) => {
      if (!currentCanvas) return;
      updateDefinition((d) => {
        const c = d.canvases.find((x) => x.id === currentCanvas.id);
        if (!c) return d;
        const updated = c.widgets.map((w) => {
          if (w.id !== widgetId) return w;
          const prev = w.layout ?? widgetLayoutFullWidth(0);
          return {
            ...w,
            layout: {
              col: patch.col ?? prev.col,
              row: patch.row ?? prev.row,
              width: patch.width ?? prev.width,
              height: patch.height ?? prev.height,
            },
          };
        });
        const normalized = normalizeCanvasRowLayouts(updated);
        return {
          ...d,
          canvases: d.canvases.map((x) =>
            x.id === currentCanvas.id ? { ...x, widgets: normalized } : x,
          ),
        };
      });
    },
    [currentCanvas, updateDefinition],
  );

  const updateWidgetLayoutBatch = useCallback(
    (patches: Array<{ widgetId: string; patch: Partial<WidgetLayout> }>) => {
      if (!currentCanvas || patches.length === 0) return;
      const patchMap = new Map(patches.map((p) => [p.widgetId, p.patch]));
      updateDefinition((d) => {
        const c = d.canvases.find((x) => x.id === currentCanvas.id);
        if (!c) return d;
        const updated = c.widgets.map((w) => {
          const patch = patchMap.get(w.id);
          if (!patch) return w;
          const prev = w.layout ?? widgetLayoutFullWidth(0);
          return {
            ...w,
            layout: {
              col: patch.col ?? prev.col,
              row: patch.row ?? prev.row,
              width: patch.width ?? prev.width,
              height: patch.height ?? prev.height,
            },
          };
        });
        const normalized = normalizeCanvasRowLayouts(updated);
        return {
          ...d,
          canvases: d.canvases.map((x) =>
            x.id === currentCanvas.id ? { ...x, widgets: normalized } : x,
          ),
        };
      });
    },
    [currentCanvas, updateDefinition],
  );

  const updateWidgetConfig = useCallback(
    (widgetId: string, patch: Record<string, unknown>) => {
      if (!currentCanvas) return;
      updateDefinition((d) => ({
        ...d,
        canvases: d.canvases.map((c) =>
          c.id === currentCanvas.id
            ? {
                ...c,
                widgets: c.widgets.map((w) =>
                  w.id === widgetId
                    ? { ...w, config: { ...w.config, ...patch } }
                    : w,
                ),
              }
            : c,
        ),
      }));
    },
    [currentCanvas, updateDefinition],
  );

  const startFresh = useCallback(() => {
    const next = createDefaultReportDefinition(
      data.workspace.name,
      undefined,
      userThemeId,
      defaultCountMode,
    );
    setDefinition(next);
    const first = next.canvases[0];
    setSelectedCanvasId(first?.id ?? null);
    setSelectedWidgetId(null);
  }, [data.workspace.name, userThemeId, defaultCountMode]);

  const loadPreset = useCallback(
    (presetId: string) => {
      const builtIn = REPORT_PRESETS.find((p) => p.id === presetId);
      if (builtIn) {
        const def = clonePresetDefinition(builtIn);
        setDefinition({
          ...def,
          filters: {
            ...def.filters,
            countMode: def.filters.countMode ?? defaultCountMode ?? "groups",
          },
        });
        const first = builtIn.definition.canvases[0];
        setSelectedCanvasId(first?.id ?? null);
        setSelectedWidgetId(null);
        return;
      }
      const saved = savedPresets.find((p) => p.id === presetId);
      if (saved) {
        const def = normalizeReportDefinitionLayout(
          JSON.parse(JSON.stringify(saved.definition)),
        );
        setDefinition({
          ...def,
          filters: {
            ...def.filters,
            countMode: def.filters.countMode ?? defaultCountMode ?? "groups",
          },
        });
        const first = def.canvases[0];
        setSelectedCanvasId(first?.id ?? null);
        setSelectedWidgetId(null);
      }
    },
    [savedPresets, defaultCountMode],
  );

  const saveCurrentAsPreset = useCallback(() => {
    const name = savePresetName.trim();
    if (!name) return;
    const id = genId("saved");
    const saved: SavedPreset = {
      id,
      name,
      savedAt: new Date().toISOString(),
      definition: JSON.parse(JSON.stringify(definition)),
    };
    const next = [...getSavedPresets(), saved];
    writeSavedPresets(next);
    setSavedPresets(next);
    setSavePresetName("");
    setSavePresetOpen(false);
  }, [definition, savePresetName]);

  const deleteSavedPreset = useCallback((id: string) => {
    const next = getSavedPresets().filter((p) => p.id !== id);
    writeSavedPresets(next);
    setSavedPresets(next);
  }, []);

  const loadSavedReport = useCallback(
    async (id: string) => {
      const def = await getReportPersistence().load(id);
      if (def) {
        setDefinition({
          ...def,
          filters: {
            ...def.filters,
            countMode: def.filters.countMode ?? defaultCountMode ?? "groups",
          },
        });
        const first = def.canvases[0];
        setSelectedCanvasId(first?.id ?? null);
        setSelectedWidgetId(null);
      }
    },
    [defaultCountMode],
  );

  const saveCurrentReport = useCallback(async () => {
    const name = saveReportName.trim() || definition.title || "Untitled report";
    await getReportPersistence().save(null, name, definition);
    setSaveReportName("");
    setSaveReportOpen(false);
    refreshSavedReports();
  }, [definition, saveReportName, refreshSavedReports]);

  const deleteSavedReport = useCallback(
    async (id: string) => {
      await getReportPersistence().delete(id);
      refreshSavedReports();
    },
    [refreshSavedReports],
  );

  const handleExportPdf = useCallback(() => {
    exportPdfFromDefinition(data, { ...definition, filters: effectiveFilters });
  }, [data, definition, effectiveFilters]);

  const handleExportHtml = useCallback(() => {
    exportHtmlFromDefinition(data, {
      ...definition,
      filters: effectiveFilters,
    });
  }, [data, definition, effectiveFilters]);

  const { token } = useAuth();
  const [bundleState, setBundleState] = useState<"idle" | "building" | "error">(
    "idle",
  );
  const handleExportBundle = useCallback(async () => {
    setBundleState("building");
    try {
      // Pass the on-screen scope so the bundle matches what is selected; with
      // no scope the builder refetches the whole workspace and the applied
      // team loadout is silently ignored.
      await buildAndDownloadExportBundle(
        { token: token ?? undefined },
        exportFindings ? { findings: exportFindings, assets: allAssets } : undefined,
      );
      setBundleState("idle");
    } catch {
      setBundleState("error");
    }
  }, [exportFindings, allAssets, token]);

  const handleExportCsv = useCallback(() => {
    exportCsvFromDefinition(data, { ...definition, filters: effectiveFilters });
  }, [data, definition, effectiveFilters]);

  const handleSendEmail = useCallback(async () => {
    const recipients = emailRecipients
      .split(/[,;\s]+/)
      .map((e) => e.trim())
      .filter(Boolean);
    if (recipients.length === 0) {
      alert("Enter at least one email address");
      return;
    }
    setEmailSending(true);
    try {
      const res = await fetch("/api/report/email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          recipients,
          definition: { ...definition, filters: effectiveFilters },
        }),
      });
      const json = await res.json();
      if (!res.ok) {
        alert(json.message || json.error || "Failed to send email");
        return;
      }
      setEmailDialogOpen(false);
      setEmailRecipients("");
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to send email");
    } finally {
      setEmailSending(false);
    }
  }, [definition, effectiveFilters, emailRecipients]);

  return (
    <div className="report-builder">
      <header className="report-builder-header">
        <h1>Report Builder</h1>
        <p>
          Build compliance evidence reports with multiple pages and widgets.
          Configure filters, add content, and export to PDF, HTML, or CSV.
        </p>
      </header>

      <div className="report-builder-toolbar">
        <div className="toolbar-group">
          <button
            onClick={handleExportPdf}
            disabled={!validation.valid}
            className="btn btn-primary"
          >
            <Printer size={16} /> Export PDF
          </button>
          <button
            onClick={handleExportHtml}
            disabled={!validation.valid}
            className="btn btn-primary"
          >
            <Globe size={16} /> Export HTML
          </button>
          <button
            onClick={handleExportCsv}
            disabled={!validation.valid}
            className="btn btn-primary"
          >
            <FileSpreadsheet size={16} /> Export CSV
          </button>
          <button
            onClick={handleExportBundle}
            disabled={bundleState === "building"}
            title="ZIP: assets + findings JSON, CycloneDX SBOM, and the executive summary — scoped to the current filters"
            className="btn btn-primary"
          >
            <Package size={16} />
            {bundleState === "building"
              ? "Building bundle…"
              : bundleState === "error"
                ? "Bundle failed — retry"
                : "Export bundle"}
          </button>
        </div>
        <div className="toolbar-divider" />
        <div className="toolbar-group">
          <button
            onClick={() => setEmailDialogOpen(true)}
            disabled={!validation.valid}
            className="btn"
          >
            <Mail size={16} /> Email
          </button>
          <button
            onClick={() => {
              setSaveReportName(definition.title);
              setSaveReportOpen(true);
            }}
            className="btn"
          >
            <Save size={16} /> Save Report
          </button>
          <button onClick={() => setSavePresetOpen(true)} className="btn">
            <Bookmark size={16} /> Save Preset
          </button>
        </div>
        <div className="toolbar-divider" />
        <div className="toolbar-group">
          <button onClick={startFresh} className="btn">
            <RotateCcw size={16} /> Start Fresh
          </button>
        </div>
      </div>

      <div className="report-builder-body">
        <ResizablePanelGroup
          direction="horizontal"
          style={{ flex: 1, minHeight: 400 }}
        >
          <ResizablePanel
            defaultSize={60}
            minSize={40}
            style={{
              display: "flex",
              flexDirection: "column",
              minWidth: 0,
              minHeight: 0,
              overflow: "hidden",
            }}
          >
            <div className="report-builder-sidebar">
              <div className="report-builder-sidebar-scroll">
                {/* Settings & Filters */}
                <div className="report-builder-section">
                  <div className="report-builder-section-header">
                    <Settings2 size={14} />
                    Report settings & filters
                  </div>
                  <div className="report-builder-section-body">
                    <div className="form-row">
                      <label className="form-label">Report title</label>
                      <input
                        type="text"
                        value={definition.title}
                        onChange={(e) =>
                          setDefinition((d) => ({
                            ...d,
                            title: e.target.value,
                          }))
                        }
                        placeholder={`Vulnerability Report - ${data.workspace.name}`}
                        className="form-input"
                        style={{ maxWidth: 400 }}
                      />
                    </div>
                    <div className="form-row">
                      <label className="form-label">Theme</label>
                      <select
                        value={definition.themeId ?? "default"}
                        onChange={(e) =>
                          setDefinition((d) => ({
                            ...d,
                            themeId: e.target.value,
                          }))
                        }
                        className="form-input"
                        style={{ minWidth: 140 }}
                      >
                        {REPORT_THEMES.map((t) => (
                          <option key={t.id} value={t.id}>
                            {t.name}
                          </option>
                        ))}
                      </select>
                    </div>
                    {favoriteCount > 0 && onUseFavoritesOnlyToggle && (
                      <label
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 8,
                          cursor: "pointer",
                          ...sans,
                          fontSize: 12,
                          color: "var(--app-fg)",
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={useFavoritesOnly}
                          onChange={onUseFavoritesOnlyToggle}
                        />
                        <Bookmark
                          size={14}
                          style={{
                            color: "var(--app-fg-secondary)",
                            flexShrink: 0,
                          }}
                        />
                        <span>Use current favorites ({favoriteCount})</span>
                      </label>
                    )}
                    <div
                      className="form-row"
                      style={{ display: "flex", gap: 20, flexWrap: "wrap" }}
                    >
                      <div style={{ flex: 1, minWidth: 120 }}>
                        <label className="form-label">Trend lookback</label>
                        <select
                          value={
                            [7, 30, 90, 120, 365].includes(
                              Number(definition.filters.dateRangePreset),
                            )
                              ? String(definition.filters.dateRangePreset)
                              : definition.filters.dateFrom ??
                                  definition.filters.dateTo
                                ? "custom"
                                : "all"
                          }
                          onChange={(e) => {
                            const v = e.target.value;
                            const preset: DateRangePreset =
                              v === "all" || v === "custom"
                                ? null
                                : (Number(v) as 7 | 30 | 90 | 120 | 365);
                            if (v === "custom") {
                              const to = new Date();
                              const from = new Date(to);
                              from.setDate(from.getDate() - 30);
                              updateFilters({
                                dateRangePreset: null,
                                dateFrom: from.toISOString().slice(0, 10),
                                dateTo: to.toISOString().slice(0, 10),
                              });
                            } else {
                              updateFilters({
                                dateRangePreset: preset,
                                dateFrom: null,
                                dateTo: null,
                              });
                            }
                          }}
                          className="form-input"
                          style={{ minWidth: 120 }}
                        >
                          <option value="all">All</option>
                          <option value="7">Last 7 days</option>
                          <option value="30">Last 30 days</option>
                          <option value="90">Last 90 days</option>
                          <option value="120">Last 120 days</option>
                          <option value="365">Last 365 days</option>
                          <option value="custom">Custom range</option>
                        </select>
                        <p
                          style={{
                            ...sans,
                            margin: "6px 0 0",
                            fontSize: 11,
                            color: "var(--app-fg-secondary)",
                            lineHeight: 1.4,
                          }}
                        >
                          KPIs and risk widgets show current open findings; trend
                          widgets use this lookback period.
                        </p>
                      </div>
                    </div>
                    {definition.filters.dateRangePreset == null &&
                      (definition.filters.dateFrom != null ||
                        definition.filters.dateTo != null) && (
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 8,
                          }}
                        >
                          <input
                            type="date"
                            value={definition.filters.dateFrom ?? ""}
                            onChange={(e) =>
                              updateFilters({
                                dateFrom: e.target.value || null,
                              })
                            }
                            className="form-input"
                          />
                          <span
                            style={{
                              ...sans,
                              fontSize: 13,
                              color: "var(--app-fg-secondary)",
                            }}
                          >
                            to
                          </span>
                          <input
                            type="date"
                            value={definition.filters.dateTo ?? ""}
                            onChange={(e) =>
                              updateFilters({ dateTo: e.target.value || null })
                            }
                            className="form-input"
                          />
                        </div>
                      )}
                    <div className="form-row">
                      <label className="form-label">Asset type</label>
                      <p
                        style={{
                          ...sans,
                          fontSize: 12,
                          color: "var(--app-fg-secondary)",
                          marginBottom: 10,
                          marginTop: 0,
                        }}
                      >
                        Select types to filter by, then pick assets per type
                      </p>
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: 8,
                          marginBottom: 12,
                        }}
                      >
                        {(
                          ["image", "component", "unknown"] as ReportAssetType[]
                        ).map((t) => (
                          <label
                            key={t}
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: 6,
                              cursor: "pointer",
                              ...sans,
                              fontSize: 12,
                            }}
                          >
                            <input
                              type="checkbox"
                              checked={assetTypeFilter.includes(t)}
                              onChange={() => toggleAssetType(t)}
                            />
                            <span style={{ color: "var(--app-fg-secondary)" }}>
                              {ASSET_TYPE_LABELS[t]}
                            </span>
                            <span
                              style={{
                                color: "var(--app-fg-secondary)",
                                fontSize: 11,
                              }}
                            >
                              ({assetsByType[t].length})
                            </span>
                          </label>
                        ))}
                      </div>
                      {assetTypeFilter.length > 0 && (
                        <div
                          style={{
                            display: "flex",
                            flexDirection: "column",
                            gap: 8,
                          }}
                        >
                          {assetTypeFilter.map((t) => {
                            const assets = assetsByType[t];
                            if (assets.length === 0) return null;
                            const selectedSet = new Set(
                              definition.filters.repoFilter,
                            );
                            return (
                              <AssetTypeDropdown
                                key={t}
                                type={t}
                                label={ASSET_TYPE_LABELS[t]}
                                assets={assets}
                                selected={selectedSet}
                                onToggle={(name) => {
                                  const current = definition.filters.repoFilter;
                                  const next = current.includes(name)
                                    ? current.filter((x) => x !== name)
                                    : [...current, name];
                                  updateFilters({ repoFilter: next });
                                }}
                                style={VAT_BUTTON}
                              />
                            );
                          })}
                        </div>
                      )}
                    </div>
                    <div className="form-row">
                      <label className="form-label">
                        Severity filter (empty = all)
                      </label>
                      <div
                        style={{ display: "flex", flexWrap: "wrap", gap: 12 }}
                      >
                        {SEVERITY_OPTIONS.map((sev) => (
                          <label
                            key={sev}
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: 6,
                              cursor: "pointer",
                              ...sans,
                              fontSize: 12,
                            }}
                          >
                            <input
                              type="checkbox"
                              checked={definition.filters.severityFilter.includes(
                                sev,
                              )}
                              onChange={() => toggleSeverity(sev)}
                            />
                            <span
                              style={{
                                color: "var(--app-fg-secondary)",
                                textTransform: "capitalize",
                              }}
                            >
                              {sev}
                            </span>
                            <span
                              style={{
                                color: "var(--app-fg-secondary)",
                                fontSize: 11,
                              }}
                            >
                              (
                              {reportContext
                                ? reportContext.counts[
                                    sev as keyof typeof reportContext.counts
                                  ] ?? 0
                                : "—"}
                              )
                            </span>
                          </label>
                        ))}
                      </div>
                    </div>
                    <div className="form-row">
                      <label className="form-label">Notes (optional)</label>
                      <textarea
                        value={definition.filters.notes}
                        onChange={(e) =>
                          updateFilters({ notes: e.target.value })
                        }
                        placeholder="Add context or commentary..."
                        rows={2}
                        className="form-input"
                        style={{ resize: "vertical" }}
                      />
                    </div>
                    <label
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        cursor: "pointer",
                        marginTop: 12,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={definition.filters.external ?? false}
                        onChange={(e) =>
                          updateFilters({ external: e.target.checked })
                        }
                      />
                      <span
                        style={{
                          ...sans,
                          fontSize: 13,
                          color: "var(--app-fg-secondary)",
                        }}
                      >
                        External report (omit internal links)
                      </span>
                    </label>
                    <div
                      className="form-row"
                      style={{
                        borderTop: "1px solid var(--app-border)",
                        paddingTop: 16,
                        marginTop: 16,
                      }}
                    >
                      <label className="form-label">Load preset</label>
                      <div
                        style={{ display: "flex", flexWrap: "wrap", gap: 8 }}
                      >
                        {REPORT_PRESETS.map((p) => (
                          <button
                            key={p.id}
                            type="button"
                            onClick={() => loadPreset(p.id)}
                            className="btn"
                            style={{ padding: "6px 12px", fontSize: 12 }}
                          >
                            {p.name}
                          </button>
                        ))}
                      </div>
                      {savedPresets.length > 0 && (
                        <div style={{ marginTop: 12 }}>
                          <label className="form-label">Saved presets</label>
                          <div
                            style={{
                              display: "flex",
                              flexWrap: "wrap",
                              gap: 8,
                            }}
                          >
                            {savedPresets.map((p) => (
                              <span
                                key={p.id}
                                className="report-builder-canvas-card"
                                style={{ padding: "6px 10px" }}
                              >
                                <button
                                  type="button"
                                  onClick={() => loadPreset(p.id)}
                                  style={{
                                    ...sans,
                                    fontSize: 13,
                                    color: "var(--app-accent)",
                                    background: "none",
                                    border: "none",
                                    cursor: "pointer",
                                  }}
                                >
                                  {p.name}
                                </button>
                                <button
                                  type="button"
                                  onClick={() => deleteSavedPreset(p.id)}
                                  className="btn"
                                  style={{ padding: "2px 6px" }}
                                  aria-label={`Delete ${p.name}`}
                                >
                                  <Trash2 size={12} />
                                </button>
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {savedReports.length > 0 && (
                        <div style={{ marginTop: 12 }}>
                          <label className="form-label">Saved reports</label>
                          <div
                            style={{
                              display: "flex",
                              flexWrap: "wrap",
                              gap: 8,
                            }}
                          >
                            {savedReports.map((r) => (
                              <span
                                key={r.id}
                                className="report-builder-canvas-card"
                                style={{ padding: "6px 10px" }}
                              >
                                <button
                                  type="button"
                                  onClick={() => loadSavedReport(r.id)}
                                  style={{
                                    ...sans,
                                    fontSize: 13,
                                    color: "var(--app-accent)",
                                    background: "none",
                                    border: "none",
                                    cursor: "pointer",
                                  }}
                                >
                                  {r.name}
                                </button>
                                <button
                                  type="button"
                                  onClick={() => deleteSavedReport(r.id)}
                                  className="btn"
                                  style={{ padding: "2px 6px" }}
                                  aria-label={`Delete ${r.name}`}
                                >
                                  <Trash2 size={12} />
                                </button>
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Pages + Widgets + Canvas */}
                <div
                  className="report-builder-three-columns"
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr 1fr",
                    gap: 20,
                    minWidth: 400,
                  }}
                >
                  <div className="report-builder-section report-builder-section-grid">
                    <div className="report-builder-section-header">
                      <Layers size={14} />
                      Pages
                    </div>
                    <div className="report-builder-section-body">
                      <div
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          gap: 6,
                        }}
                      >
                        {definition.canvases.map((canvas, idx) => (
                          <div
                            key={canvas.id}
                            className={`report-builder-canvas-card ${
                              selectedCanvasId === canvas.id ? "selected" : ""
                            }`}
                          >
                            <input
                              value={canvas.name}
                              onChange={(e) =>
                                updateCanvasName(canvas.id, e.target.value)
                              }
                              onFocus={() => setSelectedCanvasId(canvas.id)}
                              onClick={() => setSelectedCanvasId(canvas.id)}
                              className="form-input"
                              style={{
                                flex: 1,
                                border: "none",
                                background: "transparent",
                              }}
                              placeholder="Page name"
                            />
                            <div style={{ display: "flex", gap: 2 }}>
                              <button
                                type="button"
                                onClick={() => reorderCanvas(canvas.id, "up")}
                                disabled={idx === 0}
                                style={{ ...VAT_BUTTON, padding: "4px 6px" }}
                              >
                                <ChevronUp size={12} />
                              </button>
                              <button
                                type="button"
                                onClick={() => reorderCanvas(canvas.id, "down")}
                                disabled={
                                  idx === definition.canvases.length - 1
                                }
                                style={{ ...VAT_BUTTON, padding: "4px 6px" }}
                              >
                                <ChevronDown size={12} />
                              </button>
                              <button
                                type="button"
                                onClick={() => removeCanvas(canvas.id)}
                                disabled={definition.canvases.length <= 1}
                                style={{
                                  ...VAT_BUTTON,
                                  padding: "4px 6px",
                                  color: "var(--app-danger)",
                                }}
                              >
                                <Trash2 size={12} />
                              </button>
                            </div>
                          </div>
                        ))}
                        <button
                          onClick={addCanvas}
                          className="btn"
                          style={{ width: "100%", justifyContent: "center" }}
                        >
                          <Plus size={14} /> Add page
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="report-builder-section report-builder-section-grid">
                    <div className="report-builder-section-header">
                      <LayoutTemplate size={14} />
                      Widgets
                    </div>
                    <div className="report-builder-section-body">
                      <p
                        style={{
                          ...sans,
                          fontSize: 12,
                          color: "var(--app-fg-secondary)",
                          marginBottom: 12,
                          marginTop: 0,
                        }}
                      >
                        Click to add to current page
                      </p>
                      <div
                        className="report-builder-widgets-list"
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          gap: 6,
                          minHeight: 320,
                          maxHeight: 320,
                          overflowY: "auto",
                        }}
                      >
                        {WIDGET_TYPES.map((type) => (
                          <button
                            key={type}
                            type="button"
                            onClick={() => addWidget(type)}
                            disabled={!currentCanvas}
                            className="report-builder-widget-card"
                            style={{ width: "100%", textAlign: "left" }}
                          >
                            <LayoutTemplate
                              size={14}
                              style={{
                                color: "var(--app-fg-secondary)",
                                flexShrink: 0,
                              }}
                            />
                            <span style={{ flex: 1 }}>
                              {WIDGET_TYPE_LABELS[type]}
                            </span>
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="report-builder-section report-builder-section-grid report-builder-section-widget-settings">
                    <div className="report-builder-section-header">
                      Widget settings
                    </div>
                    <div className="report-builder-section-body">
                      {!selectedWidget ? (
                        <p
                          style={{
                            ...sans,
                            fontSize: 13,
                            color: "var(--app-fg-secondary)",
                          }}
                        >
                          Select a widget on the canvas below to edit options.
                        </p>
                      ) : (
                        <WidgetConfigForm
                          widget={selectedWidget}
                          onUpdate={(patch) =>
                            updateWidgetConfig(selectedWidget.id, patch)
                          }
                        />
                      )}
                    </div>
                  </div>
                </div>

                {/* Canvas grid */}
                <div className="report-builder-section">
                  <div className="report-builder-section-header">
                    {currentCanvas ? currentCanvas.name : "Select a page"}
                  </div>
                  <div className="report-builder-section-body">
                    {currentCanvas && (
                      <p
                        style={{
                          ...sans,
                          fontSize: 12,
                          color: "var(--app-fg-secondary)",
                          marginBottom: 14,
                          marginTop: -4,
                        }}
                      >
                        {currentCanvas.widgets.length} widget
                        {currentCanvas.widgets.length !== 1 ? "s" : ""} — drag
                        to reposition
                      </p>
                    )}
                    {!currentCanvas ? (
                      <p
                        style={{
                          ...sans,
                          fontSize: 13,
                          color: "var(--app-fg-secondary)",
                        }}
                      >
                        Select or add a page.
                      </p>
                    ) : currentCanvas.widgets.length === 0 ? (
                      <p
                        style={{
                          ...sans,
                          fontSize: 13,
                          color: "var(--app-fg-secondary)",
                        }}
                      >
                        Click a widget type to add it.
                      </p>
                    ) : (
                      <CanvasGrid
                        widgets={currentCanvas.widgets}
                        selectedWidgetId={selectedWidgetId}
                        onSelectWidget={setSelectedWidgetId}
                        onReorderWidget={reorderWidget}
                        onRemoveWidget={removeWidget}
                        onLayoutChange={updateWidgetLayout}
                        onBatchLayoutChange={updateWidgetLayoutBatch}
                      />
                    )}
                    {!validation.valid && (
                      <div
                        style={{
                          marginTop: 16,
                          padding: 14,
                          borderRadius: 8,
                          border: "1px solid var(--app-danger)",
                          background:
                            "color-mix(in srgb, var(--app-danger) 12%, transparent)",
                        }}
                      >
                        <p
                          style={{
                            ...sans,
                            fontSize: 13,
                            fontWeight: 600,
                            color: "var(--app-danger)",
                            marginBottom: 6,
                          }}
                        >
                          Fix before exporting
                        </p>
                        <ul
                          style={{
                            ...sans,
                            fontSize: 13,
                            color: "var(--app-danger)",
                            margin: 0,
                            paddingLeft: 20,
                          }}
                        >
                          {validation.errors.map((e, i) => (
                            <li key={i}>{e}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </ResizablePanel>

          <ResizableHandle withHandle />

          <ResizablePanel
            ref={previewPanelRef}
            defaultSize={40}
            minSize={28}
            collapsible
            style={{
              display: "flex",
              flexDirection: "column",
              minWidth: 0,
              overflow: "hidden",
            }}
          >
            {previewMode === "float" ? (
              <div
                className="report-builder-preview-panel"
                style={{
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 16,
                }}
              >
                <p
                  style={{
                    ...sans,
                    fontSize: 14,
                    color: "var(--app-fg-secondary)",
                    textAlign: "center",
                    margin: 0,
                  }}
                >
                  Preview opens in a separate window. Drag it to another
                  monitor.
                </p>
                <div style={{ display: "flex", gap: 10 }}>
                  <button
                    onClick={openFloatPreviewWindow}
                    disabled={!previewHtml}
                    className="btn"
                  >
                    <Move size={16} /> Reopen window
                  </button>
                  <button
                    onClick={() => setPreviewMode("dock")}
                    className="btn"
                  >
                    <LayoutPanelTop size={16} /> Dock
                  </button>
                </div>
              </div>
            ) : (
              <div className="report-builder-preview-panel">
                <div className="report-builder-preview-header">
                  <div className="report-builder-preview-title">
                    Live preview <span>Updates as you edit</span>
                  </div>
                  <div className="report-builder-preview-actions">
                    <button
                      onClick={() => setPreviewMode("dock")}
                      className="btn-sm"
                    >
                      <LayoutPanelTop size={14} /> Dock
                    </button>
                    <button
                      onClick={() => {
                        openFloatPreviewWindow();
                        setPreviewMode("float");
                      }}
                      disabled={!previewHtml}
                      className="btn-sm"
                    >
                      <Move size={14} /> Float
                    </button>
                    {previewHtml && (
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 4,
                        }}
                      >
                        <button
                          onClick={() =>
                            setPreviewZoom((z) =>
                              z === "fit"
                                ? 0.75
                                : typeof z === "number"
                                  ? Math.max(0.25, z - 0.25)
                                  : 0.75,
                            )
                          }
                          className="btn-sm"
                        >
                          <ZoomOut size={14} />
                        </button>
                        <button
                          onClick={() => setPreviewZoom("fit")}
                          className="btn-sm"
                          style={{ minWidth: 52 }}
                        >
                          {previewZoom === "fit"
                            ? "Fit"
                            : `${Math.round((previewZoom as number) * 100)}%`}
                        </button>
                        <button
                          onClick={() =>
                            setPreviewZoom((z) =>
                              z === "fit"
                                ? 1.25
                                : typeof z === "number"
                                  ? Math.min(2, z + 0.25)
                                  : 1.25,
                            )
                          }
                          className="btn-sm"
                        >
                          <ZoomIn size={14} />
                        </button>
                      </div>
                    )}
                  </div>
                </div>
                <div
                  ref={previewContainerRef}
                  className="report-builder-preview-content"
                >
                  {previewHtml ? (
                    <div
                      style={{
                        width: Math.ceil(previewScale * iframeWidth),
                        height: Math.ceil(iframeHeight * previewScale),
                        position: "relative",
                        overflow: "visible",
                      }}
                    >
                      <iframe
                        key={`preview-${effectiveFilters.countMode}`}
                        title="Report preview"
                        srcDoc={previewHtml}
                        sandbox="allow-same-origin allow-scripts"
                        scrolling="no"
                        style={{
                          width: iframeWidth,
                          height: iframeHeight,
                          transform: `scale(${previewScale})`,
                          transformOrigin: "0 0",
                          border: "none",
                          display: "block",
                        }}
                      />
                    </div>
                  ) : (
                    <div
                      style={{
                        display: "flex",
                        height: "100%",
                        minHeight: 320,
                        alignItems: "center",
                        justifyContent: "center",
                        ...sans,
                        fontSize: 13,
                        color: "var(--app-fg-secondary)",
                      }}
                    >
                      {reportError ? "Preview unavailable" : "Loading report…"}
                    </div>
                  )}
                </div>
              </div>
            )}
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>

      {/* Modals */}
      <Modal
        open={savePresetOpen}
        onClose={() => setSavePresetOpen(false)}
        title="Save as preset"
        desc="Save the current report so you can load it later."
      >
        <div className="form-row">
          <label className="form-label">Preset name</label>
          <input
            value={savePresetName}
            onChange={(e) => setSavePresetName(e.target.value)}
            placeholder="e.g. Monthly board report"
            className="form-input"
            onKeyDown={(e) => e.key === "Enter" && saveCurrentAsPreset()}
          />
        </div>
        <div className="report-builder-modal-footer">
          <button onClick={() => setSavePresetOpen(false)} className="btn">
            Cancel
          </button>
          <button
            onClick={saveCurrentAsPreset}
            disabled={!savePresetName.trim()}
            className="btn btn-primary"
          >
            Save preset
          </button>
        </div>
      </Modal>

      <Modal
        open={saveReportOpen}
        onClose={() => setSaveReportOpen(false)}
        title="Save report"
        desc="Save the report definition. Load from Saved reports."
      >
        <div className="form-row">
          <label className="form-label">Report name</label>
          <input
            value={saveReportName}
            onChange={(e) => setSaveReportName(e.target.value)}
            placeholder={definition.title || "e.g. Monthly report"}
            className="form-input"
            onKeyDown={(e) => e.key === "Enter" && saveCurrentReport()}
          />
        </div>
        <div className="report-builder-modal-footer">
          <button onClick={() => setSaveReportOpen(false)} className="btn">
            Cancel
          </button>
          <button onClick={saveCurrentReport} className="btn btn-primary">
            Save report
          </button>
        </div>
      </Modal>

      <Modal
        open={emailDialogOpen}
        onClose={() => setEmailDialogOpen(false)}
        title="Email report"
        desc="Send the report as HTML email. Requires /api/report/email endpoint."
      >
        <div className="form-row">
          <label className="form-label">
            Recipients (comma- or space-separated)
          </label>
          <textarea
            value={emailRecipients}
            onChange={(e) => setEmailRecipients(e.target.value)}
            placeholder="team@example.com, security@example.com"
            rows={3}
            className="form-input"
            style={{ resize: "none" }}
            disabled={emailSending}
          />
        </div>
        <div className="report-builder-modal-footer">
          <button
            onClick={() => setEmailDialogOpen(false)}
            disabled={emailSending}
            className="btn"
          >
            Cancel
          </button>
          <button
            onClick={handleSendEmail}
            disabled={emailSending}
            className="btn btn-primary"
          >
            {emailSending ? "Sending…" : "Send"}
          </button>
        </div>
      </Modal>
    </div>
  );
}
