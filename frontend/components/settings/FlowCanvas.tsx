"use client";

import { useCallback, useEffect, useMemo, useRef } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  useNodesState,
  useEdgesState,
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  Handle,
  Position,
  type NodeProps,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { mono, sans } from "@/lib/styles";
import type { Source } from "@/types";
import type { Tracker } from "@/types";
import type { IntegrationSchemas } from "@/lib/api";
import { displaySourceName } from "@/lib/utils";

const FLOW_STORAGE_KEY = "vat-integration-flow";

const SOURCE_NODE_X = 0;
const SOURCE_NODE_HEIGHT = 64;
const SOURCE_NODE_GAP = 12;
const ADD_SOURCE_OFFSET = 16;
const DEFAULT_LAYOUT = {
  vat: { x: 320, y: 40 },
  tracker: { x: 560, y: 80 },
  aikidoTracker: { x: 560, y: 60 },
  trackerLinear: { x: 560, y: 140 },
  engineer: { x: 560, y: 220 },
};

/** Aikido source node — pulse animation, shows source name (e.g. workspace) */
function AikidoFlowNode({ data, selected }: NodeProps) {
  const d = data as { source?: Source; brandColor?: string };
  const color = d?.brandColor ?? "var(--app-accent)";
  const label = displaySourceName(d?.source?.name) || "Aikido";
  return (
    <div
      className="vat-flow-node vat-flow-node-aikido"
      style={{
        background: "var(--app-node-bg)",
        border: `2px solid ${selected ? "var(--app-accent)" : color}`,
        borderRadius: 8,
        padding: "14px 20px",
        minWidth: 120,
      }}
    >
      <Handle
        type="source"
        position={Position.Right}
        style={{ background: color }}
      />
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          marginBottom: 4,
        }}
      >
        <span
          style={{ width: 8, height: 8, borderRadius: 4, background: color }}
        />
        <span
          style={{
            ...sans,
            fontSize: 13,
            fontWeight: 700,
            color: "var(--app-fg)",
          }}
        >
          {label}
        </span>
      </div>
      <div style={{ ...mono, fontSize: 9, color: "var(--app-muted)" }}>
        Source
      </div>
    </div>
  );
}

/** Generic source node (Trivy, Drata, etc.) or empty placeholder */
function EmptySourceNode({ data, selected }: NodeProps) {
  const d = data as { source?: Source; brandColor?: string };
  const color = d?.brandColor ?? d?.source?.color ?? "var(--app-muted)";
  const label =
    displaySourceName(d?.source?.name) ||
    displaySourceName(d?.source?.id) ||
    "—";
  const sublabel = d?.source ? "Source" : "No source";
  return (
    <div
      className="vat-flow-node vat-flow-node-empty"
      style={{
        background: "var(--app-node-bg)",
        border: `2px solid ${selected ? "var(--app-accent)" : color}`,
        borderRadius: 8,
        padding: "14px 20px",
        minWidth: 120,
      }}
    >
      <Handle
        type="source"
        position={Position.Right}
        style={{ background: color }}
      />
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          marginBottom: 4,
        }}
      >
        <span
          style={{ width: 8, height: 8, borderRadius: 4, background: color }}
        />
        <span
          style={{
            ...sans,
            fontSize: 13,
            fontWeight: 700,
            color: "var(--app-fg)",
          }}
        >
          {label}
        </span>
      </div>
      <div style={{ ...mono, fontSize: 9, color: "var(--app-muted)" }}>
        {sublabel}
      </div>
    </div>
  );
}

/** + Add Source node */
function AddSourceFlowNode({ data, selected }: NodeProps) {
  return (
    <div
      className="vat-flow-node vat-flow-node-add"
      style={{
        background: "transparent",
        border: `2px dashed ${
          selected ? "var(--app-accent)" : "var(--app-border)"
        }`,
        borderRadius: 8,
        padding: "14px 20px",
        minWidth: 120,
      }}
    >
      <div style={{ ...mono, fontSize: 11, color: "var(--app-muted)" }}>
        + Add Source
      </div>
    </div>
  );
}

/** VAT backend node — central hub, uses theme accent when no schema override */
function VATFlowNode({ data, selected }: NodeProps) {
  const color =
    (data as { brandColor?: string })?.brandColor ?? "var(--app-accent)";
  return (
    <div
      className="vat-flow-node vat-flow-node-vat"
      style={{
        background: "var(--app-node-bg)",
        border: `2px solid ${selected ? "var(--app-accent)" : color}`,
        borderRadius: 8,
        padding: "16px 24px",
        minWidth: 180,
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        style={{ background: color }}
      />
      <Handle
        type="source"
        position={Position.Right}
        style={{ background: color }}
      />
      <div
        style={{
          ...mono,
          fontSize: 12,
          fontWeight: 700,
          color,
          marginBottom: 6,
        }}
      >
        VAT Backend
      </div>
      <div style={{ ...sans, fontSize: 9, color: "var(--app-muted)" }}>
        Ingest → Dedup → DB
      </div>
    </div>
  );
}

/** Linear tracker node */
function LinearFlowNode({ data, selected }: NodeProps) {
  const d = data as { isAdd?: boolean; brandColor?: string };
  const isAdd = d?.isAdd ?? false;
  const color = d?.brandColor ?? "var(--app-accent)";
  return (
    <div
      className="vat-flow-node vat-flow-node-linear"
      style={{
        background: isAdd ? "transparent" : "var(--app-node-bg)",
        borderWidth: 2,
        borderStyle: isAdd ? "dashed" : "solid",
        borderColor: selected
          ? "var(--app-accent)"
          : isAdd
            ? "var(--app-border)"
            : color,
        borderRadius: 8,
        padding: "14px 20px",
        minWidth: 120,
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        style={{ background: color }}
      />
      <Handle
        type="source"
        position={Position.Right}
        id="right"
        style={{ background: color }}
      />
      <Handle
        type="source"
        position={Position.Bottom}
        id="bottom"
        style={{ background: color }}
      />
      <div
        style={{
          ...sans,
          fontSize: 13,
          fontWeight: 700,
          color: isAdd ? "var(--app-muted)" : "var(--app-fg)",
        }}
      >
        {isAdd ? "+ Add Tracker" : "Linear"}
      </div>
      <div style={{ ...mono, fontSize: 9, color: "var(--app-muted)" }}>
        {isAdd ? "Click to add" : "Tracker"}
      </div>
    </div>
  );
}

/** Aikido Tracker node — shown when useAikidoTracking is on. Tracking comes from Aikido's Linear integration. */
function AikidoTrackerFlowNode({ data, selected }: NodeProps) {
  const d = data as { brandColor?: string };
  const color = d?.brandColor ?? "#10B981";
  return (
    <div
      className="vat-flow-node vat-flow-node-aikido-tracker"
      style={{
        background: "var(--app-node-bg)",
        border: `2px solid ${selected ? "var(--app-accent)" : color}`,
        borderRadius: 8,
        padding: "14px 20px",
        minWidth: 140,
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        style={{ background: color }}
      />
      <div
        style={{
          ...sans,
          fontSize: 13,
          fontWeight: 700,
          color: "var(--app-fg)",
        }}
      >
        Aikido Tracker
      </div>
      <div style={{ ...mono, fontSize: 9, color: "var(--app-muted)" }}>
        Linear (via Aikido)
      </div>
    </div>
  );
}

/** Engineer node — tracker feedback flow */
function EngineerFlowNode({ data, selected }: NodeProps) {
  const color =
    (data as { brandColor?: string })?.brandColor ?? "var(--app-success)";
  return (
    <div
      className="vat-flow-node vat-flow-node-engineer"
      style={{
        background: "var(--app-node-bg)",
        border: `1.5px solid ${selected ? "var(--app-accent)" : color}`,
        borderRadius: 8,
        padding: "10px 16px",
        minWidth: 180,
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ background: color }}
      />
      <Handle
        type="source"
        position={Position.Left}
        style={{ background: color }}
      />
      <div style={{ ...sans, fontSize: 9, fontWeight: 600, color }}>
        ③ Engineer adds [VAT] comment in Linear
      </div>
    </div>
  );
}

const nodeTypes = {
  aikido: AikidoFlowNode,
  emptySource: EmptySourceNode,
  addSource: AddSourceFlowNode,
  vat: VATFlowNode,
  linear: LinearFlowNode,
  aikidoTracker: AikidoTrackerFlowNode,
  engineer: EngineerFlowNode,
};

interface FlowCanvasProps {
  sources: Source[];
  tracker: Tracker;
  integrationSchemas?: IntegrationSchemas | null;
  onSourceClick?: (source: Source) => void;
  onTrackerClick?: () => void;
  onAddSourceClick?: () => void;
  onAddTrackerClick?: () => void;
  onVatClick?: () => void;
  onPaneClick?: () => void;
  selectedSourceId?: string | null;
  selectedTracker?: boolean;
  selectedAddSource?: boolean;
  selectedAddTracker?: boolean;
  selectedVat?: boolean;
}

function FlowCanvasInner({
  sources,
  tracker,
  integrationSchemas,
  onSourceClick,
  onTrackerClick,
  onAddSourceClick,
  onAddTrackerClick,
  onVatClick,
  onPaneClick,
  selectedSourceId,
  selectedTracker,
  selectedAddSource,
  selectedAddTracker,
  selectedVat,
}: FlowCanvasProps) {
  const rfInstanceRef = useRef<{
    toObject: () => {
      nodes: Node[];
      edges: Edge[];
      viewport: { x: number; y: number; zoom: number };
    };
    setViewport: (v: { x: number; y: number; zoom: number }) => void;
  } | null>(null);

  const sourceBrandColor = (adapter: string) =>
    integrationSchemas?.sources?.find((s) => s.adapter_key === adapter)
      ?.brand_color;
  const trackerBrandColor = (adapter: string) =>
    integrationSchemas?.trackers?.find((t) => t.adapter_key === adapter)
      ?.brand_color;
  const flowColor = (key: string) =>
    integrationSchemas?.flow_types?.[key]?.color;

  const buildInitialNodes = useCallback((): Node[] => {
    const stored =
      typeof window !== "undefined"
        ? localStorage.getItem(FLOW_STORAGE_KEY)
        : null;
    let positions: Record<string, { x: number; y: number }> = {};
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        positions = (parsed.nodes || []).reduce(
          (acc: Record<string, { x: number; y: number }>, n: Node) => {
            acc[n.id] = n.position;
            return acc;
          },
          {},
        );
      } catch {
        // ignore
      }
    }

    const pos = (id: string, fallback: { x: number; y: number }) =>
      positions[id] ?? fallback;

    const sourceNodes: Node[] = sources.map((src, i) => {
      const nodeId = `source-${src.id}`;
      const y = 40 + i * (SOURCE_NODE_HEIGHT + SOURCE_NODE_GAP);
      const nodeType = src.adapter === "aikido" ? "aikido" : "emptySource";
      const brandColor = sourceBrandColor(src.adapter) ?? src.color;
      return {
        id: nodeId,
        type: nodeType,
        position: { x: SOURCE_NODE_X, y },
        data: { source: src, brandColor },
        selected: selectedSourceId === src.id,
      };
    });

    const addSourceY =
      sources.length > 0
        ? 40 +
          sources.length * (SOURCE_NODE_HEIGHT + SOURCE_NODE_GAP) +
          ADD_SOURCE_OFFSET
        : 80;
    const addSourceNode: Node = {
      id: "addSource",
      type: "addSource",
      position: { x: SOURCE_NODE_X, y: addSourceY },
      data: {},
      selected: selectedAddSource,
    };

    const linearColor = trackerBrandColor("linear");
    const aikidoColor = "#10B981";
    const feedbackColor = flowColor("tracker_feedback");
    const useAikidoTracking = Boolean(tracker?.useAikidoTracking);

    const nodes: Node[] = [
      ...sourceNodes,
      addSourceNode,
      {
        id: "vat",
        type: "vat",
        position: pos("vat", DEFAULT_LAYOUT.vat),
        data: {},
        selected: selectedVat ?? false,
      },
    ];

    if (useAikidoTracking) {
      nodes.push({
        id: "tracker-aikido",
        type: "aikidoTracker",
        position: pos("tracker-aikido", DEFAULT_LAYOUT.aikidoTracker),
        data: { brandColor: aikidoColor },
        selected: selectedTracker ?? false,
      });
      nodes.push({
        id: "tracker-linear",
        type: "linear",
        position: pos("tracker-linear", DEFAULT_LAYOUT.trackerLinear),
        data: { isAdd: !tracker?.name, brandColor: linearColor },
        selected: tracker?.name
          ? selectedTracker ?? false
          : selectedAddTracker ?? false,
      });
    } else {
      nodes.push({
        id: "tracker",
        type: "linear",
        position: pos("tracker", DEFAULT_LAYOUT.tracker),
        data: { isAdd: !tracker?.name, brandColor: linearColor },
        selected: tracker?.name ? selectedTracker : selectedAddTracker,
      });
    }

    if (tracker?.name && (useAikidoTracking || !useAikidoTracking)) {
      nodes.push({
        id: "engineer",
        type: "engineer",
        position: pos("engineer", DEFAULT_LAYOUT.engineer),
        data: { brandColor: feedbackColor },
        selected: false,
      });
    }
    return nodes;
  }, [
    sources,
    tracker,
    selectedSourceId,
    selectedTracker,
    selectedAddSource,
    selectedAddTracker,
    selectedVat,
    integrationSchemas,
  ]);

  const buildInitialEdges = useCallback((): Edge[] => {
    const ingestColor = flowColor("ingest");
    const syncColor = flowColor("sync_to_tracker");
    const feedbackColor = flowColor("tracker_feedback");
    const aikidoColor = "#10B981";

    const edges: Edge[] = [];
    if (sources.length > 0) {
      sources.forEach((src) => {
        const stroke =
          ingestColor ??
          sourceBrandColor(src.adapter) ??
          src.color ??
          "var(--app-accent)";
        edges.push({
          id: `e-source-${src.id}`,
          source: `source-${src.id}`,
          target: "vat",
          animated: true,
          style: { stroke, strokeDasharray: "6 4" },
        });
      });
    }
    const useAikidoTracking = Boolean(tracker?.useAikidoTracking);
    if (useAikidoTracking) {
      edges.push({
        id: "e2-aikido",
        source: "vat",
        target: "tracker-aikido",
        animated: true,
        style: {
          stroke: aikidoColor ?? "var(--app-accent)",
          strokeDasharray: "6 4",
        },
      });
      if (tracker?.name) {
        edges.push({
          id: "e2-linear",
          source: "vat",
          target: "tracker-linear",
          animated: true,
          style: {
            stroke: syncColor ?? "var(--app-accent)",
            strokeDasharray: "6 4",
          },
        });
        edges.push(
          {
            id: "e3",
            source: "tracker-linear",
            target: "engineer",
            sourceHandle: "bottom",
            animated: true,
            style: {
              stroke: feedbackColor ?? "var(--app-success)",
              strokeDasharray: "6 4",
            },
          },
          {
            id: "e4",
            source: "engineer",
            target: "vat",
            animated: true,
            style: {
              stroke: feedbackColor ?? "var(--app-success)",
              strokeDasharray: "6 4",
            },
          },
        );
      }
    } else if (tracker?.name) {
      edges.push({
        id: "e2",
        source: "vat",
        target: "tracker",
        animated: true,
        style: {
          stroke: syncColor ?? "var(--app-accent)",
          strokeDasharray: "6 4",
        },
      });
      edges.push(
        {
          id: "e3",
          source: "tracker",
          target: "engineer",
          sourceHandle: "bottom",
          animated: true,
          style: {
            stroke: feedbackColor ?? "var(--app-success)",
            strokeDasharray: "6 4",
          },
        },
        {
          id: "e4",
          source: "engineer",
          target: "vat",
          animated: true,
          style: {
            stroke: feedbackColor ?? "var(--app-success)",
            strokeDasharray: "6 4",
          },
        },
      );
    }
    return edges;
  }, [sources, tracker, integrationSchemas]);

  const initialNodes = useMemo(() => buildInitialNodes(), [buildInitialNodes]);
  const initialEdges = useMemo(() => buildInitialEdges(), [buildInitialEdges]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync nodes when sources/tracker/selection changes
  // Source nodes and addSource: always use computed positions (no overlap)
  // VAT, tracker, engineer: preserve user-dragged positions
  useEffect(() => {
    setNodes((prev) => {
      const next = buildInitialNodes();
      return next.map((n) => {
        const isSourceOrAdd =
          n.id.startsWith("source-") || n.id === "addSource";
        if (isSourceOrAdd) return n;
        const existing = prev.find((p) => p.id === n.id);
        return existing ? { ...n, position: existing.position } : n;
      });
    });
  }, [buildInitialNodes, setNodes]);

  // Sync edges when tracker changes (engineer node appears/disappears)
  useEffect(() => {
    setEdges(buildInitialEdges());
  }, [buildInitialEdges, setEdges]);

  // Persist on nodes change (drag)
  const onSave = useCallback(() => {
    const rf = rfInstanceRef.current;
    if (rf?.toObject) {
      try {
        const obj = rf.toObject();
        localStorage.setItem(FLOW_STORAGE_KEY, JSON.stringify(obj));
      } catch {
        // fallback to nodes/edges only
        localStorage.setItem(
          FLOW_STORAGE_KEY,
          JSON.stringify({ nodes, edges, viewport: { x: 0, y: 0, zoom: 1 } }),
        );
      }
    } else {
      localStorage.setItem(
        FLOW_STORAGE_KEY,
        JSON.stringify({ nodes, edges, viewport: { x: 0, y: 0, zoom: 1 } }),
      );
    }
  }, [nodes, edges]);

  useEffect(() => {
    onSave();
  }, [nodes, onSave]);

  const onInit = useCallback(
    (instance: {
      toObject: () => {
        nodes: Node[];
        edges: Edge[];
        viewport: { x: number; y: number; zoom: number };
      };
      setViewport: (v: { x: number; y: number; zoom: number }) => void;
      fitView?: (opts?: { padding?: number; duration?: number }) => void;
    }) => {
      rfInstanceRef.current = instance;
      requestAnimationFrame(() => {
        (
          instance as {
            fitView?: (opts?: { padding?: number; duration?: number }) => void;
          }
        ).fitView?.({ padding: 0.35, duration: 300 });
      });
    },
    [],
  );

  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      if (node.id.startsWith("source-")) {
        const src = node.data?.source as Source | undefined;
        if (src) onSourceClick?.(src);
      } else if (node.id === "addSource") {
        onAddSourceClick?.();
      } else if (node.id === "vat") {
        onVatClick?.();
      } else if (node.id === "tracker-aikido") {
        onTrackerClick?.();
      } else if (node.id === "tracker-linear") {
        if (tracker?.name) onTrackerClick?.();
        else onAddTrackerClick?.();
      } else if (node.id === "tracker") {
        if (tracker?.name) onTrackerClick?.();
        else onAddTrackerClick?.();
      }
    },
    [
      onSourceClick,
      onTrackerClick,
      onAddSourceClick,
      onAddTrackerClick,
      onVatClick,
      tracker,
    ],
  );

  /** Only clear selection when clicking the pane background, not when clicking a node (event bubbles). */
  const handlePaneClick = useCallback(
    (event: React.MouseEvent) => {
      if ((event.target as HTMLElement)?.closest?.(".react-flow__node")) return;
      onPaneClick?.();
    },
    [onPaneClick],
  );

  const onMoveEnd = useCallback(() => {
    const rf = rfInstanceRef.current;
    if (rf?.toObject) {
      try {
        const obj = rf.toObject();
        localStorage.setItem(FLOW_STORAGE_KEY, JSON.stringify(obj));
      } catch {
        // ignore
      }
    }
  }, []);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={onNodeClick}
      onPaneClick={handlePaneClick}
      onInit={onInit}
      onMoveEnd={onMoveEnd}
      nodeTypes={nodeTypes}
      fitView={false}
      fitViewOptions={{ padding: 0.35, duration: 300 }}
      minZoom={0.2}
      maxZoom={2}
      nodesDraggable
      nodesConnectable={false}
      elementsSelectable
      panOnDrag
      zoomOnScroll
      zoomOnPinch
      preventScrolling={false}
      style={{ background: "var(--app-bg)" }}
      className="vat-react-flow dark"
    >
      <Background
        variant={BackgroundVariant.Dots}
        color="var(--app-border)"
        gap={20}
        size={1}
      />
      <Controls
        position="bottom-left"
        showZoom
        showFitView
        showInteractive={false}
        fitViewOptions={{ padding: 0.25, duration: 300 }}
        className="vat-flow-controls"
      />
      <MiniMap
        position="bottom-right"
        nodeColor={(node) => {
          const d = node.data as { source?: Source; brandColor?: string };
          if (d?.brandColor) return d.brandColor;
          const src = d?.source;
          if (src?.color) return src.color;
          const type = node.type as string;
          const id = node.id as string;
          if (type === "aikido") return "var(--app-accent)";
          if (type === "vat") return "var(--app-accent)";
          if (id === "tracker-aikido") return "#10B981";
          if (type === "linear") return "var(--app-accent)";
          if (type === "engineer") return "var(--app-success)";
          return "var(--app-muted)";
        }}
        nodeStrokeColor="var(--app-bg)"
        maskColor="rgba(0,0,0,0.6)"
        maskStrokeColor="var(--app-border)"
        maskStrokeWidth={1}
        bgColor="var(--app-node-bg)"
        pannable
        zoomable
        ariaLabel="Integration flow overview"
      />
      <style>{`
        .vat-react-flow .react-flow__background { background: var(--app-bg) !important; }
        .vat-react-flow .react-flow__edge-path { stroke-width: 2; pointer-events: none; }
        .vat-react-flow .react-flow__edge { pointer-events: none; }
        .vat-react-flow .react-flow__controls {
          box-shadow: 0 2px 8px rgba(0,0,0,0.4);
          border-radius: 6px;
          overflow: hidden;
        }
        .vat-react-flow .react-flow__controls-button {
          background: var(--app-node-bg) !important;
          color: var(--app-muted) !important;
          border-color: var(--app-border) !important;
          fill: var(--app-muted) !important;
        }
        .vat-react-flow .react-flow__controls-button:hover {
          background: var(--app-card-bg) !important;
          color: var(--app-fg) !important;
          fill: var(--app-fg) !important;
        }
        .vat-react-flow .react-flow__minimap {
          border-radius: 8px;
          overflow: hidden;
          box-shadow: 0 2px 12px rgba(0,0,0,0.4);
          border: 1px solid var(--app-border);
        }
        @keyframes vat-pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.88; }
        }
        .vat-flow-node-aikido, .vat-flow-node-empty, .vat-flow-node-vat, .vat-flow-node-linear { animation: vat-pulse 2.5s ease-in-out infinite; }
        .vat-flow-node-vat { animation-delay: 0.3s; }
        .vat-flow-node-linear { animation-delay: 0.6s; }
      `}</style>
    </ReactFlow>
  );
}

export function FlowCanvas(props: FlowCanvasProps) {
  return (
    <div
      style={{
        height: "100%",
        minHeight: 400,
        background: "var(--app-bg)",
        border: "1px solid var(--app-border)",
        borderRadius: 10,
        overflow: "hidden",
        boxShadow: "inset 0 0 0 1px var(--app-border-subtle)",
      }}
    >
      <ReactFlowProvider>
        <FlowCanvasInner {...props} />
      </ReactFlowProvider>
    </div>
  );
}
