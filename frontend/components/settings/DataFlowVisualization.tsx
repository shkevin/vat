"use client";

import { mono, sans } from "@/lib/styles";
import { SOURCE_NODE_REGISTRY, TRACKER_NODE_REGISTRY } from "./nodes";
import { AikidoNode } from "./nodes/AikidoNode";
import { AddSourceNode } from "./nodes/AddSourceNode";
import { LinearNode } from "./nodes/LinearNode";
import type { Source } from "@/types";
import type { Tracker } from "@/types";

interface DataFlowVisualizationProps {
  sources: Source[];
  tracker: Tracker;
  onSourceClick?: (source: Source | null) => void;
  onTrackerClick?: () => void;
  onAddSourceClick?: () => void;
  onAddTrackerClick?: () => void;
  selectedSourceId?: string | null;
  selectedTracker?: boolean;
  selectedAddSource?: boolean;
  selectedAddTracker?: boolean;
}

/** Dynamic animated data flow diagram. Uses node visualization components per source/tracker type. */
export function DataFlowVisualization({
  sources,
  tracker,
  onSourceClick,
  onTrackerClick,
  onAddSourceClick,
  onAddTrackerClick,
  selectedSourceId,
  selectedTracker,
  selectedAddSource,
  selectedAddTracker,
}: DataFlowVisualizationProps) {
  const sourceNames = sources.length > 0 ? sources.map((s) => s.name).join(", ") : "No sources";
  const trackerName = tracker?.name ?? "No tracker";
  const sourceColor = sources[0] ? (SOURCE_NODE_REGISTRY[sources[0].adapter]?.color ?? sources[0].color) : "#475569";
  const trackerColor = tracker ? (TRACKER_NODE_REGISTRY[tracker.type]?.color ?? "#818cf8") : "#475569";

  // Resolve source node: use registry component if adapter matches, else generic
  const firstSource = sources[0];
  const SourceNodeComponent = firstSource && SOURCE_NODE_REGISTRY[firstSource.adapter]
    ? SOURCE_NODE_REGISTRY[firstSource.adapter].Component
    : null;

  const TrackerNodeComponent = tracker && TRACKER_NODE_REGISTRY[tracker.type]
    ? TRACKER_NODE_REGISTRY[tracker.type].Component
    : null;

  return (
    <div
      style={{
        background: "#070f1e",
        border: "1px solid #1a2540",
        borderRadius: 8,
        padding: 24,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          ...mono,
          fontSize: 9,
          fontWeight: 700,
          letterSpacing: "0.12em",
          color: "#1e3a5f",
          textTransform: "uppercase",
          marginBottom: 20,
        }}
      >
        Integration Data Flow
      </div>

      <svg
        viewBox="0 0 720 420"
        style={{ width: "100%", maxWidth: 720, height: "auto" }}
        className="vat-data-flow"
      >
        <defs>
          <linearGradient id="flowGrad1" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor={sourceColor} stopOpacity="0.3" />
            <stop offset="100%" stopColor={sourceColor} stopOpacity="1" />
          </linearGradient>
          <linearGradient id="flowGrad2" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor={trackerColor} stopOpacity="0.3" />
            <stop offset="100%" stopColor={trackerColor} stopOpacity="1" />
          </linearGradient>
          <linearGradient id="flowGrad3" x1="100%" y1="0%" x2="0%" y2="0%">
            <stop offset="0%" stopColor="#50c878" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#50c878" stopOpacity="1" />
          </linearGradient>
          <linearGradient id="flowGrad4" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#818cf8" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#818cf8" stopOpacity="1" />
          </linearGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* ── Step 1: Source → VAT (webhook, findings) ── */}
        {firstSource && SourceNodeComponent ? (
          <SourceNodeComponent
            x={20}
            y={60}
            selected={selectedSourceId === firstSource.id}
            onClick={() => onSourceClick?.(firstSource)}
          />
        ) : (
          <g
            className="flow-node flow-node-source"
            onClick={() => onAddSourceClick?.()}
            style={{ cursor: onAddSourceClick ? "pointer" : "default" }}
          >
            <rect x={20} y={60} width={120} height={60} rx={6} fill="#0c1e38" stroke="#475569" strokeWidth={2} />
            <text x={80} y={95} textAnchor="middle" fill="#64748b" style={{ ...mono, fontSize: 11 }}>—</text>
            <text x={80} y={112} textAnchor="middle" fill="#64748b" style={{ ...sans, fontSize: 9 }}>No source</text>
          </g>
        )}

        {onAddSourceClick && (
          <AddSourceNode x={20} y={135} selected={selectedAddSource} onClick={onAddSourceClick} />
        )}

        <g>
          <line x1={140} y1={90} x2={200} y2={90} stroke="url(#flowGrad1)" strokeWidth={2} strokeDasharray="6 4" className="flow-line flow-line-1" />
          <polygon points="200,90 192,86 192,94" fill={sourceColor} />
          <text x={170} y={80} textAnchor="middle" fill="#64748b" style={{ ...mono, fontSize: 8 }}>① webhook</text>
          <text x={170} y={72} textAnchor="middle" fill="#475569" style={{ ...mono, fontSize: 7 }}>findings</text>
        </g>

        {/* ── VAT Backend ── */}
        <g className="flow-node flow-node-vat">
          <rect x={200} y={40} width={200} height={100} rx={8} fill="#0c1e38" stroke="#38bdf8" strokeWidth={2} filter="url(#glow)" />
          <text x={300} y={70} textAnchor="middle" fill="#38bdf8" style={{ ...mono, fontSize: 12, fontWeight: 700 }}>VAT Backend</text>
          <text x={300} y={88} textAnchor="middle" fill="#64748b" style={{ ...sans, fontSize: 9 }}>Ingest → Dedup → DB</text>
          <text x={300} y={125} textAnchor="middle" fill="#475569" style={{ ...mono, fontSize: 8 }}>/webhook/aikido · /webhook/linear</text>
        </g>

        {/* ── Step 2: VAT → Tracker (create issue) ── */}
        <g>
          <line x1={400} y1={90} x2={460} y2={90} stroke="url(#flowGrad2)" strokeWidth={2} strokeDasharray="6 4" className="flow-line flow-line-2" />
          <polygon points="460,90 452,86 452,94" fill={trackerColor} />
          <text x={430} y={80} textAnchor="middle" fill="#64748b" style={{ ...mono, fontSize: 8 }}>② create issue</text>
          <text x={430} y={72} textAnchor="middle" fill="#475569" style={{ ...mono, fontSize: 7 }}>+ [VAT] template</text>
        </g>

        {/* ── Tracker node (uses registry component) ── */}
        {tracker && TrackerNodeComponent ? (
          <TrackerNodeComponent
            x={460}
            y={60}
            selected={selectedTracker}
            isAdd={false}
            onClick={onTrackerClick}
          />
        ) : (
          <LinearNode
            x={460}
            y={60}
            selected={selectedAddTracker}
            isAdd
            onClick={onAddTrackerClick}
          />
        )}

        {/* ── Step 3: Engineer comments ── */}
        <g className="flow-node flow-node-engineer">
          <rect x={460} y={135} width={120} height={40} rx={6} fill="#0c1e38" stroke="#50c878" strokeWidth={1.5} />
          <text x={520} y={158} textAnchor="middle" fill="#50c878" style={{ ...sans, fontSize: 9, fontWeight: 600 }}>③ Engineer adds [VAT] comment in Linear</text>
        </g>

        {/* ── Step 4: Tracker → VAT (comment webhook) ── */}
        <path d="M 520 135 L 520 180 L 300 180 L 300 140" fill="none" stroke="url(#flowGrad3)" strokeWidth={2} strokeDasharray="6 4" className="flow-line flow-line-3" />
        <polygon points="300,138 296,142 304,142" fill="#50c878" />
        <text x={410} y={175} textAnchor="middle" fill="#64748b" style={{ ...mono, fontSize: 8 }}>④ comment webhook</text>

        {/* ── Step 5: VAT → Tracker (post decision) ── */}
        <path d="M 400 140 L 460 140 L 460 120" fill="none" stroke="url(#flowGrad4)" strokeWidth={2} strokeDasharray="6 4" className="flow-line flow-line-4" />
        <polygon points="460,116 456,121 464,121" fill="#818cf8" />
        <text x={430} y={135} textAnchor="middle" fill="#64748b" style={{ ...mono, fontSize: 8 }}>⑤ post decision</text>

        {/* Flow path legend */}
        <g>
          <text x={360} y={220} textAnchor="middle" fill="#334155" style={{ ...mono, fontSize: 9, fontWeight: 700 }}>DATA FLOW PATH</text>
          <text x={360} y={238} textAnchor="middle" fill="#475569" style={{ ...sans, fontSize: 9 }}>
            ① Findings webhook → ② Create issue → ③ Engineer responds → ④ Comment webhook → ⑤ Decision posted
          </text>
        </g>
      </svg>

      <style>{`
        @keyframes flowDash {
          from { stroke-dashoffset: 0; }
          to { stroke-dashoffset: -20; }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.88; }
        }
        .vat-data-flow .flow-line-1,
        .vat-data-flow .flow-line-2,
        .vat-data-flow .flow-line-3,
        .vat-data-flow .flow-line-4 {
          stroke-dashoffset: 0;
          animation: flowDash 1.5s linear infinite;
        }
        .vat-data-flow .flow-node rect {
          transition: opacity 0.2s;
        }
        .vat-data-flow .flow-node:hover rect {
          opacity: 0.95;
        }
        .vat-data-flow .flow-node-aikido rect,
        .vat-data-flow .flow-node-source rect {
          animation: pulse 2.5s ease-in-out infinite;
        }
        .vat-data-flow .flow-node-vat rect {
          animation: pulse 2.5s ease-in-out infinite 0.3s;
        }
        .vat-data-flow .flow-node-linear rect,
        .vat-data-flow .flow-node-tracker rect {
          animation: pulse 2.5s ease-in-out infinite 0.6s;
        }
        .vat-data-flow .flow-node-add-source rect {
          transition: stroke 0.2s;
        }
        .vat-data-flow .flow-node-add-source:hover rect {
          stroke: #475569;
        }
      `}</style>

      <p
        style={{
          ...sans,
          fontSize: 11,
          color: "#475569",
          marginTop: 16,
          lineHeight: 1.5,
        }}
      >
        Findings flow from {sourceNames} via webhook into VAT. VAT deduplicates, persists, and creates {trackerName} issues with the [VAT] template. Engineers respond in {trackerName}; VAT parses comments via webhook and advances status. Reviewer decisions are posted back to {trackerName}.
      </p>
    </div>
  );
}
