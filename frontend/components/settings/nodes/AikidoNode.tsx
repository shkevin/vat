"use client";

import { mono, sans } from "@/lib/styles";

export const AIKIDO_NODE = {
  adapter: "aikido",
  color: "#06b6d4",
  label: "Aikido",
  sublabel: "Source",
} as const;

interface AikidoNodeProps {
  x: number;
  y: number;
  width?: number;
  height?: number;
  selected?: boolean;
  onClick?: () => void;
}

/** Aikido source node visualization — used by the graph when this source is configured */
export function AikidoNode({
  x,
  y,
  width = 120,
  height = 60,
  selected = false,
  onClick,
}: AikidoNodeProps) {
  const cx = x + width / 2;
  return (
    <g
      className="flow-node flow-node-aikido"
      onClick={onClick}
      style={{ cursor: onClick ? "pointer" : "default" }}
    >
      <rect
        x={x}
        y={y}
        width={width}
        height={height}
        rx={6}
        fill="#0c1e38"
        stroke={selected ? "#3b82f6" : AIKIDO_NODE.color}
        strokeWidth={selected ? 2.5 : 2}
        filter="url(#glow)"
      />
      <text
        x={cx}
        y={y + height / 2 - 8}
        textAnchor="middle"
        fill={AIKIDO_NODE.color}
        style={{ ...mono, fontSize: 11, fontWeight: 700 }}
      >
        {AIKIDO_NODE.label}
      </text>
      <text
        x={cx}
        y={y + height / 2 + 8}
        textAnchor="middle"
        fill="#64748b"
        style={{ ...sans, fontSize: 9 }}
      >
        {AIKIDO_NODE.sublabel}
      </text>
    </g>
  );
}
