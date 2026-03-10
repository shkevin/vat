"use client";

import { mono } from "@/lib/styles";

interface AddSourceNodeProps {
  x: number;
  y: number;
  width?: number;
  height?: number;
  selected?: boolean;
  onClick?: () => void;
}

/** + Add Source node — click to add a new source (Aikido) */
export function AddSourceNode({
  x,
  y,
  width = 120,
  height = 36,
  selected = false,
  onClick,
}: AddSourceNodeProps) {
  const cx = x + width / 2;
  return (
    <g
      className="flow-node flow-node-add-source"
      onClick={onClick}
      style={{ cursor: "pointer" }}
    >
      <rect
        x={x}
        y={y}
        width={width}
        height={height}
        rx={6}
        fill="transparent"
        stroke={selected ? "#3b82f6" : "#334155"}
        strokeWidth={selected ? 2.5 : 1.5}
        strokeDasharray="4 4"
      />
      <text
        x={cx}
        y={y + height / 2 + 1}
        textAnchor="middle"
        fill="#64748b"
        style={{ ...mono, fontSize: 10 }}
      >
        + Add Source
      </text>
    </g>
  );
}
