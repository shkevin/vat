"use client";

import { mono, sans } from "@/lib/styles";

export const LINEAR_NODE = {
  type: "linear",
  color: "#818cf8",
  icon: "◈",
  label: "Linear",
  sublabel: "Tracker",
} as const;

interface LinearNodeProps {
  x: number;
  y: number;
  width?: number;
  height?: number;
  selected?: boolean;
  isAdd?: boolean;
  onClick?: () => void;
}

/** Linear tracker node visualization — used by the graph when this tracker is configured */
export function LinearNode({
  x,
  y,
  width = 120,
  height = 60,
  selected = false,
  isAdd = false,
  onClick,
}: LinearNodeProps) {
  const cx = x + width / 2;
  const color = isAdd ? "#475569" : LINEAR_NODE.color;
  return (
    <g
      className="flow-node flow-node-linear"
      onClick={onClick}
      style={{ cursor: onClick ? "pointer" : "default" }}
    >
      <rect
        x={x}
        y={y}
        width={width}
        height={height}
        rx={6}
        fill={isAdd ? "transparent" : "#0c1e38"}
        stroke={selected ? "#3b82f6" : color}
        strokeWidth={selected ? 2.5 : isAdd ? 1.5 : 2}
        strokeDasharray={isAdd ? "4 4" : undefined}
        filter={isAdd ? undefined : "url(#glow)"}
      />
      <text
        x={cx}
        y={y + height / 2 - 8}
        textAnchor="middle"
        fill={color}
        style={{ ...mono, fontSize: 11, fontWeight: 700 }}
      >
        {isAdd ? "+ Add Tracker" : LINEAR_NODE.label}
      </text>
      <text
        x={cx}
        y={y + height / 2 + 8}
        textAnchor="middle"
        fill="#64748b"
        style={{ ...sans, fontSize: 9 }}
      >
        {isAdd ? "Click to add" : LINEAR_NODE.sublabel}
      </text>
    </g>
  );
}
