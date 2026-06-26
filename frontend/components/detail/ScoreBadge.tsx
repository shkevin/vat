import React from "react";
import {
  scoreStyle,
  toneFromCvssScore,
  toneFromEpssScore,
  type ScoreTone,
} from "@/lib/scoreColors";

export function ScoreBadge({
  value,
  kind,
  size = "sm",
  prefix,
}: {
  value: string;
  kind: "cvss" | "epss";
  size?: "sm" | "lg";
  prefix?: string;
}) {
  const tone: ScoreTone =
    kind === "cvss" ? toneFromCvssScore(value) : toneFromEpssScore(value);
  const style = scoreStyle(tone);
  const sizeClass = size === "lg" ? " detail-panel-score-badge-lg" : "";
  return (
    <span
      className={`detail-panel-score-badge${sizeClass}`}
      style={style}
      title={tone}
    >
      {prefix ? `${prefix} ` : ""}
      {value}
    </span>
  );
}
