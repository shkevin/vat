import { SEV } from "@/lib/constants";

export type ScoreTone =
  | "Critical"
  | "High"
  | "Medium"
  | "Low"
  | "Informational";

export function parseNumericScore(
  value: string | number | null | undefined,
): number | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  const match = String(value).trim().match(/^(\d+(?:\.\d+)?)/);
  if (!match) return null;
  const parsed = Number(match[1]);
  return Number.isFinite(parsed) ? parsed : null;
}

/** CVSS base/environmental bands (0–10). */
export function toneFromCvssScore(
  value: string | number | null | undefined,
): ScoreTone {
  const score = parseNumericScore(value);
  if (score === null || score === 0) return "Informational";
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  if (score >= 0.1) return "Low";
  return "Informational";
}

/** EPSS exploit probability (0–1, or percent-style values > 1). */
export function toneFromEpssScore(
  value: string | number | null | undefined,
): ScoreTone {
  let score = parseNumericScore(value);
  if (score === null) return "Informational";
  if (score > 1) score = score / 100;
  if (score >= 0.7) return "Critical";
  if (score >= 0.4) return "High";
  if (score >= 0.1) return "Medium";
  if (score > 0) return "Low";
  return "Informational";
}

export function scoreStyle(tone: ScoreTone): {
  color: string;
  background: string;
  border: string;
} {
  const palette = SEV[tone] ?? SEV.Informational;
  return {
    color: palette.c,
    background: palette.bg,
    border: `1px solid ${palette.c}40`,
  };
}

export function metricPillClass(tone: ScoreTone): string {
  return `score-${tone.toLowerCase()}`;
}
