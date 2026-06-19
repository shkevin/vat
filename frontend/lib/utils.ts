/** Classification banner colors for security labels. */
export function getClassificationColor(classification: string): string {
  const u = (classification || "").toUpperCase();
  if (u.includes("SECRET") && u.includes("TOP"))
    return "var(--app-classification-topsecret)";
  if (u.includes("SECRET")) return "var(--app-classification-secret)";
  if (u.includes("CONFIDENTIAL"))
    return "var(--app-classification-confidential)";
  if (u.includes("CUI") || u.includes("CONTROLLED"))
    return "var(--app-classification-cui)";
  return "var(--app-classification-unclassified)";
}

export function makeFingerprint(cveId: string, component: string): string {
  const s = `${(cveId || "").toLowerCase()}|${(component || "")
    .toLowerCase()
    .replace(/:\S+/, "")}`;
  let h = 0;
  for (const c of s) {
    h = (h << 5) - h + c.charCodeAt(0);
    h |= 0;
  }
  return Math.abs(h).toString(16).padStart(8, "0");
}

export const now = () => new Date().toISOString();

/** Strip vat-local- and folder-scan- prefixes for display; do not differentiate scanners by origin. */
export function displaySourceName(name: string | null | undefined): string {
  if (!name) return "";
  const normalized = name.replace(/^(vat-local-|folder-scan-)/i, "").trim() || name;
  const key = normalized.toLowerCase();
  if (key === "vuln_feed_match") return "Feed Match";
  return normalized;
}

export function fmtDt(s: string | null | undefined): string {
  if (!s) return "—";
  try {
    return new Date(s).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  } catch {
    return s;
  }
}

export function fmtDtSm(s: string | null | undefined): string {
  if (!s) return "—";
  try {
    return new Date(s).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
    });
  } catch {
    return s;
  }
}

export function daysLeft(d: string | null | undefined): number | null {
  if (!d) return null;
  return Math.ceil((new Date(d).getTime() - Date.now()) / 86400000);
}

export function slaDot(due: string | null | undefined, status: string): string {
  if (!isOpenRisk(status)) return "#334155";
  const d = daysLeft(due);
  if (d === null) return "#334155";
  return d < 0
    ? "#f87060"
    : d < 2
      ? "#f87060"
      : d < 7
        ? "#f5a623"
        : d < 14
          ? "#f5d020"
          : "#334155";
}

export function getSlaDays(
  type: string,
  severity: string,
  slaDays: Record<string, Record<string, number>>,
): number {
  return (slaDays[type] || slaDays.SCA)?.[severity] ?? 30;
}

import { FINDING_TYPES, LICENSE_RISK } from "./constants";
import {
  isOpenRisk,
  isOverdueOpenRisk,
  isRiskAccepted,
} from "./metricSemantics";
import type { Finding } from "@/types";

/** Display title — when title equals numeric cveId (Aikido issue ID), show descriptive fallback. */
export function displayTitle(f: Finding): string {
  const t = f.title ?? "";
  const id = f.cveId ?? "";
  if (!t || !id || t !== id) return t || id || "—";
  if (!/^\d+$/.test(id)) return t;
  const typeLabel = FINDING_TYPES[f.findingType]?.label ?? f.findingType;
  const loc = f.image ?? f.component;
  return loc ? `${typeLabel} in ${loc}` : typeLabel;
}

export function licenseRisk(id: string): string {
  return LICENSE_RISK[id] || "Informational";
}

export interface Alert {
  type: string;
  severity: string;
  fId?: string;
  msg: string;
  waiverRef?: string;
  d?: number;
}

export function computeAlerts(
  findings: Array<{
    archived?: boolean;
    status?: string;
    attestation?: {
      expiresAt?: string;
      waiverRef?: string;
      approver?: string;
    } | null;
    slaDue?: string;
    trackerComment?: boolean;
    cveId?: string;
    title?: string;
    findingType?: string;
    regressionCount?: number;
    id?: string;
  }>,
  daysLeftFn: (d: string | null | undefined) => number | null,
): Alert[] {
  const alerts: Alert[] = [];
  const active = findings.filter((f) => !f.archived);

  active
    .filter((f) => isRiskAccepted(f.status) && f.attestation?.expiresAt)
    .forEach((f) => {
      const exp = f.attestation?.expiresAt;
      if (exp && daysLeftFn(exp) !== null && daysLeftFn(exp)! < 0)
        alerts.push({
          type: "expired-waiver",
          severity: "High",
          fId: f.id,
          msg: `Waiver expired: ${f.cveId} — risk acceptance by ${
            f.attestation?.approver || "reviewer"
          } expired ${Math.abs(daysLeftFn(exp)!)}d ago`,
          waiverRef: f.attestation?.waiverRef,
        });
    });

  active
    .filter((f) => isRiskAccepted(f.status) && f.attestation?.expiresAt)
    .forEach((f) => {
      const exp = f.attestation?.expiresAt;
      if (!exp) return;
      const d = daysLeftFn(exp);
      if (d !== null && d >= 0 && d <= 30)
        alerts.push({
          type: "waiver-expiring",
          severity: d <= 7 ? "High" : "Medium",
          fId: f.id,
          msg: `Waiver expiring in ${d}d: ${f.cveId} (${
            f.attestation?.waiverRef || "no ref"
          })`,
          d,
        });
    });

  active
    .filter(
      (f) => isOpenRisk(f.status) && f.slaDue && !f.trackerComment,
    )
    .forEach((f) => {
      const d = daysLeftFn(f.slaDue);
      if (d !== null && d >= 0 && d <= 2)
        alerts.push({
          type: "sla-48h",
          severity: "High",
          fId: f.id,
          msg: `SLA breach in ${d}d — no engineer comment: ${f.cveId} (${
            (f as { trackerId?: string }).trackerId || "no ticket"
          })`,
        });
    });

  active
    .filter((f) => isOverdueOpenRisk(f.status, f.slaDue))
    .forEach((f) => {
      const d = daysLeftFn(f.slaDue);
      if (d !== null && d < 0)
        alerts.push({
          type: "overdue",
          severity: "Critical",
          fId: f.id,
          msg: `${Math.abs(d)}d overdue: ${f.cveId} — ${(f.title || "").slice(
            0,
            50,
          )}`,
        });
    });

  active
    .filter((f) => f.status === "Reopened")
    .forEach((f) => {
      alerts.push({
        type: "regression",
        severity: "High",
        fId: f.id,
        msg: `Regression detected: ${f.cveId} was previously resolved (count: ${
          f.regressionCount || 0
        })`,
      });
    });

  active
    .filter((f) => f.findingType === "Secret" && isOpenRisk(f.status))
    .forEach((f) => {
      alerts.push({
        type: "secret-open",
        severity: "Critical",
        fId: f.id,
        msg: `URGENT — Open secret: ${(f.title || "").slice(
          0,
          60,
        )} — rotate immediately`,
      });
    });

  const so: Record<string, number> = {
    Critical: 0,
    High: 1,
    Medium: 2,
    Low: 3,
  };
  return alerts.sort((a, b) => (so[a.severity] ?? 4) - (so[b.severity] ?? 4));
}
