"use client";

import { TypeTag, SevTag } from "@/components/atoms";
import { mono, sans } from "@/lib/styles";
import { daysLeft, displayTitle, fmtDt } from "@/lib/utils";
import type { Finding } from "@/types";

interface WaiversTabProps {
  waivers: Finding[];
  onSelect: (f: Finding) => void;
}

type WaiverSection = "expired" | "expiring" | "healthy";

function getSection(f: Finding): WaiverSection {
  const exp = f.attestation?.expiresAt;
  if (!exp) return "healthy";
  const d = daysLeft(exp);
  if (d === null) return "healthy";
  if (d < 0) return "expired";
  if (d <= 30) return "expiring";
  return "healthy";
}

const SECTION_LABELS: Record<WaiverSection, { label: string; color: string }> =
  {
    expired: { label: "Expired — Action Required", color: "var(--app-danger)" },
    expiring: { label: "Expiring within 30 days", color: "var(--app-warning)" },
    healthy: { label: "Healthy", color: "var(--app-success)" },
  };

export function WaiversTab({ waivers, onSelect }: WaiversTabProps) {
  const bySection = waivers.reduce(
    (acc, f) => {
      const s = getSection(f);
      if (!acc[s]) acc[s] = [];
      acc[s].push(f);
      return acc;
    },
    {} as Record<WaiverSection, Finding[]>,
  );

  const order: WaiverSection[] = ["expired", "expiring", "healthy"];

  return (
    <div>
      <div
        style={{
          ...mono,
          fontSize: 9,
          fontWeight: 700,
          letterSpacing: "0.12em",
          color: "var(--app-muted)",
          textTransform: "uppercase",
          marginBottom: 14,
        }}
      >
        Waivers — {waivers.length} Risk Accepted
      </div>

      {waivers.length === 0 ? (
        <div
          style={{
            ...sans,
            fontSize: 13,
            color: "var(--app-muted)",
            padding: "48px 0",
            textAlign: "center",
          }}
        >
          No risk-accepted findings with attestation.
        </div>
      ) : (
        order.map((section) => {
          const items = bySection[section] ?? [];
          if (items.length === 0) return null;

          const { label, color } = SECTION_LABELS[section];
          return (
            <div key={section} style={{ marginBottom: 24 }}>
              <div
                style={{
                  ...mono,
                  fontSize: 10,
                  fontWeight: 700,
                  color,
                  marginBottom: 10,
                }}
              >
                {label} ({items.length})
              </div>
              {items.map((f) => (
                <div
                  key={f.id}
                  onClick={() => onSelect(f)}
                  style={{
                    background: "var(--app-card-bg)",
                    border: `1px solid ${
                      section === "expired"
                        ? "color-mix(in srgb, var(--app-danger) 40%, transparent)"
                        : "var(--app-border)"
                    }`,
                    borderRadius: 6,
                    padding: "14px 16px",
                    marginBottom: 8,
                    cursor: "pointer",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      flexWrap: "wrap",
                      gap: 7,
                      alignItems: "center",
                      marginBottom: 6,
                    }}
                  >
                    <TypeTag type={f.findingType} />
                    <span
                      style={{
                        ...mono,
                        fontSize: 12,
                        color: "var(--app-accent)",
                        fontWeight: 700,
                      }}
                    >
                      {f.cveId}
                    </span>
                    <SevTag sev={f.severity} />
                    {f.attestation?.waiverRef && (
                      <span
                        style={{
                          ...mono,
                          fontSize: 10,
                          color: "var(--app-accent)",
                          background: "var(--app-card-bg)",
                          padding: "2px 7px",
                          borderRadius: 2,
                        }}
                      >
                        {f.attestation.waiverRef}
                      </span>
                    )}
                  </div>
                  <div
                    style={{
                      ...sans,
                      fontSize: 13,
                      fontWeight: 500,
                      color: "var(--app-fg)",
                      marginBottom: 4,
                    }}
                  >
                    {displayTitle(f)}
                  </div>
                  <div
                    style={{
                      ...mono,
                      fontSize: 10,
                      color: "var(--app-muted)",
                    }}
                  >
                    {f.component} · Expires {fmtDt(f.attestation?.expiresAt)} ·{" "}
                    {f.attestation?.approver ?? "—"}
                  </div>
                </div>
              ))}
            </div>
          );
        })
      )}
    </div>
  );
}
