"use client";

import { TypeTag, SevTag, SrcTag } from "@/components/atoms";
import { mono, sans } from "@/lib/styles";
import { SEV_ORDER } from "@/lib/constants";
import { displayTitle } from "@/lib/utils";
import type { Finding } from "@/types";
import type { Source } from "@/types";
import type { Tracker } from "@/types";

interface ReviewQueueProps {
  reviewQueue: Finding[];
  sources: Source[];
  tracker: Tracker;
  onSelect: (f: Finding) => void;
}

export function ReviewQueue({
  reviewQueue,
  sources,
  tracker,
  onSelect,
}: ReviewQueueProps) {
  const sorted = [...reviewQueue].sort(
    (a, b) =>
      SEV_ORDER.indexOf(a.severity as (typeof SEV_ORDER)[number]) -
      SEV_ORDER.indexOf(b.severity as (typeof SEV_ORDER)[number])
  );

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
        Review Queue — {reviewQueue.length} finding
        {reviewQueue.length !== 1 ? "s" : ""}
      </div>
      {reviewQueue.length === 0 ? (
        <div
          style={{
            ...sans,
            fontSize: 13,
            color: "var(--app-muted)",
            padding: "48px 0",
            textAlign: "center",
          }}
        >
          Nothing pending review.
        </div>
      ) : (
        sorted.map((f) => (
          <div
            key={f.id}
            onClick={() => onSelect(f)}
            style={{
              background: "var(--app-card-bg)",
              border: "1px solid var(--app-border)",
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
                marginBottom: 7,
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
              <SrcTag source={f.source ?? ""} sources={sources} />
              {f.trackerId && (
                <span
                  style={{
                    fontFamily: mono.fontFamily,
                    fontSize: 10,
                    fontWeight: 700,
                    color: "var(--app-accent)",
                    background: "var(--app-input-bg)",
                    padding: "2px 7px",
                    borderRadius: 2,
                  }}
                >
                  {tracker?.icon ?? "◈"} {f.trackerId}
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
                marginBottom: f.justification ? 8 : 0,
              }}
            >
              {f.component} · {f.owner ?? "—"}
            </div>
            {f.justification && (
              <div
                style={{
                  ...sans,
                  fontSize: 12,
                  color: "var(--app-muted)",
                  lineHeight: 1.55,
                  borderLeft: "2px solid var(--app-border)",
                  paddingLeft: 10,
                }}
              >
                {f.justification.slice(0, 180)}
                {f.justification.length > 180 ? "…" : ""}
              </div>
            )}
          </div>
        ))
      )}
    </div>
  );
}
