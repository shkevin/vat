"use client";

import { getClassificationColor } from "@/lib/utils";

interface ClassificationBannerProps {
  classification: string;
}

export function ClassificationBanner({ classification }: ClassificationBannerProps) {
  return (
    <div
      style={{
        background: getClassificationColor(classification),
        color: "#fff",
        textAlign: "center",
        padding: "6px 16px",
        minHeight: 24,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontSize: 12,
        fontWeight: 700,
        letterSpacing: "0.1em",
        textTransform: "uppercase",
      }}
    >
      {classification}
    </div>
  );
}
