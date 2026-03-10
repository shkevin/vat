"use client";

import { getClassificationColor } from "@/lib/utils";

interface AppFooterProps {
  classification: string;
  suffix?: string;
}

export function AppFooter({ classification, suffix = "" }: AppFooterProps) {
  return (
    <div
      style={{
        background: getClassificationColor(classification),
        color: "#fff",
        padding: "6px 20px",
        minHeight: 24,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        textAlign: "center",
        fontSize: 12,
        fontWeight: 700,
        letterSpacing: "0.1em",
        textTransform: "uppercase",
        marginTop: "auto",
      }}
    >
      <span>
        {classification}
        {suffix}
      </span>
    </div>
  );
}
