// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import React from "react";
import { describe, expect, it, vi } from "vitest";

import { DetailPanel } from "./DetailPanel";
import type { Finding, Tracker } from "@/types";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;
(globalThis as typeof globalThis & { React: typeof React }).React = React;

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({ token: null }),
}));

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f-test",
    findingType: "Secret",
    fingerprintId: "fp-test",
    cveId: "private-key",
    title: "Private key detected",
    severity: "High",
    status: "Open",
    sources: [{ name: "gitleaks", importedAt: "2026-06-26T00:00:00Z" }],
    audit: [],
    filePath: "src/config.ts",
    line: 12,
    snippetMasked: "const token = \"***REDACTED***\";",
    description: "A private key was detected in source control.",
    ...overrides,
  };
}

const tracker: Tracker = {
  name: "Linear",
  type: "linear",
  baseUrl: "https://linear.example.local",
  icon: "L",
  description: "Linear tracker",
  commentPrefix: "[VAT]",
};

describe("DetailPanel evidence", () => {
  it("renders evidence summary and proof near the top of the detail panel", () => {
    render(
      <DetailPanel
        finding={finding()}
        sources={[]}
        tracker={tracker}
        onArchive={vi.fn()}
        onClose={vi.fn()}
        onRevert={vi.fn()}
        onUnarchive={vi.fn()}
        onUpdate={vi.fn()}
        readOnly
      />,
    );

    expect(screen.getByText("Evidence")).toBeTruthy();
    expect(screen.getByText("Masked line preview")).toBeTruthy();
    expect(
      screen.getAllByText('const token = "***REDACTED***";').length,
    ).toBeGreaterThan(0);
    expect(screen.getByText("Reviewer Next Step")).toBeTruthy();
  });
});
