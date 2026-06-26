// @vitest-environment jsdom
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DetailPanel } from "./DetailPanel";
import type { Finding, Tracker } from "@/types";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;
(globalThis as typeof globalThis & { React: typeof React }).React = React;

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({ token: null }),
}));

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

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
  it("defaults editable findings to the details tab", () => {
    render(
      <DetailPanel
        finding={finding({
          id: "f-open",
          status: "Open",
        })}
        sources={[]}
        tracker={tracker}
        onArchive={vi.fn()}
        onClose={vi.fn()}
        onRevert={vi.fn()}
        onUnarchive={vi.fn()}
        onUpdate={vi.fn()}
      />,
    );

    expect(
      screen.getByRole("tab", { name: "Details" }).getAttribute("aria-selected"),
    ).toBe("true");
    expect(
      screen
        .getByRole("tab", { name: "Decision" })
        .getAttribute("aria-selected"),
    ).toBe("false");
  });

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

  it("renders the canonical scanner source for operator findings", () => {
    const { container } = render(
      <DetailPanel
        finding={finding({
          findingType: "SCA",
          source: "trivy",
          sources: [{ name: "trivy", importedAt: "2026-06-26T00:00:00Z" }],
          snippetMasked: null,
        })}
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
    const badges = container.querySelector(".detail-panel-badges");
    expect(badges).toBeTruthy();

    expect(within(badges as HTMLElement).getByText("trivy")).toBeTruthy();
    expect(within(badges as HTMLElement).queryByText("Aikido")).toBeNull();
    expect(screen.queryByText("Aikido")).toBeNull();
  });

  it("marks long image digest evidence values as breakable", () => {
    const digest =
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    render(
      <DetailPanel
        finding={finding({
          findingType: "SCA",
          imageDigest: digest,
          snippetMasked: null,
        })}
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

    const digestRow = screen
      .getByText("Image digest")
      .closest(".detail-panel-kv-item");
    expect(digestRow).toBeTruthy();

    const digestValue = within(digestRow as HTMLElement).getByText(digest);
    expect(digestValue.className).toContain("detail-panel-breakable-value");
  });

  it("closes from outside clicks after the slide-out transition starts", () => {
    vi.useFakeTimers();
    const onClose = vi.fn();
    const { container } = render(
      <DetailPanel
        finding={finding()}
        sources={[]}
        tracker={tracker}
        onArchive={vi.fn()}
        onClose={onClose}
        onRevert={vi.fn()}
        onUnarchive={vi.fn()}
        onUpdate={vi.fn()}
        readOnly
      />,
    );

    const backdrop = container.querySelector(".detail-panel-backdrop");
    expect(backdrop).toBeTruthy();

    fireEvent.mouseDown(backdrop as HTMLElement);

    expect(screen.getByRole("dialog").className).toContain(
      "detail-panel-closing",
    );
    expect(onClose).not.toHaveBeenCalled();

    act(() => {
      vi.runOnlyPendingTimers();
    });

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("renders audit entries in the history tab", () => {
    render(
      <DetailPanel
        finding={finding({
          audit: [
            {
              ts: "2026-06-26T00:00:00Z",
              user: "reviewer@example.com",
              action: "Imported from trivy",
              note: null,
            },
            {
              ts: "2026-06-26T00:01:00Z",
              user: "reviewer@example.com",
              action: "Status → Risk Accepted",
              note: "accepted for 30 days",
            },
          ],
        })}
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

    fireEvent.click(screen.getByRole("tab", { name: "History" }));

    expect(screen.getByText("Status → Risk Accepted")).toBeTruthy();
    expect(screen.getByText("Imported from trivy")).toBeTruthy();
    expect(screen.getByText('"accepted for 30 days"')).toBeTruthy();
  });

  it("saves reviewer environmental scoring from the decision tab", async () => {
    const onUpdate = vi.fn();
    render(
      <DetailPanel
        finding={finding({
          findingType: "SCA",
          riskScoring: {
            source: {
              source: "trivy",
              score: "7.4",
              vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            },
          },
        })}
        sources={[]}
        tracker={tracker}
        onArchive={vi.fn()}
        onClose={vi.fn()}
        onRevert={vi.fn()}
        onUnarchive={vi.fn()}
        onUpdate={onUpdate}
      />,
    );

    fireEvent.click(screen.getByRole("tab", { name: "Decision" }));
    fireEvent.change(
      screen.getByPlaceholderText("CVSS:3.1/.../MC:N/MI:N/MA:N"),
      {
        target: {
          value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/MC:N/MI:N/MA:N",
        },
      },
    );
    fireEvent.change(screen.getByPlaceholderText("Computed or enter manually"), {
      target: { value: "0.0" },
    });
    fireEvent.change(
      screen.getByPlaceholderText("Explain why environmental scoring changes the practical risk."),
      {
        target: { value: "The vulnerable ECDSA signing path is not reachable." },
      },
    );
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: "Save Environmental Scoring" }),
      );
    });

    expect(onUpdate).toHaveBeenCalledWith(
      expect.objectContaining({
        riskScoring: {
          source: {
            source: "trivy",
            score: "7.4",
            vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
          },
          environmental: {
            cvssVersion: "3.1",
            vector:
              "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/MC:N/MI:N/MA:N",
            score: "0.0",
            rationale: "The vulnerable ECDSA signing path is not reachable.",
            knownScannerException: "",
            scopeNote: "",
          },
        },
      }),
    );
  });

  it("shows an empty state when no audit history is recorded", () => {
    render(
      <DetailPanel
        finding={finding({ audit: [] })}
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

    fireEvent.click(screen.getByRole("tab", { name: "History" }));

    expect(screen.getByText("No audit history recorded yet.")).toBeTruthy();
  });
});
