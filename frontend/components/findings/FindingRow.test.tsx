// @vitest-environment jsdom
import { cleanup, render } from "@testing-library/react";
import React from "react";
import { afterEach, describe, expect, it } from "vitest";

import { FindingRow } from "./FindingRow";
import type { Finding } from "@/types";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;
(globalThis as typeof globalThis & { React: typeof React }).React = React;

afterEach(cleanup);

const finding = {
  id: "f1",
  findingType: "SCA",
  cveId: "CVE-2020-0001",
  severity: "High",
  status: "Open",
  sources: [],
  audit: [],
} as unknown as Finding;

const base = {
  finding,
  sources: [],
  selected: false,
  checked: false,
  onCheck: () => {},
  onClick: () => {},
};

const boxes = (c: HTMLElement) => c.querySelectorAll('input[type="checkbox"]').length;

describe("FindingRow checkbox visibility", () => {
  it("renders a checkbox by default", () => {
    const { container } = render(<FindingRow {...base} />);
    expect(boxes(container)).toBe(1);
  });

  it("renders a checkbox when showCheckbox is true", () => {
    const { container } = render(<FindingRow {...base} showCheckbox />);
    expect(boxes(container)).toBe(1);
  });

  // Secondary source-rows of the same finding share its id; hiding their checkbox
  // is what stops "checking one row also checks the row above" in ungrouped mode.
  it("hides the checkbox on secondary source-rows (showCheckbox=false)", () => {
    const { container } = render(<FindingRow {...base} showCheckbox={false} />);
    expect(boxes(container)).toBe(0);
  });
});
