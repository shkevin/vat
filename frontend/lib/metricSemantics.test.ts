import { describe, expect, it } from "vitest";
import {
  isClosedDisposition,
  isOpenRisk,
  isOverdueOpenRisk,
  isRiskAccepted,
  isVerifiedDisposition,
} from "./metricSemantics";

describe("metric semantics", () => {
  it("keeps risk accepted out of both closed and open-risk buckets", () => {
    expect(isRiskAccepted("Risk Accepted")).toBe(true);
    expect(isRiskAccepted("RiskAccepted")).toBe(true);
    expect(isClosedDisposition("Risk Accepted")).toBe(false);
    expect(isOpenRisk("Risk Accepted")).toBe(false);
  });

  it("treats active workflow statuses as open risk", () => {
    expect(isOpenRisk("Open")).toBe(true);
    expect(isOpenRisk("In Review")).toBe(true);
    expect(isOpenRisk("InReview")).toBe(true);
    expect(isOpenRisk("Reopened")).toBe(true);
    expect(isOpenRisk("Rejected")).toBe(true);
    expect(isOpenRisk("Mitigated")).toBe(true);
  });

  it("uses closed dispositions as verified dispositions", () => {
    for (const status of [
      "Resolved",
      "False Positive",
      "Duplicate",
      "Not Applicable",
      "Approved",
      "Suppressed",
      "closed",
      "ignored",
      "auto_ignored",
    ]) {
      expect(isClosedDisposition(status), status).toBe(true);
      expect(isVerifiedDisposition(status), status).toBe(true);
      expect(isOpenRisk(status), status).toBe(false);
    }
  });

  it("only marks unresolved open-risk findings overdue", () => {
    const asOf = Date.parse("2026-06-18T12:00:00Z");
    const yesterday = "2026-06-17T00:00:00Z";

    expect(isOverdueOpenRisk("Reopened", yesterday, asOf)).toBe(true);
    expect(isOverdueOpenRisk("Risk Accepted", yesterday, asOf)).toBe(false);
    expect(isOverdueOpenRisk("Resolved", yesterday, asOf)).toBe(false);
  });
});
