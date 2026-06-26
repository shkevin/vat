import { describe, expect, it } from "vitest";

import {
  toneFromCvssScore,
  toneFromEpssScore,
} from "@/lib/scoreColors";

describe("scoreColors", () => {
  it("maps CVSS scores to severity tones", () => {
    expect(toneFromCvssScore("9.8")).toBe("Critical");
    expect(toneFromCvssScore("7.4")).toBe("High");
    expect(toneFromCvssScore("5.5")).toBe("Medium");
    expect(toneFromCvssScore("2.1")).toBe("Low");
    expect(toneFromCvssScore("0.0")).toBe("Informational");
  });

  it("maps EPSS probabilities to severity tones", () => {
    expect(toneFromEpssScore("0.82")).toBe("Critical");
    expect(toneFromEpssScore("0.45")).toBe("High");
    expect(toneFromEpssScore("0.12")).toBe("Medium");
    expect(toneFromEpssScore("0.012")).toBe("Low");
    expect(toneFromEpssScore("0")).toBe("Informational");
  });
});
