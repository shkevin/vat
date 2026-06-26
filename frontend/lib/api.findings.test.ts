import { afterEach, describe, expect, it, vi } from "vitest";

import { updateFinding } from "@/lib/api";

describe("findings API client", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("serializes riskScoring as risk_scoring on updates", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          id: "f-risk",
          findingType: "SCA",
          fingerprintId: "fp-risk",
          cveId: "CVE-2024-23342",
          severity: "High",
          status: "Open",
          sources: [],
          audit: [],
          riskScoring: {
            environmental: {
              score: "0.0",
              rationale: "Not reachable.",
            },
          },
        }),
        { status: 200 },
      ),
    );

    await updateFinding("f-risk", {
      riskScoring: {
        environmental: {
          score: "0.0",
          rationale: "Not reachable.",
        },
      },
    });

    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    expect(fetchSpy).toHaveBeenCalledWith(
      "/api/findings/f-risk",
      expect.objectContaining({ method: "PATCH" }),
    );
    expect(JSON.parse(String(init.body))).toEqual({
      risk_scoring: {
        environmental: {
          score: "0.0",
          rationale: "Not reachable.",
        },
      },
    });
  });
});
