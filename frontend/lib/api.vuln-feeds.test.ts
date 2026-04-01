import { afterEach, describe, expect, it, vi } from "vitest";

import {
  fetchVulnFeedRecords,
  fetchVulnFeedRuns,
  fetchVulnFeedSummary,
  triggerVulnFeedRefresh,
} from "@/lib/api";

describe("vuln feed API client", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("calls summary endpoint", async () => {
    const fetchSpy = vi
      .spyOn(global, "fetch")
      .mockResolvedValue(
        new Response(
          JSON.stringify({
            total_records: 0,
            severity_breakdown: {},
            sources: [],
            top_vulnerabilities: [],
          }),
          { status: 200 },
        ),
      );

    const result = await fetchVulnFeedSummary();
    expect(result.total_records).toBe(0);
    expect(fetchSpy).toHaveBeenCalledWith(
      "/api/vuln-feeds/summary",
      expect.objectContaining({ headers: {} }),
    );
  });

  it("calls runs endpoint with query params", async () => {
    const fetchSpy = vi
      .spyOn(global, "fetch")
      .mockResolvedValue(
        new Response(JSON.stringify({ count: 0, runs: [] }), { status: 200 }),
      );

    await fetchVulnFeedRuns({ source: "osv", limit: 25 });
    expect(fetchSpy).toHaveBeenCalledWith(
      "/api/vuln-feeds/runs?source=osv&limit=25",
      expect.objectContaining({ headers: {} }),
    );
  });

  it("calls refresh endpoint", async () => {
    const fetchSpy = vi
      .spyOn(global, "fetch")
      .mockResolvedValue(
        new Response(JSON.stringify({ dispatched: true }), { status: 200 }),
      );

    const payload = await triggerVulnFeedRefresh({ use_celery: true });
    expect(payload.dispatched).toBe(true);
    expect(fetchSpy).toHaveBeenCalledWith(
      "/api/vuln-feeds/refresh?use_celery=true",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("calls records endpoint with search filters", async () => {
    const fetchSpy = vi
      .spyOn(global, "fetch")
      .mockResolvedValue(
        new Response(JSON.stringify({ total: 0, count: 0, records: [] }), {
          status: 200,
        }),
      );

    await fetchVulnFeedRecords({
      source: "osv",
      severity: "HIGH",
      search: "openssl",
      limit: 25,
      offset: 50,
    });
    expect(fetchSpy).toHaveBeenCalledWith(
      "/api/vuln-feeds/records?source=osv&severity=HIGH&search=openssl&limit=25&offset=50",
      expect.objectContaining({ headers: {} }),
    );
  });
});
