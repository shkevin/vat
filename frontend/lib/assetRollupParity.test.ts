import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { deriveAssets } from "./assetUtils";
import { setContainerAssetPathAliases } from "./containerRefNormalization";
import { SEV_ORDER } from "./constants";
import type { Finding } from "@/types";

/**
 * Gate for moving asset rollups server-side: the backend's numbers must match
 * deriveAssets exactly before the dashboard can paint from them.
 *
 * Needs a dump from backend/scripts/dump_asset_rollup_parity.py at
 * lib/__parity.json; skips when absent so CI is unaffected. See that script
 * for the two commands.
 */
const DUMP = join(__dirname, "__parity.json");
const ALIASES = process.env.VAT_CONTAINER_ASSET_PATH_ALIASES ?? "";

describe.skipIf(!existsSync(DUMP))("asset rollup parity (needs a live dump)", () => {
  it("backend rollups match deriveAssets on every asset and field", () => {
    // The app primes these from GET /api/config/container-aliases at startup.
    // Without them applyContainerAssetPathAliases no-ops and every container key
    // keeps its registry prefix — which reads as a divergence but is not one.
    setContainerAssetPathAliases(ALIASES);

    const data = JSON.parse(readFileSync(DUMP, "utf8")) as {
      findings: Finding[];
      backend: Array<Record<string, unknown>>;
    };
    const derived = deriveAssets(data.findings, SEV_ORDER);
    const b = new Map(data.backend.map((a) => [String(a.id), a]));
    const d = new Map(derived.map((a) => [a.id, a]));

    expect([...b.keys()].filter((k) => !d.has(k))).toEqual([]);
    expect([...d.keys()].filter((k) => !b.has(k))).toEqual([]);

    const fields = [
      "openCount", "inReviewCount", "overdueCount",
      "worstSeverity", "verifiedPct", "oraPct",
    ] as const;
    const mismatches: string[] = [];
    for (const k of d.keys()) {
      for (const f of fields) {
        const bv = (b.get(k) as Record<string, unknown>)[f];
        const dv = (d.get(k) as unknown as Record<string, unknown>)[f];
        if (JSON.stringify(bv) !== JSON.stringify(dv)) {
          mismatches.push(`${k}.${f}: backend=${bv} derived=${dv}`);
        }
      }
    }
    expect(mismatches.slice(0, 20)).toEqual([]);
  });
});
