import { describe, it, expect } from "vitest";
import { afterAll, beforeAll } from "vitest";
import { setContainerAssetPathAliases } from "./containerRefNormalization";
import {
  primaryTagForRow,
  resolveTeamEntries,
  summarizeTeamImport,
  teamTagForAsset,
} from "./assetUtils";

// Ids as VAT derives them; observedTags as VAT actually recorded them.
const ASSETS = [
  {
    id: "docker.io/kamiwaza-extensions-tomo/images/kaizen-api",
    observedTags: [
      { tag: "release-1.2.1" },
      { tag: "latest" },
      { tag: "develop" },
    ],
  },
  { id: "docker.io/kamiwaza-extensions-tomo/images/no-tags" },
  { id: "kamiwaza" },
];

describe("teamTagForAsset", () => {
  it("matches a branch to its tag across separator styles", () => {
    // release/1.2.1 (branch) and release-1.2.1 (tag) are the same ref.
    expect(teamTagForAsset(["release/1.2.1"], ["latest", "release-1.2.1"])).toBe(
      "release-1.2.1",
    );
    expect(teamTagForAsset(["develop"], ["develop", "latest"])).toBe("develop");
  });

  it("returns nothing rather than guessing when no tag matches", () => {
    expect(teamTagForAsset(["release/9.9.9"], ["latest", "develop"])).toBeUndefined();
    expect(teamTagForAsset([], ["latest"])).toBeUndefined();
    expect(teamTagForAsset(["develop"], [])).toBeUndefined();
  });

  it("never invents a tag the asset does not have", () => {
    // "latest" is present but the team is a release line — no false positive.
    expect(teamTagForAsset(["release/1.2.1"], ["latest"])).toBeUndefined();
  });
});

describe("resolveTeamEntries", () => {
  const members = [
    { name: "kamiwaza", branch: "release/1.2.1" },
    { name: "kamiwaza-extensions-tomo/images/kaizen-api" },
  ];

  it("pins a container to the tag matching the team's branch", () => {
    expect(resolveTeamEntries(members, ASSETS)).toEqual([
      { assetId: "kamiwaza", branch: "release/1.2.1", tag: undefined },
      {
        assetId: "docker.io/kamiwaza-extensions-tomo/images/kaizen-api",
        branch: undefined,
        tag: "release-1.2.1",
      },
    ]);
  });

  it("picks develop for a develop team, from the same asset", () => {
    const [, container] = resolveTeamEntries(
      [
        { name: "kamiwaza", branch: "develop" },
        { name: "kamiwaza-extensions-tomo/images/kaizen-api" },
      ],
      ASSETS,
    );
    expect(container.tag).toBe("develop");
  });

  it("leaves the tag unset when the asset has no observed tags", () => {
    const [, container] = resolveTeamEntries(
      [
        { name: "kamiwaza", branch: "develop" },
        { name: "kamiwaza-extensions-tomo/images/no-tags" },
      ],
      ASSETS,
    );
    expect(container.tag).toBeUndefined();
  });

  it("still keeps a repo on two branches as two entries", () => {
    expect(
      resolveTeamEntries(
        [
          { name: "kamiwaza", branch: "develop" },
          { name: "kamiwaza", branch: "release/1.2.1" },
        ],
        ASSETS,
      ),
    ).toEqual([
      { assetId: "kamiwaza", branch: "develop", tag: undefined },
      { assetId: "kamiwaza", branch: "release/1.2.1", tag: undefined },
    ]);
  });

  it("drops names VAT has never ingested", () => {
    expect(resolveTeamEntries([{ name: "never/ingested" }], ASSETS)).toEqual([]);
  });
});

describe("duplicate asset rows for the same image", () => {
  // Aikido-style `ns/images/api` and registry-prefixed `docker.io/ns/images/api`
  // both exist as asset rows; only the prefixed one has findings and tags.
  // Verified against live data: resolving to the bare row produced no tags at
  // all, and pointed loadouts at an asset page with nothing on it.
  const BOTH = [
    { id: "repo" },
    { id: "ns/images/api" },
    { id: "docker.io/ns/images/api", observedTags: [{ tag: "develop" }] },
  ];

  it("resolves to the row that actually has data, either order", () => {
    for (const assets of [BOTH, [...BOTH].reverse()]) {
      expect(
        resolveTeamEntries(
          [{ name: "repo", branch: "develop" }, { name: "ns/images/api" }],
          assets,
        )[1],
      ).toEqual({
        assetId: "docker.io/ns/images/api",
        branch: undefined,
        tag: "develop",
      });
    }
  });

  it("still resolves when only the bare row exists", () => {
    expect(
      resolveTeamEntries([{ name: "ns/images/api" }], [{ id: "ns/images/api" }]),
    ).toEqual([{ assetId: "ns/images/api", branch: undefined, tag: undefined }]);
  });
});

describe("primaryTagForRow", () => {
  const OBSERVED = ["develop", "latest", "release-1.2.1"];

  it("leads with the tag the loadout pins", () => {
    expect(primaryTagForRow(OBSERVED, "release-1.2.1")).toEqual({
      primary: "release-1.2.1",
      restCount: 2,
    });
    expect(primaryTagForRow(OBSERVED, "develop")).toEqual({
      primary: "develop",
      restCount: 2,
    });
  });

  it("falls back to the generic pick when nothing is pinned", () => {
    // Ambiguous on its own — the same answer regardless of which team you view.
    expect(primaryTagForRow(OBSERVED).primary).toBe("develop");
    expect(primaryTagForRow(OBSERVED, "  ").primary).toBe("develop");
    expect(primaryTagForRow(OBSERVED, null).primary).toBe("develop");
  });

  it("prefers a version tag over latest when unpinned", () => {
    expect(primaryTagForRow(["latest", "1.4.0", "1.10.0"]).primary).toBe("1.10.0");
  });
});

describe("summarizeTeamImport", () => {
  it("does not call people-only teams a failure", () => {
    // The live workspace: 19 teams, 7 own resources, 12 (Marketing, Security,
    // org-admins...) own nothing. Nothing went wrong here.
    const msg = summarizeTeamImport({ imported: 7, ownNothing: 12, unmatched: 0 });
    expect(msg).toContain("Imported 7 teams as loadouts.");
    expect(msg).toContain("12 own nothing in Aikido");
    expect(msg).not.toMatch(/skipped|no matching assets/i);
  });

  it("calls out teams whose resources VAT has not ingested", () => {
    const msg = summarizeTeamImport({ imported: 5, ownNothing: 0, unmatched: 2 });
    expect(msg).toContain("2 teams own repos or containers VAT has not ingested.");
  });

  it("reports both reasons separately", () => {
    const msg = summarizeTeamImport({ imported: 5, ownNothing: 12, unmatched: 2 });
    expect(msg).toContain("2 teams own repos or containers VAT has not ingested.");
    expect(msg).toContain("12 own nothing in Aikido.");
  });

  it("says so plainly when nothing was created", () => {
    expect(summarizeTeamImport({ imported: 0, ownNothing: 3, unmatched: 0 })).toContain(
      "No loadouts created.",
    );
    expect(summarizeTeamImport({ imported: 0, ownNothing: 0, unmatched: 0 })).toBe(
      "No Aikido teams found.",
    );
  });

  it("gets the singular right", () => {
    const msg = summarizeTeamImport({ imported: 1, ownNothing: 1, unmatched: 1 });
    expect(msg).toContain("Imported 1 team as a loadout.");
    expect(msg).toContain("1 team owns repos");
  });
});

describe("summarizeTeamImport: unresolved members", () => {
  it("says so when Aikido members could not be read", () => {
    // A failed container fetch drops those responsibilities, which used to
    // look like "that team only owns repos".
    const msg = summarizeTeamImport({
      imported: 7, ownNothing: 12, unmatched: 0, unresolved: 41,
    });
    expect(msg).toContain("41 team members could not be read from Aikido");
    expect(msg).toContain("retry");
  });

  it("stays quiet when everything resolved", () => {
    const msg = summarizeTeamImport({
      imported: 7, ownNothing: 12, unmatched: 0, unresolved: 0,
    });
    expect(msg).not.toContain("could not be read");
  });

  it("gets the singular right", () => {
    expect(
      summarizeTeamImport({ imported: 1, ownNothing: 0, unmatched: 0, unresolved: 1 }),
    ).toContain("1 team member could not be read");
  });
});

describe("which asset row an entry points at", () => {
  // The app primes these from GET /api/config/container-aliases at startup, and
  // they are what strips docker.io/ so the canonical key is the id the UI lists.
  // Without priming, containerImageGroupKey *adds* the prefix instead.
  beforeAll(() => setContainerAssetPathAliases("docker.io/=>"));
  afterAll(() => setContainerAssetPathAliases(""));

  // Both rows exist for the same image. The UI lists the alias-stripped one;
  // the registry-prefixed one carries the observed tags. Pointing entries at
  // the prefixed row to reach its tags made them invisible in the workspace —
  // a 82-member team showed 17 assets.
  const BOTH = [
    { id: "repo-a" },
    { id: "ns/images/api" },
    { id: "docker.io/ns/images/api", observedTags: [{ tag: "release-1.2.1" }] },
  ];
  const members = [
    { name: "repo-a", branch: "release/1.2.1" },
    { name: "ns/images/api" },
  ];

  it("stores the id the UI lists, not the one holding the tags", () => {
    const [, container] = resolveTeamEntries(members, BOTH);
    expect(container.assetId).toBe("ns/images/api");
  });

  it("still finds the tag, which lives on the other row", () => {
    const [, container] = resolveTeamEntries(members, BOTH);
    expect(container.tag).toBe("release-1.2.1");
  });

  it("is order-independent", () => {
    for (const assets of [BOTH, [...BOTH].reverse()]) {
      const [, container] = resolveTeamEntries(members, assets);
      expect(container.assetId).toBe("ns/images/api");
      expect(container.tag).toBe("release-1.2.1");
    }
  });

  it("uses the only row available when there is no duplicate", () => {
    expect(
      resolveTeamEntries([{ name: "ns/images/solo" }], [{ id: "ns/images/solo" }]),
    ).toEqual([{ assetId: "ns/images/solo", branch: undefined, tag: undefined }]);
  });
});
