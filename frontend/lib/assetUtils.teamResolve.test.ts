import { describe, it, expect } from "vitest";
import { resolveTeamEntries, teamTagForAsset } from "./assetUtils";

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
