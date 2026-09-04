import { describe, it, expect } from "vitest";
import { resolveTeamEntries } from "./assetUtils";

// Members as Aikido reports them (containers without the registry prefix, repos
// pinned to a branch); ids as VAT derives them from findings.
const ASSETS = [
  { id: "docker.io/kamiwaza-extensions-tomo/images/tomo-postgres" },
  { id: "docker.io/kamiwaza-extensions-tomo/images/tomo-web" },
  { id: "containers" },
];

describe("resolveTeamEntries", () => {
  it("matches Aikido container names to registry-prefixed VAT asset ids, keeping the tag", () => {
    expect(
      resolveTeamEntries(
        [{ name: "kamiwaza-extensions-tomo/images/tomo-postgres", tag: "latest" }],
        ASSETS,
      ),
    ).toEqual([
      {
        assetId: "docker.io/kamiwaza-extensions-tomo/images/tomo-postgres",
        branch: undefined,
        tag: "latest",
      },
    ]);
  });

  it("keeps a code repo's branch", () => {
    expect(resolveTeamEntries([{ name: "containers", branch: "develop" }], ASSETS)).toEqual([
      { assetId: "containers", branch: "develop", tag: undefined },
    ]);
  });

  it("keeps the same repo on two branches as two entries", () => {
    expect(
      resolveTeamEntries(
        [
          { name: "containers", branch: "develop" },
          { name: "containers", branch: "release/1.2.1" },
        ],
        ASSETS,
      ),
    ).toEqual([
      { assetId: "containers", branch: "develop", tag: undefined },
      { assetId: "containers", branch: "release/1.2.1", tag: undefined },
    ]);
  });

  it("drops names VAT has never ingested, and de-dupes identical context", () => {
    expect(
      resolveTeamEntries(
        [
          { name: "kamiwaza-extensions-tomo/images/tomo-web", tag: "latest" },
          { name: "docker.io/kamiwaza-extensions-tomo/images/tomo-web", tag: "latest" },
          { name: "never/ingested/repo", tag: "v1" },
          { name: "  " },
        ],
        ASSETS,
      ),
    ).toEqual([
      {
        assetId: "docker.io/kamiwaza-extensions-tomo/images/tomo-web",
        branch: undefined,
        tag: "latest",
      },
    ]);
  });

  it("returns nothing when there are no assets", () => {
    expect(resolveTeamEntries([{ name: "anything" }], [])).toEqual([]);
  });
});
