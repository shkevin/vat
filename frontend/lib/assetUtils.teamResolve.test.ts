import { describe, it, expect } from "vitest";
import { resolveAssetIdsByName } from "./assetUtils";

// Names as Aikido reports them for a team's responsibilities; ids as VAT
// derives them from findings (registry-prefixed for containers).
const ASSETS = [
  { id: "docker.io/kamiwaza-extensions-tomo/images/tomo-postgres" },
  { id: "docker.io/kamiwaza-extensions-tomo/images/tomo-web" },
  { id: "containers" },
];

describe("resolveAssetIdsByName", () => {
  it("matches Aikido container names to registry-prefixed VAT asset ids", () => {
    expect(
      resolveAssetIdsByName(
        ["kamiwaza-extensions-tomo/images/tomo-postgres"],
        ASSETS,
      ),
    ).toEqual(["docker.io/kamiwaza-extensions-tomo/images/tomo-postgres"]);
  });

  it("matches exact ids and code-repo names", () => {
    expect(resolveAssetIdsByName(["containers"], ASSETS)).toEqual(["containers"]);
  });

  it("drops names VAT has never ingested and de-dupes", () => {
    expect(
      resolveAssetIdsByName(
        [
          "kamiwaza-extensions-tomo/images/tomo-web",
          "docker.io/kamiwaza-extensions-tomo/images/tomo-web",
          "never/ingested/repo",
          "  ",
        ],
        ASSETS,
      ),
    ).toEqual(["docker.io/kamiwaza-extensions-tomo/images/tomo-web"]);
  });

  it("returns nothing when there are no assets", () => {
    expect(resolveAssetIdsByName(["anything"], [])).toEqual([]);
  });
});
