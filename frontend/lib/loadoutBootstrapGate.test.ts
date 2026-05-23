import { describe, expect, it } from "vitest";

import {
  loadoutBootstrapKey,
  shouldRunLoadoutBootstrap,
} from "./loadoutBootstrapGate";

describe("loadout bootstrap gate", () => {
  it("creates stable keys from primitive auth identity", () => {
    expect(loadoutBootstrapKey("token-1", undefined)).toBe("token:token-1");
    expect(loadoutBootstrapKey(undefined, "user@example.com")).toBe(
      "email:user@example.com",
    );
    expect(loadoutBootstrapKey(undefined, undefined)).toBe(null);
  });

  it("runs once per authenticated identity", () => {
    expect(shouldRunLoadoutBootstrap(null, "token:token-1")).toBe(true);
    expect(shouldRunLoadoutBootstrap("token:token-1", "token:token-1")).toBe(
      false,
    );
    expect(shouldRunLoadoutBootstrap("token:token-1", "token:token-2")).toBe(
      true,
    );
    expect(shouldRunLoadoutBootstrap("token:token-1", null)).toBe(false);
  });
});
