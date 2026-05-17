import { describe, expect, it } from "vitest";

import {
  shouldInitializeAikidoSyncStatus,
  shouldPollAikidoSyncStatus,
} from "./aikidoSyncStatusGate";

describe("aikido sync status gating", () => {
  it("initializes status checks when oauth is configured even without token", () => {
    expect(shouldInitializeAikidoSyncStatus(true, null)).toBe(true);
    expect(shouldInitializeAikidoSyncStatus(true, undefined)).toBe(true);
  });

  it("polls status while syncing even without token", () => {
    expect(shouldPollAikidoSyncStatus(true, null)).toBe(true);
    expect(shouldPollAikidoSyncStatus(true, undefined)).toBe(true);
  });

  it("still blocks when oauth is disabled or sync is idle", () => {
    expect(shouldInitializeAikidoSyncStatus(false, null)).toBe(false);
    expect(shouldPollAikidoSyncStatus(false, null)).toBe(false);
  });
});
