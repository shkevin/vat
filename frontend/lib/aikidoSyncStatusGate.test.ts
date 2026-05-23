import { describe, expect, it } from "vitest";

import {
  getAikidoSyncPollDelayMs,
  hasRestorableAikidoSyncProgress,
  shouldInitializeAikidoSyncStatus,
  shouldKeepAikidoSyncingAfterPollError,
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

  it("restores queued and numeric running progress after refresh", () => {
    expect(
      hasRestorableAikidoSyncProgress({
        status: "running",
        step: 0,
        total: 18,
        label: "Queued",
      }),
    ).toBe(true);
    expect(
      hasRestorableAikidoSyncProgress({
        status: "running",
        step: 9,
        total: 18,
        label: "Container SBOMs",
      }),
    ).toBe(true);
  });

  it("keeps sync state during transient poll errors and backs off", () => {
    expect(shouldKeepAikidoSyncingAfterPollError(true)).toBe(true);
    expect(shouldKeepAikidoSyncingAfterPollError(false)).toBe(false);
    expect(getAikidoSyncPollDelayMs(0)).toBe(1500);
    expect(getAikidoSyncPollDelayMs(1)).toBe(3000);
    expect(getAikidoSyncPollDelayMs(5)).toBe(15000);
  });
});
