export function shouldInitializeAikidoSyncStatus(
  oauthConfigured: boolean,
  _token?: string | null,
): boolean {
  return oauthConfigured;
}

export function shouldPollAikidoSyncStatus(
  syncing: boolean,
  _token?: string | null,
): boolean {
  return syncing;
}

export type AikidoSyncProgressLike = {
  status?: string | null;
  step?: number | null;
  total?: number | null;
  label?: string | null;
};

export function hasRestorableAikidoSyncProgress(
  status: AikidoSyncProgressLike | null | undefined,
): status is AikidoSyncProgressLike & {
  status: "running";
  step: number;
  total: number;
  label: string;
} {
  return (
    status?.status === "running" &&
    typeof status.step === "number" &&
    typeof status.total === "number" &&
    status.total > 0 &&
    typeof status.label === "string" &&
    status.label.length > 0
  );
}

export function shouldKeepAikidoSyncingAfterPollError(syncing: boolean): boolean {
  return syncing;
}

export function getAikidoSyncPollDelayMs(consecutiveFailures: number): number {
  const failures = Math.max(0, consecutiveFailures);
  return Math.min(3000 * 2 ** failures, 15000);
}

export function shouldPauseAikidoSyncPolling(
  visibilityState?: DocumentVisibilityState | string,
): boolean {
  return visibilityState === "hidden";
}
