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
