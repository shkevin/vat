export function loadoutBootstrapKey(
  token?: string | null,
  userEmail?: string | null,
): string | null {
  if (token) return `token:${token}`;
  if (userEmail) return `email:${userEmail}`;
  return null;
}

export function shouldRunLoadoutBootstrap(
  lastBootstrapKey: string | null,
  nextBootstrapKey: string | null,
): boolean {
  return Boolean(nextBootstrapKey && nextBootstrapKey !== lastBootstrapKey);
}
