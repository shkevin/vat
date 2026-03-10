/** Decode JWT payload without verification (client-side display only). Backend verifies. */

export function decodeJwtPayload(token: string): { sub?: string; user_id?: string; tenant_id?: string | null; role?: string } | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payload = parts[1];
    const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(decoded) as { sub?: string; user_id?: string; tenant_id?: string | null; role?: string };
  } catch {
    return null;
  }
}
