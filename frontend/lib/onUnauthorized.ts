/**
 * Central handler for 401 Unauthorized responses.
 * AuthProvider registers a callback that clears session and localStorage.
 * API layer calls triggerUnauthorized() when any request returns 401.
 */

let handler: (() => void) | null = null;

export function setOnUnauthorized(h: (() => void) | null): void {
  handler = h;
}

export function triggerUnauthorized(): void {
  handler?.();
}
