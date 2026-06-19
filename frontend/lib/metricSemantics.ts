const CLOSED_STATUS_KEYS = new Set([
  "resolved",
  "false positive",
  "duplicate",
  "not applicable",
  "approved",
  "suppressed",
  // Source-native terminal statuses used by report data from integrations.
  "closed",
  "ignored",
  "auto ignored",
]);

const RISK_ACCEPTED_STATUS_KEY = "risk accepted";

export function normalizeMetricStatus(status: unknown): string {
  return String(status ?? "")
    .trim()
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .toLowerCase();
}

export function isClosedDisposition(status: unknown): boolean {
  return CLOSED_STATUS_KEYS.has(normalizeMetricStatus(status));
}

export function isRiskAccepted(status: unknown): boolean {
  return normalizeMetricStatus(status) === RISK_ACCEPTED_STATUS_KEY;
}

export function isVerifiedDisposition(status: unknown): boolean {
  return isClosedDisposition(status);
}

export function isOpenRisk(status: unknown): boolean {
  const normalized = normalizeMetricStatus(status);
  return (
    normalized.length > 0 &&
    !CLOSED_STATUS_KEYS.has(normalized) &&
    normalized !== RISK_ACCEPTED_STATUS_KEY
  );
}

export function isOverdueOpenRisk(
  status: unknown,
  slaDue: string | null | undefined,
  asOfMs = Date.now(),
): boolean {
  if (!isOpenRisk(status) || !slaDue) return false;
  const dueMs = new Date(slaDue).getTime();
  return Number.isFinite(dueMs) && dueMs < asOfMs;
}
