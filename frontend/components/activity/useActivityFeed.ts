"use client";

import { useEffect, useMemo, useState } from "react";
import { fetchAuditEvents, type Auth, type ApiAuditEvent } from "@/lib/api";
import type { Finding } from "@/types";
import type { ActivityEvent, ActivityEventKind, ActivityEventSource } from "@/types/activity";
import { assetIdForFinding } from "@/lib/assetUtils";

interface UseActivityFeedOptions {
  findings: Finding[];
  auth?: Auth;
  isAdmin: boolean;
  sourceFilter: ActivityEventSource | "all";
  enabled?: boolean;
  systemLimit?: number;
}

interface UseActivityFeedResult {
  events: ActivityEvent[];
  loadingSystem: boolean;
  systemError: string | null;
  canViewSystem: boolean;
}

function classifyFindingEvent(action: string, note: string | null): ActivityEventKind {
  const a = action.toLowerCase();
  if (a.includes("status")) return "status_change";
  if (a.includes("archive") || a.includes("revert") || a.includes("override")) {
    return "lifecycle";
  }
  if (a.includes("approve") || a.includes("reject") || a.includes("accept")) {
    return "decision";
  }
  if (note) return "review_note";
  return "decision";
}

function classifySystemEvent(eventType: string): ActivityEventKind {
  if (eventType.startsWith("ingest.")) return "ingest";
  if (eventType.startsWith("sync.")) return "sync";
  if (eventType.startsWith("export.")) return "export";
  if (eventType.includes("asset") || eventType.includes("merge") || eventType.includes("correlation")) {
    return "asset";
  }
  return "system";
}

function asNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  return null;
}

function formatRollupTitle(data: Record<string, unknown> | undefined): string {
  const created = asNumber(data?.dedupNewCount) ?? 0;
  const merged = asNumber(data?.dedupMergedCount) ?? 0;
  const failed = asNumber(data?.failed) ?? 0;
  return `Ingest window: ${created} created, ${merged} merged, ${failed} failed`;
}

function formatRollupDetail(data: Record<string, unknown> | undefined): string | undefined {
  if (!data) return undefined;
  const detailParts: string[] = [];
  if (typeof data.sourceId === "string" && data.sourceId) detailParts.push(`source: ${data.sourceId}`);
  if (typeof data.parserId === "string" && data.parserId) detailParts.push(`parser: ${data.parserId}`);
  const durationSec = asNumber(data.windowDurationSec);
  if (durationSec != null) detailParts.push(`window: ${durationSec.toFixed(1)}s`);
  if (typeof data.flushReason === "string" && data.flushReason) {
    detailParts.push(`flush: ${data.flushReason}`);
  }
  const sampledMappings = Array.isArray(data.sampledMappings) ? data.sampledMappings.length : 0;
  const sampledDedup = Array.isArray(data.sampledDedup) ? data.sampledDedup.length : 0;
  const sampledFailures = Array.isArray(data.sampledFailures) ? data.sampledFailures.length : 0;
  detailParts.push(
    `samples: ${sampledMappings} mappings, ${sampledDedup} dedup, ${sampledFailures} failures`,
  );
  return detailParts.join(" · ") || undefined;
}

function toFindingEvents(findings: Finding[]): ActivityEvent[] {
  const rows: ActivityEvent[] = [];
  for (const finding of findings) {
    const resolvedAssetId = assetIdForFinding(finding);
    const assetName = finding.image || finding.component || resolvedAssetId || undefined;
    const audit = finding.audit ?? [];
    for (let i = 0; i < audit.length; i += 1) {
      const entry = audit[i];
      rows.push({
        id: `finding:${finding.id}:${entry.ts}:${i}`,
        source: "finding",
        kind: classifyFindingEvent(entry.action ?? "", entry.note ?? null),
        eventType: "finding.audit",
        timestamp: entry.ts,
        title: entry.action || "Finding updated",
        detail: entry.note ?? undefined,
        findingId: finding.id,
        assetId: resolvedAssetId,
        assetName,
        severity: finding.severity,
      });
    }
  }
  return rows;
}

function shouldRollupFindingEvent(event: ActivityEvent): boolean {
  if (event.source !== "finding") return false;
  const title = (event.title || "").trim();
  if (!title) return false;
  // High-volume source sync events (Aikido SBOM imports) are noisy in feed.
  if (/from sbom/i.test(title)) return true;
  if (/^imported from .* scan$/i.test(title)) return true;
  return false;
}

function minuteBucketKey(tsIso: string): string {
  const date = new Date(tsIso);
  if (Number.isNaN(date.getTime())) return "invalid";
  date.setSeconds(0, 0);
  return date.toISOString();
}

function formatFindingRollupSnapshot(events: ActivityEvent[]): string {
  const byAction = new Map<string, number>();
  const sampleFindingIds: string[] = [];
  for (const event of events) {
    const action = (event.title || "Finding updated").trim();
    byAction.set(action, (byAction.get(action) ?? 0) + 1);
    if (event.findingId && sampleFindingIds.length < 3 && !sampleFindingIds.includes(event.findingId)) {
      sampleFindingIds.push(event.findingId);
    }
  }
  const actionSummary = [...byAction.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([action, count]) => `${action} ×${count}`)
    .join(", ");
  const sampleSummary = sampleFindingIds.length > 0 ? `samples: ${sampleFindingIds.join(", ")}` : "";
  return [actionSummary ? `snapshot: ${actionSummary}` : "", sampleSummary]
    .filter((part) => part.length > 0)
    .join(" · ");
}

function formatSeveritySummary(events: ActivityEvent[]): string {
  const order = ["Critical", "High", "Medium", "Low", "Informational"];
  const counts = new Map<string, number>();
  for (const event of events) {
    const sev = (event.severity || "Informational").trim();
    counts.set(sev, (counts.get(sev) ?? 0) + 1);
  }
  const parts = order
    .filter((sev) => (counts.get(sev) ?? 0) > 0)
    .map((sev) => `${sev} ×${counts.get(sev)}`);
  if (parts.length === 0) return "severity: Informational ×0";
  return `severity: ${parts.join(", ")}`;
}

function formatTopActions(events: ActivityEvent[]): string {
  const byAction = new Map<string, number>();
  for (const event of events) {
    const action = (event.title || "Finding updated").trim();
    byAction.set(action, (byAction.get(action) ?? 0) + 1);
  }
  const top = [...byAction.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 2)
    .map(([action, count]) => `${action} ×${count}`);
  return top.join(" · ");
}

export function rollupFindingEvents(events: ActivityEvent[]): ActivityEvent[] {
  const passthrough: ActivityEvent[] = [];
  const buckets = new Map<string, ActivityEvent[]>();
  for (const event of events) {
    if (!shouldRollupFindingEvent(event) || !event.assetId) {
      passthrough.push(event);
      continue;
    }
    const key = `${event.assetId}::${minuteBucketKey(event.timestamp)}`;
    const list = buckets.get(key) ?? [];
    list.push(event);
    buckets.set(key, list);
  }

  const rolled: ActivityEvent[] = [];
  for (const [key, list] of buckets.entries()) {
    if (list.length <= 2) {
      rolled.push(...list);
      continue;
    }
    const latest = [...list].sort((a, b) => {
      const aTs = new Date(a.timestamp).getTime();
      const bTs = new Date(b.timestamp).getTime();
      return (Number.isNaN(bTs) ? 0 : bTs) - (Number.isNaN(aTs) ? 0 : aTs);
    })[0];
    const [assetId] = key.split("::");
    const assetName = latest.assetName || assetId;
    const relatedFindingIds = list
      .map((item) => item.findingId)
      .filter((id): id is string => Boolean(id))
      .filter((id, idx, all) => all.indexOf(id) === idx);
    const relatedFindings = list
      .map((item) => ({
        id: item.findingId || item.id,
        title: item.title,
        severity: item.severity,
        timestamp: item.timestamp,
        assetId: item.assetId,
        assetName: item.assetName,
      }))
      .filter((item, idx, all) => all.findIndex((x) => x.id === item.id) === idx)
      .slice(0, 20);
    rolled.push({
      id: `finding-rollup:${assetId}:${minuteBucketKey(latest.timestamp)}`,
      source: "finding",
      kind: latest.kind,
      eventType: "finding.audit.rollup.asset",
      timestamp: latest.timestamp,
      title: `${assetName}: activity rollup (${list.length} updates)`,
      detail: `${formatSeveritySummary(list)} · ${formatTopActions(list)}`,
      relatedFindingIds,
      relatedFindings,
      assetId,
      assetName,
      severity: latest.severity,
    });
  }

  return [...passthrough, ...rolled];
}

export function toSystemEvent(row: ApiAuditEvent): ActivityEvent {
  if (row.eventType === "ingest.rollup.window") {
    return {
      id: `system:${row.eventId}`,
      source: "system",
      kind: "ingest",
      eventType: row.eventType,
      timestamp: row.createdAt ?? new Date(0).toISOString(),
      title: formatRollupTitle(row.data),
      detail: formatRollupDetail(row.data),
    };
  }
  const detailParts: string[] = [];
  if (row.decisionName) detailParts.push(`decision: ${row.decisionName}`);
  if (row.decisionResult) detailParts.push(`result: ${row.decisionResult}`);
  if (row.decisionReasonCode) detailParts.push(`reason: ${row.decisionReasonCode}`);
  const dataSummary = row.data && Object.keys(row.data).length > 0 ? "data attached" : "";
  if (dataSummary) detailParts.push(dataSummary);
  return {
    id: `system:${row.eventId}`,
    source: "system",
    kind: classifySystemEvent(row.eventType),
    eventType: row.eventType,
    timestamp: row.createdAt ?? new Date(0).toISOString(),
    title: row.eventType,
    detail: detailParts.join(" · ") || undefined,
    findingId: row.findingId ?? undefined,
    assetId: row.assetId ?? undefined,
  };
}

export function useActivityFeed({
  findings,
  auth,
  isAdmin,
  sourceFilter,
  enabled = true,
  systemLimit = 300,
}: UseActivityFeedOptions): UseActivityFeedResult {
  const [systemEvents, setSystemEvents] = useState<ActivityEvent[]>([]);
  const [loadingSystem, setLoadingSystem] = useState(false);
  const [systemError, setSystemError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function loadSystemEvents() {
      if (!enabled || !isAdmin) {
        setSystemEvents([]);
        setLoadingSystem(false);
        setSystemError(null);
        return;
      }
      setLoadingSystem(true);
      setSystemError(null);
      try {
        const res = await fetchAuditEvents({ limit: systemLimit }, auth);
        if (cancelled) return;
        setSystemEvents((res.events ?? []).map(toSystemEvent));
      } catch (err) {
        if (cancelled) return;
        setSystemError(err instanceof Error ? err.message : "Failed to load system events");
        setSystemEvents([]);
      } finally {
        if (!cancelled) setLoadingSystem(false);
      }
    }
    void loadSystemEvents();
    return () => {
      cancelled = true;
    };
  }, [auth?.token, auth?.userEmail, enabled, isAdmin, systemLimit]);

  const findingEvents = useMemo(
    () => rollupFindingEvents(toFindingEvents(findings)),
    [findings],
  );

  const events = useMemo(() => {
    let merged = [...findingEvents, ...systemEvents];
    if (sourceFilter !== "all") {
      merged = merged.filter((e) => e.source === sourceFilter);
    }
    merged.sort((a, b) => {
      const aTs = Date.parse(a.timestamp);
      const bTs = Date.parse(b.timestamp);
      return (Number.isNaN(bTs) ? 0 : bTs) - (Number.isNaN(aTs) ? 0 : aTs);
    });
    return merged;
  }, [findingEvents, sourceFilter, systemEvents]);

  return {
    events,
    loadingSystem,
    systemError,
    canViewSystem: isAdmin,
  };
}

