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

function toFindingEvents(findings: Finding[]): ActivityEvent[] {
  const rows: ActivityEvent[] = [];
  for (const finding of findings) {
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
        assetId: assetIdForFinding(finding),
        severity: finding.severity,
      });
    }
  }
  return rows;
}

function toSystemEvent(row: ApiAuditEvent): ActivityEvent {
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

  const findingEvents = useMemo(() => toFindingEvents(findings), [findings]);

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

