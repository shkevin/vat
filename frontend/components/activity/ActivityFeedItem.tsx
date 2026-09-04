"use client";

import { useState } from "react";
import type { ActivityEvent } from "@/types/activity";
import { encodeAssetIdPath } from "@/lib/assetUtils";

interface ActivityFeedItemProps {
  event: ActivityEvent;
  onNavigateToFinding?: (findingId: string) => void;
}

function severityTone(severity?: string): string {
  const s = (severity ?? "").trim().toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  if (s === "informational" || s === "info") return "info";
  return "unknown";
}

function fmtTs(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const diffMs = Date.now() - d.getTime();
  if (diffMs < 60_000) return "now";
  const mins = Math.floor(diffMs / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function ActivityFeedItem({ event, onNavigateToFinding }: ActivityFeedItemProps) {
  const findingId = event.findingId;
  const relatedFindingIds = event.relatedFindingIds ?? [];
  const relatedFindings = event.relatedFindings ?? [];
  const isRollup = event.eventType === "finding.audit.rollup.asset";
  const [expanded, setExpanded] = useState(false);
  const isFindingEvent = event.source === "finding";
  const sevTone = isFindingEvent ? severityTone(event.severity) : "unknown";
  return (
    <article
      className={`activity-feed-item ${
        isFindingEvent ? `finding-sev-${sevTone}` : ""
      }`.trim()}
      onClick={() => {
        if (isRollup && (relatedFindings.length > 0 || relatedFindingIds.length > 0)) {
          setExpanded((prev) => !prev);
        }
      }}
      role={isRollup && (relatedFindings.length > 0 || relatedFindingIds.length > 0) ? "button" : undefined}
      tabIndex={
        isRollup && (relatedFindings.length > 0 || relatedFindingIds.length > 0) ? 0 : undefined
      }
      onKeyDown={(eventKey) => {
        if (
          isRollup &&
          (relatedFindings.length > 0 || relatedFindingIds.length > 0) &&
          (eventKey.key === "Enter" || eventKey.key === " ")
        ) {
          eventKey.preventDefault();
          setExpanded((prev) => !prev);
        }
      }}
    >
      <div className="activity-feed-item-meta">
        <span className={`activity-feed-source-badge source-${event.source}`}>{event.source}</span>
        {isFindingEvent && (
          <span className={`activity-feed-severity-badge sev-${sevTone}`}>
            {(event.severity ?? "Unknown").toUpperCase()}
          </span>
        )}
        <span className="activity-feed-item-ts" title={new Date(event.timestamp).toLocaleString()}>
          {fmtTs(event.timestamp)}
        </span>
      </div>
      <div className="activity-feed-item-title">{event.title}</div>
      {event.detail && (
        <div className={isRollup ? "activity-feed-item-detail rollup-summary" : "activity-feed-item-detail"}>
          {event.detail}
        </div>
      )}
      <div className="activity-feed-item-links">
        {findingId && onNavigateToFinding && (
          <button
            type="button"
            className="activity-feed-link-btn"
            onClick={(clickEvent) => {
              clickEvent.stopPropagation();
              onNavigateToFinding(findingId);
            }}
          >
            Open finding
          </button>
        )}
        {event.assetId ? (
          <a
            className="activity-feed-link-btn"
            href={`/assets/${encodeAssetIdPath(event.assetId)}?tab=findings`}
            onClick={(clickEvent) => clickEvent.stopPropagation()}
          >
            Open asset
          </a>
        ) : null}
      </div>
      {isRollup && expanded && (relatedFindings.length > 0 || relatedFindingIds.length > 0) && (
        <div className="activity-feed-rollup-list">
          {(relatedFindings.length > 0
            ? relatedFindings.map((entry) => ({
                id: entry.id,
                title: entry.title,
                severity: entry.severity,
                timestamp: entry.timestamp,
              }))
            : relatedFindingIds.map((id) => ({
                id,
                title: "Finding from rollup",
                severity: undefined,
                timestamp: event.timestamp,
              }))
          ).map((entry) => (
            <div key={entry.id} className="activity-feed-rollup-item">
              <div className="activity-feed-rollup-item-main">
                <span
                  className={`activity-feed-severity-badge sev-${severityTone(entry.severity)}`}
                  style={{ alignSelf: "flex-start" }}
                >
                  {(entry.severity ?? "Unknown").toUpperCase()}
                </span>
                <div className="activity-feed-rollup-item-copy">
                  <div className="activity-feed-rollup-item-title">{entry.title}</div>
                  <div className="activity-feed-rollup-item-meta">
                    {entry.id} · {fmtTs(entry.timestamp)}
                  </div>
                </div>
              </div>
              {onNavigateToFinding && (
                <button
                  type="button"
                  className="activity-feed-link-btn"
                  onClick={(clickEvent) => {
                    clickEvent.stopPropagation();
                    onNavigateToFinding(entry.id);
                  }}
                >
                  Open finding
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </article>
  );
}

