"use client";

import type { ActivityEvent } from "@/types/activity";

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
  const isFindingEvent = event.source === "finding";
  const sevTone = isFindingEvent ? severityTone(event.severity) : "unknown";
  return (
    <article
      className={`activity-feed-item ${
        isFindingEvent ? `finding-sev-${sevTone}` : ""
      }`.trim()}
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
      {event.detail && <div className="activity-feed-item-detail">{event.detail}</div>}
      <div className="activity-feed-item-links">
        {findingId && onNavigateToFinding && (
          <button
            type="button"
            className="activity-feed-link-btn"
            onClick={() => onNavigateToFinding(findingId)}
          >
            Open finding
          </button>
        )}
        {event.assetId ? (
          <a
            className="activity-feed-link-btn"
            href={`/assets/${encodeURIComponent(event.assetId)}?tab=findings`}
          >
            Open asset
          </a>
        ) : null}
      </div>
    </article>
  );
}

