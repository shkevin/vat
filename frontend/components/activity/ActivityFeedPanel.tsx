"use client";

import { ActivityFeedFilters } from "@/components/activity/ActivityFeedFilters";
import { ActivityFeedItem } from "@/components/activity/ActivityFeedItem";
import { useMediaQuery } from "@/hooks/useMediaQuery";
import type { ActivityEvent, ActivityEventSource } from "@/types/activity";

interface ActivityFeedPanelProps {
  events: ActivityEvent[];
  loadingSystem: boolean;
  systemError: string | null;
  canViewSystem: boolean;
  collapsed: boolean;
  onCollapsedChange: (next: boolean) => void;
  sourceFilter: ActivityEventSource | "all";
  onSourceFilterChange: (next: ActivityEventSource | "all") => void;
  onNavigateToFinding?: (findingId: string) => void;
}

function relativeMinutes(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "Unknown time";
  const diffMs = Date.now() - d.getTime();
  if (diffMs < 60_000) return "Last minute";
  const mins = Math.max(1, Math.floor(diffMs / 60_000));
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function groupEvents(events: ActivityEvent[]): Array<{ label: string; events: ActivityEvent[] }> {
  const groups = new Map<string, ActivityEvent[]>();
  const order: string[] = [];
  for (const event of events) {
    const d = new Date(event.timestamp);
    const key = Number.isNaN(d.getTime())
      ? "unknown"
      : Date.now() - d.getTime() < 60_000
        ? "last-minute"
        : `${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}-${d.getUTCHours()}-${d.getUTCMinutes()}`;
    if (!groups.has(key)) {
      groups.set(key, []);
      order.push(key);
    }
    groups.get(key)!.push(event);
  }
  return order.map((key) => {
    const gEvents = groups.get(key) ?? [];
    if (key === "unknown" || gEvents.length === 0) {
      return { label: "Unknown time", events: gEvents };
    }
    if (key === "last-minute") {
      return {
        label: `Last minute · ${gEvents.length} update${gEvents.length === 1 ? "" : "s"}`,
        events: gEvents,
      };
    }
    return {
      label: `${relativeMinutes(gEvents[0].timestamp)} · ${gEvents.length} update${
        gEvents.length === 1 ? "" : "s"
      }`,
      events: gEvents,
    };
  });
}

function FeedBody({
  events,
  loadingSystem,
  systemError,
  canViewSystem,
  sourceFilter,
  onSourceFilterChange,
  onNavigateToFinding,
}: Omit<ActivityFeedPanelProps, "collapsed" | "onCollapsedChange">) {
  const grouped = groupEvents(events);
  return (
    <>
      <ActivityFeedFilters
        sourceFilter={sourceFilter}
        onSourceFilterChange={onSourceFilterChange}
      />
      {!canViewSystem && (
        <div className="activity-feed-inline-note">
          System audit events require admin role. Findings stream remains available.
        </div>
      )}
      {loadingSystem && (
        <div className="activity-feed-inline-note">Loading system events…</div>
      )}
      {systemError && <div className="activity-feed-inline-error">{systemError}</div>}
      <div className="activity-feed-list" role="log" aria-label="Activity events">
        {events.length === 0 ? (
          <div className="activity-feed-empty">No activity matches current filters.</div>
        ) : (
          grouped.map((group) => (
            <section key={`${group.label}-${group.events[0]?.id ?? "empty"}`}>
              <div className="activity-feed-group-label">{group.label}</div>
              {group.events.map((event) => (
                <ActivityFeedItem
                  key={event.id}
                  event={event}
                  onNavigateToFinding={onNavigateToFinding}
                />
              ))}
            </section>
          ))
        )}
      </div>
    </>
  );
}

export function ActivityFeedPanel({
  events,
  loadingSystem,
  systemError,
  canViewSystem,
  collapsed,
  onCollapsedChange,
  sourceFilter,
  onSourceFilterChange,
  onNavigateToFinding,
}: ActivityFeedPanelProps) {
  const isCompact = useMediaQuery("(max-width: 1280px)");

  if (isCompact) {
    if (collapsed) {
      return (
        <button
          type="button"
          className="activity-feed-fab"
          onClick={() => onCollapsedChange(false)}
          aria-label="Open activity feed"
        >
          Activity
        </button>
      );
    }
    return (
      <>
        <div
          className="activity-feed-backdrop"
          role="presentation"
          onClick={() => onCollapsedChange(true)}
        />
        <aside className="activity-feed-overlay" aria-label="Activity feed">
          <header className="activity-feed-header">
            <div className="activity-feed-header-title">Activity Feed</div>
            <button
              type="button"
              className="activity-feed-collapse-btn"
              onClick={() => onCollapsedChange(true)}
              aria-label="Close activity feed"
            >
              ×
            </button>
          </header>
          <FeedBody
            events={events}
            loadingSystem={loadingSystem}
            systemError={systemError}
            canViewSystem={canViewSystem}
            sourceFilter={sourceFilter}
            onSourceFilterChange={onSourceFilterChange}
            onNavigateToFinding={onNavigateToFinding}
          />
        </aside>
      </>
    );
  }

  return (
    <aside
      className="activity-feed-dock"
      data-collapsed={collapsed ? "true" : "false"}
      aria-label="Activity feed"
    >
      <header className="activity-feed-header">
        {!collapsed && <div className="activity-feed-header-title">Activity Feed</div>}
        <button
          type="button"
          className="activity-feed-collapse-btn"
          onClick={() => onCollapsedChange(!collapsed)}
          aria-label={collapsed ? "Expand activity feed" : "Collapse activity feed"}
        >
          {collapsed ? "◀" : "▶"}
        </button>
      </header>
      {!collapsed && (
        <FeedBody
          events={events}
          loadingSystem={loadingSystem}
          systemError={systemError}
          canViewSystem={canViewSystem}
          sourceFilter={sourceFilter}
          onSourceFilterChange={onSourceFilterChange}
          onNavigateToFinding={onNavigateToFinding}
        />
      )}
    </aside>
  );
}

