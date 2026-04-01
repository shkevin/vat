"use client";

import type { ActivityEventSource } from "@/types/activity";

interface ActivityFeedFiltersProps {
  sourceFilter: ActivityEventSource | "all";
  onSourceFilterChange: (next: ActivityEventSource | "all") => void;
}

const SOURCE_OPTIONS: Array<{ id: ActivityEventSource | "all"; label: string }> = [
  { id: "all", label: "All" },
  { id: "finding", label: "Findings" },
  { id: "system", label: "System" },
];

export function ActivityFeedFilters({
  sourceFilter,
  onSourceFilterChange,
}: ActivityFeedFiltersProps) {
  return (
    <div className="activity-feed-filters">
      <div
        className="activity-feed-source-switch"
        role="tablist"
        aria-label="Activity source filter"
      >
        {SOURCE_OPTIONS.map((opt) => (
          <button
            key={opt.id}
            type="button"
            role="tab"
            aria-selected={sourceFilter === opt.id}
            className="activity-feed-source-tab"
            onClick={() => onSourceFilterChange(opt.id)}
          >
            {opt.label}
          </button>
        ))}
      </div>
    </div>
  );
}

