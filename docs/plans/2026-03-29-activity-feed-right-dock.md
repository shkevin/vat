# VAT Activity Feed Right Dock Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a Twitch-like, right-side, collapsible activity feed that merges finding audit history and system audit events, with source/event filtering.

**Architecture:** Keep data-fetching and normalization in a dedicated hook and present a focused UI panel component that can be docked or collapsed. Integrate panel state into existing layout patterns in `VATLayout`, with responsive drawer behavior on smaller screens and role-aware loading for admin-only system audit events.

**Tech Stack:** Next.js/React client components, TypeScript, existing VAT contexts/hooks, existing REST API layer (`frontend/lib/api.ts`), existing theme tokens and global CSS.

---

### Task 1: Add Activity Feed Domain Types + API Client

**Files:**
- Create: `frontend/types/activity.ts`
- Modify: `frontend/lib/api.ts`

**Step 1: Add normalized activity event types**
- Define `ActivityEventSource`, `ActivityEventKind`, and `ActivityEvent`.
- Include normalized fields: id, source, timestamp, title, detail, eventType, findingId, assetId, severity.

**Step 2: Add system audit API call**
- Add `fetchAuditEvents` in `frontend/lib/api.ts` calling `GET /audit/events`.
- Include filter args (`limit`, `dateFrom`, `dateTo`, `eventType`) and map response fields.
- Keep auth handling aligned with existing helpers and return typed payload.

**Step 3: Validate typing**
- Run TS/lint check for files touched and resolve any type drift.

### Task 2: Build Activity Feed Data Hook

**Files:**
- Create: `frontend/components/activity/useActivityFeed.ts`
- Modify: `frontend/types/index.ts` (only if needed for type re-export)

**Step 1: Map finding audit trail events**
- Convert `Finding.audit[]` entries into normalized `ActivityEvent` objects.
- Preserve linkage to finding id and source info where available.

**Step 2: Fetch and map system audit events**
- For admin users only, call `fetchAuditEvents`.
- Handle unauthorized/forbidden gracefully and expose an informational state.

**Step 3: Merge + filter**
- Merge both streams, sort by descending timestamp.
- Implement source filter (`all|finding|system`) plus kind/event-type filtering.
- Expose loading/error/admin-gated metadata from hook.

### Task 3: Build Feed UI Components

**Files:**
- Create: `frontend/components/activity/ActivityFeedPanel.tsx`
- Create: `frontend/components/activity/ActivityFeedFilters.tsx`
- Create: `frontend/components/activity/ActivityFeedItem.tsx`
- Modify: `frontend/app/globals.css`

**Step 1: Panel shell**
- Add panel header, collapse toggle, scrolling list region, and empty/loading/error states.

**Step 2: Filter controls**
- Add source switcher (`All`, `Findings`, `System`).
- Add event-kind multi-select filter controls.
- Keep controls keyboard accessible and theme-token based.

**Step 3: Event row rendering**
- Show timestamp, source badge, event title/detail, and optional finding/asset linkage.
- Add subtle visual hierarchy aligned with existing design system.

### Task 4: Integrate into Existing Layout + Persist UI Preferences

**Files:**
- Modify: `frontend/components/layout/VATLayout.tsx`
- Modify: `frontend/components/VAT.tsx`
- Modify: `frontend/lib/userPreferencesStorage.ts`
- Modify: `frontend/contexts/UserPreferencesContext.tsx` (if needed)

**Step 1: Add right-dock slot in layout**
- Introduce a right activity-feed column in the `VATLayout` content row.
- Keep current filter sidebar + main content behavior unchanged.

**Step 2: Add collapse behavior**
- Expanded width ~340px; collapsed rail ~36px.
- On small screens, render as overlay drawer with ESC/backdrop close.

**Step 3: Persist feed preferences**
- Save `activityFeedCollapsed`, `activityFeedSourceFilter`, and event-kind filter selections in existing user preference storage.

**Step 4: Wire from VAT page**
- Compose hook + panel in `VAT.tsx`.
- Pass required props to `VATLayout`.

### Task 5: Verify and Harden

**Files:**
- Test/verify impacted files from previous tasks.

**Step 1: Static verification**
- Run lint/type checks scoped to frontend.
- Fix any introduced issues.

**Step 2: Behavioral verification**
- Confirm:
  - feed visible by default on desktop;
  - collapses/expands cleanly;
  - source filter switches streams;
  - non-admin users do not break when system events are unavailable.

**Step 3: Regression sanity checks**
- Validate existing main area scroll and detail panel behavior remain unchanged.

