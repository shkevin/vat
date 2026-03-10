# Design: Finding ↔ External Issue Links

**Status:** Proposal  
**Date:** February 2026  
**Context:** Unified, source-agnostic and tracker-agnostic association between findings and external issues, with bidirectional sync where adapters support it.

---

## 1. Problem

Today:

- **`tracker_id`** — Single string, assumes one tracker. No multi-tracker support.
- **`source_issue_ids`** — Separate structure for sources. Inconsistent with trackers.
- **Sync flow** — Only `create_issue` and `post_decision`. No `update_issue` when VAT fields change.
- **Bidirectional sync** — Trackers (Linear) support inbound (webhook/polling). Sources (Aikido) support inbound (webhooks) and outbound (ignore/unignore). Not all sources support both.
- **State drift** — VAT changes (labels, severity, etc.) are not pushed to trackers.

We need:

1. **Unified link model** — Same structure for sources and trackers.
2. **Capability-driven sync** — Only enqueue/process when the adapter supports the operation.
3. **Bidirectional where supported** — Sources and trackers can sync both ways; adapters declare what they support.
4. **Clean design** — No backward compatibility; efficient lookup; clear separation of concerns.

---

## 2. Design Principles

### 2.1 Single Link Model

One **`external_links`** JSONB array. No `tracker_id`, no `source_issue_ids`. Clean slate.

### 2.2 Capability-Driven Behavior

Adapters declare capabilities. The sync service only enqueues or processes when the adapter supports the operation. No assumptions.

### 2.3 Separation of Concerns

| Layer | Responsibility |
|-------|----------------|
| **Link model** | Store associations. No sync logic. |
| **Sync service** | Orchestrate: decide what to enqueue, process events, check capabilities. |
| **Adapters** | Implement operations. Declare capabilities. |
| **Inbound handlers** | Webhook/polling → find finding by link → apply update. |

---

## 3. Link Structure

```json
{
  "external_links": [
    {
      "adapter_key": "linear",
      "kind": "tracker",
      "issue_id": "AUT-123",
      "url": "https://linear.app/org/issue/AUT-123",
      "created_at": "2026-02-28T12:00:00Z",
      "last_synced_at": "2026-02-28T14:30:00Z",
      "synced_fields": ["labels", "status", "title"]
    },
    {
      "adapter_key": "aikido",
      "kind": "source",
      "issue_id": "aik-abc123",
      "url": null,
      "created_at": "2026-02-27T09:00:00Z"
    }
  ]
}
```

**Fields:**

| Field | Required | Purpose |
|-------|----------|---------|
| `adapter_key` | Yes | Adapter key (linear, jira, aikido). Matches registry and config. |
| `kind` | Yes | `"tracker"` or `"source"` — determines which capabilities apply. |
| `issue_id` | Yes | Native ID in that system. |
| `url` | No | Deep link for UI. |
| `created_at` | Yes | When the link was established. |
| `last_synced_at` | No | (Trackers) Last successful VAT → external sync. |
| `synced_fields` | No | (Trackers) VAT fields last pushed. For change detection. |

---

## 4. Adapter Capabilities

### 4.1 Source Adapters

```python
@dataclass(frozen=True)
class SourceAdapterCapabilities:
    supports_ignore: bool = False
    supports_unignore: bool = False
    supports_inbound_sync: bool = False  # Can receive updates (webhook/polling)?
```

| Capability | Meaning | Example |
|------------|---------|---------|
| `supports_ignore` | VAT can tell source to ignore/suppress | Aikido |
| `supports_unignore` | VAT can tell source to unignore | Aikido |
| `supports_inbound_sync` | Source can push updates to VAT (webhook/polling) | Aikido (webhooks) |

**Push-only sources** (manual, CI): No webhook. `supports_inbound_sync=False`, `supports_ignore=False`, `supports_unignore=False`. Link still stored for provenance.

### 4.2 Tracker Adapters

```python
@dataclass(frozen=True)
class TrackerAdapterCapabilities:
    supports_create_issue: bool = True
    supports_post_comment: bool = True
    supports_update_issue: bool = False  # PATCH labels, status, etc.
    supports_list_issues: bool = False
    supports_inbound_sync: bool = False  # Webhook/polling → VAT
```

| Capability | Meaning | Example |
|------------|---------|---------|
| `supports_create_issue` | Create tracker issue from finding | Linear |
| `supports_post_comment` | Post reviewer decision as comment | Linear |
| `supports_update_issue` | Push VAT field changes to tracker | Linear (when implemented) |
| `supports_list_issues` | List issues for linking | Linear |
| `supports_inbound_sync` | Tracker can push updates to VAT | Linear (webhook/polling) |

### 4.3 Capability Check Before Sync

```python
# Outbound: only enqueue if adapter supports it
if link["kind"] == "tracker":
    caps = get_tracker_capabilities(link["adapter_key"])
    if caps.supports_update_issue and "labels" in changed_fields:
        await enqueue_update_issue(...)

# Inbound: only process if adapter supports sync-back
if adapter.get_capabilities().supports_inbound_sync:
    finding = await find_finding_by_external_id(db, adapter_key, issue_id)
    if finding:
        await apply_inbound_update(finding, payload)
```

---

## 5. Sync Directions

### 5.1 Outbound (VAT → External)

| Event | Kind | When | Adapter check |
|-------|------|------|----------------|
| `create_issue` | tracker | Backfill, manual sync | `supports_create_issue` |
| `post_decision` | tracker | Status → terminal | `supports_post_comment` |
| `update_issue` | tracker | Labels, severity, status, title change | `supports_update_issue` |
| `ignore_issue` | source | Status → FP/Suppressed | `supports_ignore` |
| `unignore_issue` | source | Status → Reopened | `supports_unignore` |

### 5.2 Inbound (External → VAT)

| Source | Mechanism | Adapter check |
|--------|-----------|----------------|
| Tracker (Linear) | Webhook, polling | `supports_inbound_sync` |
| Source (Aikido) | Webhook | `supports_inbound_sync` |

**Flow:** Inbound handler receives payload → parses adapter_key + issue_id → `find_finding_by_external_id()` → if found and adapter supports inbound sync, apply update to finding.

**Not all sources support inbound:** Push-only sources (manual, CI) have no webhook. We never process inbound for them. The link exists only for provenance.

---

## 6. Lookup

```python
def find_finding_by_external_id(
    db: AsyncSession, adapter_key: str, issue_id: str
) -> Finding | None:
    """Find by adapter + issue_id. Works for any source or tracker."""
    from sqlalchemy import type_coerce
    from sqlalchemy.dialects.postgresql import JSONB

    # PostgreSQL: external_links @> '[{"adapter_key":"linear","issue_id":"AUT-123"}]'
    # Array containment: any element in external_links contains the query object
    needle = [{"adapter_key": adapter_key, "issue_id": issue_id}]
    stmt = select(Finding).where(
        Finding.external_links.op("@>")(type_coerce(needle, JSONB))
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()
```

**Index:**

```sql
CREATE INDEX idx_findings_external_links_gin ON findings USING GIN (external_links jsonb_path_ops);
```

**Note:** `@>` for JSONB arrays: left array contains right if each right element is contained in some left element. `{"a":1,"b":2} @> {"a":1}` is true.

---

## 7. Update Issue Flow (VAT → Tracker)

### 7.1 Schema

```python
class VatTrackerUpdateIssueRequest(BaseModel):
    issue_id: str
    finding: dict  # Snapshot: labels, severity, status, title, etc.
    changed_fields: list[str]  # ["labels", "severity", "status"]
```

### 7.2 When to Enqueue

In `update_finding()`: after commit, for each tracker link where adapter `supports_update_issue`, if changed fields intersect syncable fields (labels, severity, status, title).

### 7.3 Adapter Extension

```python
class TrackerAdapter(Protocol):
    # ... existing ...
    async def update_issue(self, request: VatTrackerUpdateIssueRequest) -> None: ...
```

---

## 8. Implementation Phases

### Phase 1: Link Model

1. Add `external_links` column (JSONB, default `[]`).
2. Remove `tracker_id` and `source_issue_ids` columns.
3. Migration: one-time backfill from existing data into `external_links`.
4. Update all read/write paths to use `external_links`.
5. Add GIN index for lookup.

### Phase 2: Capabilities

1. Add `supports_inbound_sync` to source and tracker capabilities.
2. Add `supports_update_issue` to tracker capabilities.
3. In inbound handlers: check `supports_inbound_sync` before applying updates.
4. In outbound: check capabilities before enqueueing.

### Phase 3: Update Issue

1. Add `VatTrackerUpdateIssueRequest`, `update_issue` to adapter protocol.
2. Implement in LinearAdapter.
3. In `update_finding()`: enqueue `update_issue` per tracker link when syncable fields change.

### Phase 4: Closed/Canceled Drift Prevention

When a user closes or cancels a Linear issue without adding a [VAT] block, the finding in VAT stays open — causing drift. To prevent this:

1. **Linear webhook** — Handle `Issue.update` when `stateId` or `state` changes.
2. **Detection** — If the new workflow state is `done` or `canceled`, find the linked finding.
3. **Reopen** — If the finding is not in a terminal status (Open, In Review, etc.), reopen the Linear issue by setting its state to the first open workflow state (backlog, unstarted, or started).
4. **Linear adapter** — `is_state_closed(state_id)`, `reopen_issue(issue_id)`, `_get_open_state_id_for_team(team_uuid)`.

VAT remains source of truth: the tracker must not stay closed unless the finding is properly handled in VAT.

---

## 9. Summary

| Aspect | Design |
|--------|--------|
| Link storage | `external_links` only. No legacy fields. |
| Lookup | By `adapter_key` + `issue_id`. GIN index. |
| Bidirectional | Supported where adapter declares it. `supports_inbound_sync` for both sources and trackers. |
| Sources | Not all support sync-back. Push-only sources: link for provenance, no inbound. |
| Outbound | Capability check before enqueue. `create_issue`, `post_decision`, `update_issue` (trackers); `ignore`, `unignore` (sources). |
| Separation | Link model (data) ↔ Sync service (orchestration) ↔ Adapters (capabilities + impl). |
| Drift prevention | Linear: on Issue.update (state→done/canceled), reopen if finding not terminal. |
