# Classification Workflow Audit

**Date:** 2025-03-09  
**Scope:** Status updates, Revert, Archive/Unarchive, Bulk update — end-to-end flows and async/error handling.

> **User-facing documentation:** See [Decision Workflow](decision-workflow.md) for the overall decision workflow, statuses, and how to use Revert, Archive, and bulk actions.

---

## 1. Status Update Flow

```
DetailPanel.doUpdate(status, extra)
    │
    ├─ setSaving(true)
    ├─ Build updated: { ...finding, status, justification, comp, rvNote, suppressionScope?, attestation?, audit }
    ├─ await onUpdate(updated)     ← FIXED: now awaited
    ├─ setToast("✓ {status}") on success, "Update failed" on catch
    └─ setSaving(false) in finally

onUpdate = handleUpdate (useVATData)
    │
    ├─ updateFinding(upd.id, { status, justification, ... }, auth)
    │       └─ PATCH /api/findings/{id} → update_finding
    │               ├─ On status change: finding.previous_status = finding.status.value
    │               ├─ finding.status = new_status
    │               └─ justification, compensating_controls, reviewer_note, suppression_scope, attestation
    │
    ├─ toFinding(raw) → setFindings, setSelected
    └─ catch → refetch() + rethrow (caller shows error toast)
```

**Verification:** `previous_status` is set on status change; justification, suppressionScope, attestation passed correctly.

---

## 2. Revert Flow

```
Revert shown when:
  showAdminActions && finding.previousStatus && finding.status !== "Open"

DetailPanel Revert onClick
    │
    ├─ setSaving(true)
    ├─ await onRevert(finding.id, revertReason)   ← FIXED: now awaited
    ├─ On success: setShowRevert(false), setRevertReason(""), setToast("↩ Reverted")
    ├─ On catch: setToast("Revert failed")
    └─ setSaving(false) in finally

handleRevert → revertFinding(id, reason, auth)
    │
    └─ POST /api/findings/{id}/revert { reason }
            └─ revert_finding: requires previous_status; swaps status ↔ previous_status
```

**Verification:** Revert visibility correct; backend requires `previous_status`; status swap correct.

---

## 3. Archive / Unarchive Flow

```
Archive:
  DetailPanel → await onArchive(id, archiveReason)   ← FIXED: now awaited
  handleArchive → archiveFinding(id, reason) → POST /findings/{id}/archive
  Backend: archive_finding → archived=True, archived_at, archived_reason, audit

Unarchive:
  DetailPanel → await onUnarchive(id)   ← FIXED: now awaited (both buttons)
  handleUnarchive → unarchiveFinding(id) → POST /findings/{id}/unarchive
  Backend: unarchive_finding → archived=False, clear archived_*
```

**Verification:** Archive and Unarchive work end-to-end; errors surface to user via toast.

---

## 4. Bulk Update Flow

```
BulkBar.handleApply
    │
    ├─ setApplying(true)
    ├─ await onAction(status, justification)   ← FIXED: now awaited
    ├─ On success: setOpen(false), setJustification("")
    ├─ On catch: setError("Bulk update failed") or onError(msg)
    └─ setApplying(false) in finally

handleBulk → bulkUpdateFindings(ids, status, justification, auth)
    │
    └─ POST /api/findings/bulk
            └─ bulk_update_findings: previous_status set per finding on status change
```

**Verification:** `previous_status` set per finding; errors shown inline or via onError.

---

## 5. Bugs Fixed

| # | Bug | Severity | Fix |
|---|-----|----------|-----|
| 1 | `doUpdate` did not await `onUpdate`; success toast before API completed | High | Made `doUpdate` async; await `onUpdate`; try/catch/finally; error toast |
| 2 | Revert onClick did not await; success toast before API; no error feedback | High | Async handler; await `onRevert`; setSaving; error toast on catch |
| 3 | Archive onClick did not await; no error feedback | Medium | Async handler; await `onArchive`; setSaving; error toast |
| 4 | Unarchive onClick did not await; no error feedback | Medium | Async handlers (both buttons); await `onUnarchive`; error toast |
| 5 | BulkBar `handleApply` did not await; no error feedback | Medium | Async `handleApply`; await `onAction`; inline error state + optional `onError` |

---

## 6. Handler Error Propagation

**useVATData handlers** now rethrow after refetch so callers can show error feedback:

```ts
} catch (err) {
  await refetch();
  throw err;
}
```

---

## 7. `previousStatus` in `toFinding`

Explicit mapping added for robustness:

```ts
previousStatus: raw.previousStatus != null ? String(raw.previousStatus) : null,
```

---

## 8. Expired Waivers and Revert

- `applyWaiverExpiry` transforms expired Risk Accepted → status "Open", previousStatus "Risk Accepted" (client-side).
- Revert is shown when `status !== "Open"` and `previousStatus` exists.
- For expired waivers, displayed status is "Open", so Revert is **not** shown. No change needed.

---

## 9. Prop Types Updated

- `DetailPanel`: `onUpdate`, `onArchive`, `onUnarchive`, `onRevert` accept `void | Promise<void>`.
- `BulkBar`: `onAction` accepts `void | Promise<void>`; optional `onError?: (message: string) => void`.
