# VAT Decision Workflow

This document describes how findings move through the classification and triage process in VAT. It is intended for security reviewers, engineers, and future maintainers.

---

## Overview

Each finding has a **status** that reflects its current state in the triage lifecycle. Reviewers classify findings by choosing an action (e.g. False Positive, Resolved, Risk Accepted). VAT records every status change in the audit trail and supports **Revert** to undo recent decisions when needed.

---

## Statuses

| Status | Description | SLA Clock |
|--------|-------------|-----------|
| **Open** | New or unclassified finding; awaiting triage | Running |
| **Synced to Tracker** | Pushed to Linear (or other tracker); awaiting engineer response | Running |
| **In Review** | Engineer submitted justification; awaiting security review | Running |
| **Approved** | Risk acceptance approved by reviewer | Stopped |
| **Rejected** | Risk acceptance rejected; engineer must remediate | Running |
| **Risk Accepted** | Formal waiver with named approver and expiry date | Stopped |
| **False Positive** | Scanner is wrong; fingerprint suppressed globally | Stopped |
| **Suppressed** | Real finding, accepted in this context only (e.g. specific deployment) | Stopped |
| **Not Applicable** | Does not apply to this environment | Stopped |
| **Mitigated** | Remediation in progress | Running |
| **Resolved** | Fixed or remediated | Stopped |
| **Duplicate** | Same as another finding; consolidated | Stopped |
| **Reopened** | Previously resolved; re-detected by scanner (regression) | Running |

---

## Classification Actions

From the **Decision** tab in the finding detail panel, reviewers can choose:

### Quick Actions

| Action | Result | When to Use |
|--------|--------|-------------|
| **False Positive** | Status → False Positive, scope = global | Scanner is wrong; same CVE+component will be suppressed on future imports |
| **Suppressed** | Status → Suppressed, scope = contextual | Real vulnerability, accepted for this specific context only |
| **Not Applicable** | Status → Not Applicable | Finding does not apply to this environment |
| **Duplicate** | Status → Duplicate | Same issue as another finding |
| **Resolved** | Status → Resolved | Fixed or remediated |
| **Mitigated** | Status → Mitigated | Remediation in progress |

### Risk Acceptance

| Action | Result | When to Use |
|--------|--------|-------------|
| **Accept Risk** | Status → Risk Accepted | Formal waiver with attestation (approver, title, waiver ref, expiry date) |

Requires: Approver name, Approver title, Waiver reference, Expiry date.

### Waiver Expiry

- When a Risk Accepted finding’s expiry date passes, VAT **auto-reopens** it to Open.
- The Waivers tab and topbar badge warn when waivers expire within 30 days.

---

## Revert

**Revert** undoes the last status change and returns the finding to its previous status.

### When Revert Is Available

- Admin users only
- Finding has a **previous status** (i.e. it was changed from another status)
- Current status is **not** Open

### How to Revert

1. Open the finding detail panel → **Decision** tab
2. Click **↩ Revert**
3. Enter a **reason** (required)
4. Click **Confirm Revert**

The finding returns to its previous status. The revert reason and user are recorded in the audit trail.

---

## Archive

**Archive** removes a finding from the active list without deleting it. Archived findings are retained for audit and can be viewed by enabling the Archived filter.

### When to Archive

- Asset decommissioned
- Finding no longer relevant (e.g. image retired)
- Cleanup of historical noise

### How to Archive

1. Open the finding detail panel → **Decision** tab
2. Click **Archive**
3. Enter a **reason** (required)
4. Click **Confirm Archive**

### Unarchive

Admin users can **Unarchive** a finding to return it to the active list. Use when an archived finding needs to be re-triaged.

---

## Bulk Actions

Reviewers can apply the same status and justification to multiple findings at once.

### Supported Bulk Statuses

- False Positive
- Suppressed
- Duplicate
- Resolved

### How to Bulk Update

1. Select findings (checkboxes in the list)
2. Choose a status (e.g. False Positive)
3. Enter a **shared justification**
4. Click **Apply to N**

Each finding is updated with the same status and justification. The previous status is stored for each finding so Revert remains available.

---

## Status Flow (Simplified)

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                         Open                              │
                    └─────────────────────────────────────────────────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    │                         │                         │
                    ▼                         ▼                         ▼
         Synced to Tracker            In Review                   Direct actions
                    │                         │                    (FP, Suppressed,
                    │                         │                     Resolved, etc.)
                    ▼                         ▼
              In Review              Approved / Rejected /
                                      Risk Accepted / FP /
                                      Suppressed / etc.
                                              │
                                              ▼
                                    Risk Accepted ──(expiry)──► Open
                                    Resolved ──(re-scan)──► Reopened
```

---

## Audit Trail

Every status change, revert, archive, and bulk action is recorded in the finding’s **Audit Trail** (History tab). Each entry includes:

- Timestamp
- User (reviewer, system, or engineer)
- Action (e.g. "Status → False Positive", "Reverted to Open")
- Note (justification, revert reason, etc.)

---

## Related Documentation

- [VAT PRD](VAT-PRD.md) — Product requirements, status machine, attestation
- [Classification Workflow Audit](classification-workflow-audit.md) — Technical implementation and async handling
