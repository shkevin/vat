# Enterprise Detail Pane Design

**Date:** 2025-03-09  
**Scope:** VAT Finding Detail Panel — full pane revamp (Details, Decision, History)

## Design Principles

1. **Information hierarchy** — Lead with risk, then narrative, then context, then supporting
2. **Visual callouts** — Metrics as pills; status changes emphasized in timeline
3. **Progressive disclosure** — Collapsible sections for supporting metadata
4. **Workflow clarity** — Decision tab: status card + action groups
5. **Enterprise polish** — 8px grid, structured cards, professional typography

## Layout Structure

### Header (sticky)
- **Hero:** CVE ID (mono, accent) + title (sans, 16px, semibold)
- **Badges row:** TypeTag, SevTag, StTag, SrcTag(s)
- **Meta line:** Component · Asset · CVSS · EPSS (when present)
- **Close button:** Top-right, subtle

### Alerts (conditional)
- Archived banner
- Regression banner
- Secret SLA banner

### Tab navigation
- Details | Decision | History — pill-style, clear active state

### Details tab — Information flow
1. **Risk metrics bar** — Visual pills: CVSS, EPSS, SLA (days, color-coded), Owner
2. **Description** — The narrative (moved up for context)
3. **Finding scope** — Component, Asset, Location, Line preview in key-value card
4. **Subissues** (grouped) — Cards by context when groupFindings
5. **Secret alert** — When findingType === "Secret"
6. **Tracking & Sources** — Collapsible: Source attribution, Tracking grid, Sync to Linear
7. **Regression history** — When regressionCount > 0
8. **Resolution** (when terminal) — Justification, compensating controls
9. **Attestation** (when Risk Accepted) — Structured grid

### Decision tab — Workflow
1. **Status card** — Current status + "Choose an action below"
2. **Reviewer notes** — Editable with Save
3. **Justification & Controls** — Form card
4. **Risk acceptance attestation** — Form card
5. **Suppression type** — Two-option selector (False Positive vs Contextual)
6. **Primary actions** — Approve, Reject, Accept Risk
7. **Resolve & defer** — FP, Suppress, NA, Duplicate, Resolved, Mitigated
8. **Revert / Archive** (admin)

### History tab
- Intro: "Chronological record of all changes"
- **Timeline** — Status changes get accent marker; user + timestamp + action + note
- Status-change items use `status-change` class for visual emphasis

## Implementation

- Add `.detail-panel` CSS classes to `globals.css` (risk bar, metrics pills, action groups, collapsible, timeline)
- `CollapsibleSection` component for Tracking & Sources
- Preserve all existing behavior and props
