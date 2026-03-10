# Linear VAT Template

This document describes the structured VAT (Vulnerability Assessment Tracker) template optimized for Linear's markdown editor.

## Linear Markdown Support (Reference)

Linear supports:
- **Headings:** `#`, `##`, `###`
- **Bold/italic:** `**text**`, `_text_`
- **Code:** `` `inline` `` and fenced code blocks
- **Tables:** `/table` or `|--` shortcut
- **Collapsible sections:** `>>>` or `/collapsible` (March 2025+)
- **Lists:** bulleted, numbered, checklists
- **Links:** paste URLs or `Cmd/Ctrl+K`
- **Horizontal dividers:** `___`

## Design Principles

1. **Single source of truth:** File path and source links appear once (in the adapter-built location block), not duplicated in the template.
2. **Parseable format:** Response block must use `status:`, `justification:`, `compensating-controls:` for VAT webhook parsing.
3. **Linear-native:** Use tables, headings, and collapsible sections for better UX.
4. **Copy-paste friendly:** Include a ready-to-fill block engineers can copy and post as a comment.

## Template Structure

The adapter builds the issue body as:

1. **VAT Finding header** (severity, component, type)
2. **Location block** (file, code link, view-in-source link) — *single specification*
3. **Description**
4. **Response template** (below)

## Default Template (Raw)

```
[VAT] {finding_id}

---
### Vulnerability Assessment Response
Post the block below as a **comment** to update this finding in VAT.

| Field | Value |
|-------|-------|
| status | `false-positive` \| `not-applicable` \| `risk-accepted` \| `mitigated` \| `duplicate` |
| justification | _(required — explain why; cite evidence for false-positive)_ |
| compensating-controls | _(optional — e.g. WAF, network segmentation, monitoring)_ |

**Copy-paste and fill in:**
```
[VAT] {finding_id}
status: 
justification: 
compensating-controls: 
```
```

## Placeholders

| Placeholder | Description |
|------------|-------------|
| `{finding_id}` | VAT finding ID for matching responses |
| `{cve_id}` | CVE identifier (fallback for finding_id) |
| `{file_path}` | Path to affected file |
| `{line}` | Line number |
| `{source_file_url}` | Link to code in source |
| `{source_issue_url}` | Link to view in scanner (e.g. Aikido) |

Note: `source_file_url` and `source_issue_url` are rendered in the location block by the adapter — do not duplicate them in the template.
