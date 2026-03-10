# E2E Tests — Real Staging Linear Integration

End-to-end tests that run against a **real Linear workspace** (staging/sandbox). Unlike unit tests (respx mocks) and integration tests (WireMock), these hit the live Linear GraphQL API.

## Prerequisites

Configure Linear in VAT **Settings → Tracker** (API key, team ID). The tests use this existing configuration from the database.

## Run

```bash
cd backend

# Run all e2e Linear tests
uv run pytest tests/e2e/test_linear_real.py -v

# Run by marker
uv run pytest -m e2e_linear -v

# Verbose with prints
uv run pytest tests/e2e/test_linear_real.py -v -s
```

Tests are **skipped** when Linear is not configured in VAT settings.

## What Is Tested

| Test | Description |
|------|-------------|
| `test_linear_create_issue` | Create Linear issue with [VAT] template |
| `test_linear_post_comment` | Create issue, post reviewer decision comment |
| `test_linear_list_issues` | List issues from team (pagination) |
| `test_linear_find_existing_issue_for_cve` | Deduplication: find existing issue by CVE |
| `test_linear_find_existing_issue_for_cve_not_found` | Returns None for non-existent CVE |
| `test_linear_webhook_comment_create` | Simulate Linear webhook with [VAT] block → verify finding updated in VAT |
| `test_linear_poll_for_updates` | Poll Linear API for [VAT] blocks, apply to findings |
| **`test_roundtrip_vat_to_linear`** | **VAT → Linear**: Create finding, sync to Linear, verify issue in Linear |
| **`test_roundtrip_linear_to_vat`** | **Linear → VAT**: Create finding + Linear issue with [VAT] comment, poll, verify finding updated |

## Full Flow (Manual)

For a complete manual e2e run:

1. **Start VAT** — `docker compose up` or `uv run uvicorn app.main:app`
2. **Configure Linear** — Settings → Tracker → Linear (API key, team ID)
3. **Create finding** — Ingest, Aikido sync, or seed
4. **Sync to Linear** — POST `/api/sync` or click Sync in UI
5. **Add [VAT] comment in Linear** — e.g. `[VAT] CVE-2024-1234\nstatus: false-positive\njustification: Not used`
6. **Poll or webhook** — POST `/api/sync/poll-linear` or configure Linear webhook URL
7. **Verify** — Finding status updated in VAT

## Webhook Setup (Optional)

To test real webhooks (Linear → VAT):

1. Expose VAT: `ngrok http 8000` or deploy to staging
2. Linear → Settings → API → Webhooks → Add
3. URL: `https://your-vat-url/webhook/linear`
4. Events: Comment (create), Issue (update)
5. Optional: Webhook secret for signature verification

## Troubleshooting: Linear Comment Not Syncing to VAT

When a [VAT] comment in Linear (e.g. `status: risk-accepted`) does not update the finding in VAT:

### 1. Webhook not configured

Linear must send webhooks to VAT when comments are created. If webhooks are not set up:

- Linear → Settings → API → Webhooks → Add
- URL: `https://<your-vat-host>/webhook/linear`
- Events: **Comment** (create), **Issue** (update)
- If VAT has a webhook secret configured, add the same secret in Linear

### 2. Poll not running

If you use polling instead of webhooks:

- Set `VAT_LINEAR_POLL_ENABLED=true` and ensure Celery beat is running (poll runs on schedule)
- Or manually trigger: `POST /api/sync/poll-linear` (admin only)

### 3. Finding lookup fails

VAT finds the finding by: (a) tracker link with `issue_id` (e.g. `AUT-128`), (b) `cve_id` from the [VAT] block (e.g. `SAST-2024-012`).

- **Tracker link**: The finding must have been synced to Linear through VAT (Sync → Linear). Manually created Linear issues have no link.
- **cve_id match**: The finding’s `cve_id` must match the identifier in the [VAT] block. For SAST findings, use the same ID as in the issue description (e.g. `SAST-2024-012`).

Check logs for: `Linear→VAT: no finding found for ... (issue_id=..., cve_id=...)` — this indicates lookup failed.

### 4. Verify integration status

`GET /api/settings/linear/status` (admin) returns:

- `webhookUrl` — URL to configure in Linear
- `webhookSecretConfigured` — whether signature verification is enabled
- `pollEnabled` — whether scheduled polling is on

## CI

Ensure Linear is configured in VAT settings (via DB seed or UI). Use a dedicated Linear workspace for CI to avoid polluting production data.
