"""Watched label auto-inject — PRD §5.9.4. When a watched label is applied to a Linear issue, inject [VAT] template.
Template re-injection: when issue description no longer has parseable [VAT] block, re-append template as comment."""

import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.linear import LinearAdapter
from app.api.settings import get_labels, get_linear_credentials, get_tracker_issue_template
from app.core.config import get_settings

logger = logging.getLogger(__name__)


def _label_ids_from_issue(data: dict) -> list[str]:
    """Extract label IDs from Linear webhook issue data. Handles labelIds or labels.nodes[].id."""
    issue = data.get("issue") or data
    labels = issue.get("labels") or issue.get("labelIds") or []
    if isinstance(labels, dict) and "nodes" in labels:
        labels = labels["nodes"]
    if isinstance(labels, list):
        out = []
        for item in labels:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict) and item.get("id"):
                out.append(item["id"])
        return out
    return []


def _label_ids_from_updated_from(updated_from: dict) -> list[str]:
    """Extract previous label IDs from updatedFrom."""
    labels = updated_from.get("labels") or updated_from.get("labelIds") or []
    if isinstance(labels, list):
        return [x for x in labels if isinstance(x, str)]
    return []


async def handle_issue_label_update(
    db: AsyncSession,
    data: dict,
    updated_from: dict,
) -> dict | None:
    """
    When an Issue.update webhook adds a watched label, inject [VAT] template.
    Returns result dict for webhook response, or None if not applicable.
    """
    api_key, team_id, _ = await get_linear_credentials(db)
    if not api_key or not team_id:
        return None

    labels_cfg = await get_labels(db)
    watched_names = [str(l.get("name", "")).strip() for l in labels_cfg if l.get("name")]
    if not watched_names:
        return None

    # Require updatedFrom.labelIds so we know labels changed (avoid injecting on unrelated updates)
    if "labelIds" not in updated_from and "labels" not in updated_from:
        return None
    current_ids = set(_label_ids_from_issue(data))
    previous_ids = set(_label_ids_from_updated_from(updated_from))
    added_ids = current_ids - previous_ids
    if not added_ids:
        return None

    adapter = LinearAdapter(api_key=api_key, team_id=team_id)
    watched_label_ids = await adapter._resolve_label_ids(watched_names)
    if not watched_label_ids:
        return None

    if not added_ids.intersection(set(watched_label_ids)):
        return None

    issue_obj = data.get("issue") or data
    issue_id = issue_obj.get("identifier") or issue_obj.get("id") or data.get("issueId") or ""
    if not issue_id:
        return None

    issue = await adapter.get_issue(str(issue_id))
    if not issue:
        logger.warning("Watched label inject: could not fetch issue %s", issue_id)
        return None

    desc = (issue.get("description") or "") + (issue.get("title") or "")
    if "[VAT]" in desc and "status:" in desc:
        return {"injected": False, "reason": "issue already has [VAT] block"}

    cve_ids = LinearAdapter.extract_cve_ids(desc)
    cve_id = cve_ids[0] if cve_ids else issue.get("identifier") or "unknown"

    template = await get_tracker_issue_template(db)
    try:
        await adapter.inject_vat_template_on_issue(str(issue_id), cve_id, template)
        logger.info("Watched label inject: injected [VAT] template on issue %s (cve=%s)", issue_id, cve_id)
        return {"injected": True, "issue_id": issue_id, "cve_id": cve_id}
    except Exception as e:
        logger.exception("Watched label inject failed for issue %s: %s", issue_id, e)
        return {"injected": False, "error": str(e)}


async def handle_template_reinject(
    db: AsyncSession,
    adapter: LinearAdapter,
    issue_obj: dict,
    issue_id: str,
    new_description: str,
) -> dict | None:
    """
    When issue description no longer has parseable [VAT] block, re-inject template as comment.
    Returns result dict or None if not applicable (template present or reinject disabled).
    """
    if not get_settings().linear_reinject_on_removal:
        return None
    if not new_description or not isinstance(new_description, str):
        return None
    # Check if description has parseable block
    parsed = LinearAdapter.parse_vat_block_from_text(new_description)
    if parsed:
        return None  # Template present and parseable
    # Check for minimal structure (status: and justification: or alternatives)
    has_status = any(k in new_description.lower() for k in ["status:", "verdict:", "disposition:"])
    has_justification = any(k in new_description.lower() for k in ["justification:", "reason:", "rationale:"])
    if has_status and has_justification:
        return None  # Has structure, parsing may have failed for other reasons
    cves = LinearAdapter.extract_cve_ids(new_description)
    cve_id = cves[0] if cves else (issue_obj.get("identifier") or "unknown")
    template = await get_tracker_issue_template(db)
    try:
        await adapter.inject_vat_template_on_issue(
            str(issue_id), cve_id, template, reason="template was removed or altered — please use the format below"
        )
        logger.info("Template re-inject: injected [VAT] template on issue %s (cve=%s)", issue_id, cve_id)
        return {"reinjected": True, "issue_id": issue_id, "cve_id": cve_id}
    except Exception as e:
        logger.exception("Template re-inject failed for issue %s: %s", issue_id, e)
        return {"reinjected": False, "error": str(e)}
