"""Linear tracker adapter — GraphQL API for issue creation and comments.
PRD §5.9: Create issues with [VAT] template, post reviewer decisions.
Resilient parsing: key-value extraction, synonym dict, RapidFuzz, spaCy token-based matching."""

import asyncio
import re
import logging
from typing import Optional

import httpx
from rapidfuzz import fuzz, process

try:
    import spacy
    from spacy.matcher import Matcher

    _SPACY_AVAILABLE = True
except ImportError:
    _SPACY_AVAILABLE = False

from app.adapters.base import TrackerAdapter
from app.adapters.registry import TrackerAdapterCapabilities, register_tracker_adapter
from app.core.config import get_settings
from app.schemas.integration_ui import IntegrationFieldSchema, IntegrationSettingsSchema
from app.schemas.vat import (
    VatTrackerCommentUpdate,
    VatTrackerCreateIssueRequest,
    VatTrackerPostDecisionRequest,
    VatTrackerUpdateIssueRequest,
)

logger = logging.getLogger(__name__)

LINEAR_GRAPHQL_DEFAULT = "https://api.linear.app/graphql"

# CVE pattern: CVE-YYYY-NNNNN (4 digits, 4+ digits)
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# UUID pattern for Linear team/entity IDs (team.id expects UUID; team.key is slug like "ENG", "Automatedhass")
_UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _is_uuid(value: str) -> bool:
    """True if value looks like a Linear UUID (used for team.id vs team.key)."""
    return bool(value and _UUID_PATTERN.match(str(value).strip()))


def _team_filter(team_id: str) -> dict:
    """Build team filter for Linear GraphQL. Uses team.key for slugs (e.g. Automatedhass), team.id for UUIDs."""
    tid = (team_id or "").strip()
    if _is_uuid(tid):
        return {"team": {"id": {"eq": tid}}}
    return {"team": {"key": {"eqIgnoreCase": tid}}}


async def _resolve_issue_id(adapter: "LinearAdapter", issue_id: str) -> Optional[str]:
    """
    Resolve issue identifier (e.g. AUT-110) to UUID.
    Linear's IssueFilter no longer has 'identifier' field. Try issue(id:) first (accepts UUID);
    if that returns null for identifier format, fall back to listing team issues and matching by identifier.
    Returns UUID or None if not found.
    """
    if not issue_id or len(issue_id) > 100:
        return None
    stripped = issue_id.strip()
    # Try issue(id:) — works for UUID; may work for identifier depending on Linear version
    query = """
    query Issue($id: String!) {
        issue(id: $id) {
            id
        }
    }
    """
    try:
        result = await adapter._request(query, {"id": stripped})
        issue = result.get("issue")
        if issue:
            return issue.get("id")
    except Exception:
        pass
    # Fallback: list team issues and find by identifier (IssueFilter.identifier was removed)
    if "-" in stripped and len(stripped) < 40:
        try:
            nodes, _ = await adapter.list_issues(first=250, include_archived=True)
            needle = stripped.upper()
            for node in nodes:
                ident = (node.get("identifier") or "").upper()
                if ident == needle:
                    return node.get("id")
        except Exception:
            pass
    return None


async def _resolve_team_uuid(adapter) -> str:
    """
    Resolve team_id to UUID. create_issue requires teamId as UUID; when user provides
    team key (e.g. Automatedhass), fetch teams and return the matching team's id.
    """
    tid = (adapter._team_id or "").strip()
    if _is_uuid(tid):
        return tid
    query = """
    query Teams($filter: TeamFilter!) {
        teams(filter: $filter, first: 1) {
            nodes { id key }
        }
    }
    """
    result = await adapter._request(query, {"filter": {"key": {"eqIgnoreCase": tid}}})
    nodes = result.get("teams", {}).get("nodes", [])
    if nodes:
        return nodes[0]["id"]
    raise ValueError(f"Linear team '{tid}' not found. Use team key (e.g. Automatedhass) or team UUID.")


async def get_organization_url_key(adapter: "LinearAdapter") -> Optional[str]:
    """
    Fetch the organization urlKey for the configured team. Used to build issue URLs
    like https://linear.app/{urlKey}/issue/AUT-29. Returns None on failure.
    """
    tid = (adapter._team_id or "").strip()
    if not tid:
        return None
    try:
        if _is_uuid(tid):
            query = """
            query Team($id: String!) {
                team(id: $id) {
                    organization { urlKey }
                }
            }
            """
            result = await adapter._request(query, {"id": tid})
            team = result.get("team") or {}
        else:
            query = """
            query Teams($filter: TeamFilter!) {
                teams(filter: $filter, first: 1) {
                    nodes { organization { urlKey } }
                }
            }
            """
            result = await adapter._request(query, {"filter": {"key": {"eqIgnoreCase": tid}}})
            nodes = (result.get("teams") or {}).get("nodes") or []
            if not nodes:
                return None
            team = nodes[0] or {}
        org = team.get("organization") or {}
        return org.get("urlKey")
    except Exception:
        return None

# [VAT] block parser per PRD §5.9.3
_VAT_BLOCK_RE = re.compile(
    r"\[VAT\]\s*(?P<cve_id>\S+)\s*\n"
    r"status:\s*(?P<status>false-positive|not-applicable|risk-accepted|mitigated|duplicate)\s*\n"
    r"justification:\s*(?P<justification>.*?)(?:\ncompensating-controls:\s*(?P<compensating>.*?))?(?=\n\n|\n\[|\Z)",
    re.DOTALL | re.IGNORECASE,
)
_VAT_BLOCK_RELAXED_RE = re.compile(
    r"\[VAT\]\s*(?P<cve_id>\S+)\s*\n"
    r"status:\s*(?P<status>[^\n]+?)\s*\n"
    r"justification:\s*(?P<justification>.*?)(?:\ncompensating-controls:\s*(?P<compensating>.*?))?(?=\n\n|\n\[|\Z)",
    re.DOTALL | re.IGNORECASE,
)
# Flexible patterns for AI/developer variations: different casing, no space after colon, abbreviations
# status: / Status: / status : ; justification: / Justification:
_VAT_FLEXIBLE_RE = re.compile(
    r"(?:\[VAT\]\s*(?P<cve_id>\S+)\s*\n\s*)?"
    r"[Ss]tatus\s*:\s*(?P<status>[^\n]+?)\s*\n"
    r"[Jj]ustification\s*:\s*(?P<justification>.*?)(?:\n[Cc]ompensating[- ]?[Cc]ontrols?\s*:\s*(?P<compensating>.*?))?(?=\n\n|\n\[VAT\]|\n[Ss]tatus\s*:|\Z)",
    re.DOTALL | re.IGNORECASE,
)
# Single-line / compact: [VAT] CVE-XXX status: fp justification: because...
_VAT_COMPACT_RE = re.compile(
    r"\[VAT\]\s*(?P<cve_id>\S+)\s+[Ss]tatus\s*:\s*(?P<status>[^\n|]+?)(?:\s*[|]\s*)?\s*[Jj]ustification\s*:\s*(?P<justification>[^\n]+)",
    re.IGNORECASE,
)
_STATUS_MAP = {
    "false-positive": "False Positive",
    "false positive": "False Positive",
    "falsepositive": "False Positive",
    "fp": "False Positive",
    "not-applicable": "Not Applicable",
    "not applicable": "Not Applicable",
    "notapplicable": "Not Applicable",
    "na": "Not Applicable",
    "n/a": "Not Applicable",
    "risk-accepted": "Risk Accepted",
    "risk accepted": "Risk Accepted",
    "riskaccepted": "Risk Accepted",
    "ra": "Risk Accepted",
    "mitigated": "Mitigated",
    "duplicate": "Duplicate",
    "dup": "Duplicate",
}
# Canonical status values for RapidFuzz fuzzy matching (typos, variations)
_STATUS_CANONICAL = ["False Positive", "Not Applicable", "Risk Accepted", "Mitigated", "Duplicate"]
# Alternative keys for key-value extraction (Verdict, Disposition, etc.)
_STATUS_KEYS = ["status", "verdict", "disposition", "result", "outcome"]
_JUSTIFICATION_KEYS = ["justification", "reason", "rationale", "because"]
_COMPENSATING_KEYS = ["compensating-controls", "compensating controls", "compensating", "controls"]


def _normalize_status(raw: str) -> Optional[str]:
    """Normalize status via synonym dict, then RapidFuzz for typos."""
    if not raw or not raw.strip():
        return None
    key = raw.strip().lower().replace(" ", "-").replace("_", "-")
    if key in _STATUS_MAP:
        return _STATUS_MAP[key]
    for k, v in _STATUS_MAP.items():
        if k.replace("-", "") == key.replace("-", ""):
            return v
    # Fuzzy match for typos (e.g. "fals positive", "mitagated")
    match = process.extractOne(raw.strip(), _STATUS_CANONICAL, scorer=fuzz.ratio, score_cutoff=70)
    return match[0] if match else None


def _parse_vat_block(text: str, cve_id_hint: Optional[str] = None) -> Optional[dict]:
    """
    Extract [VAT] block from text (comment or issue body). Resilient to AI/developer variations.
    Returns dict with cve_id, status, justification, compensating_controls or None.
    When cve_id_hint is provided (e.g. from issue context), can parse formats without [VAT] CVE prefix.
    """
    if not text or not isinstance(text, str):
        return None

    def _make_result(cve_id: str, status: str, justification: str, compensating: str = "") -> dict:
        return {
            "cve_id": cve_id.strip(),
            "status": status,
            "justification": (justification or "").strip(),
            "compensating_controls": (compensating or "").strip() if compensating else "",
        }

    def _extract_status(raw: str) -> Optional[str]:
        raw = (raw or "").strip()
        for part in re.split(r"[\s|,/]+", raw):
            normalized = _normalize_status(part)
            if normalized:
                return normalized
        return _normalize_status(raw)

    # 1. Standard [VAT] block
    block_starts = [m.start() for m in re.finditer(r"\[VAT\]\s*\S+", text)]
    for i, start in enumerate(block_starts):
        end = block_starts[i + 1] if i + 1 < len(block_starts) else len(text)
        chunk = text[start:end]
        m = _VAT_BLOCK_RE.search(chunk)
        if m:
            status = _STATUS_MAP.get(m.group("status").lower(), m.group("status"))
            return _make_result(m.group("cve_id"), status, m.group("justification") or "", m.group("compensating") or "")
        m = _VAT_BLOCK_RELAXED_RE.search(chunk)
        if m:
            normalized = _extract_status(m.group("status"))
            if normalized:
                return _make_result(
                    m.group("cve_id"), normalized, m.group("justification") or "", m.group("compensating") or ""
                )

    # 2. Compact/single-line: [VAT] CVE-XXX status: fp justification: ...
    m = _VAT_COMPACT_RE.search(text)
    if m:
        normalized = _extract_status(m.group("status"))
        if normalized:
            return _make_result(m.group("cve_id"), normalized, m.group("justification") or "", "")

    # 3. Flexible format (Status:, Justification: with variations) — requires CVE from [VAT] or hint
    m = _VAT_FLEXIBLE_RE.search(text)
    if m:
        normalized = _extract_status(m.group("status"))
        if normalized:
            cve_id = (m.group("cve_id") or "").strip()
            if cve_id:
                return _make_result(cve_id, normalized, m.group("justification") or "", m.group("compensating") or "")
            if cve_id_hint:
                return _make_result(cve_id_hint, normalized, m.group("justification") or "", m.group("compensating") or "")

    # 4. Context-aware: no [VAT] prefix but has status/justification — use CVE from issue
    if cve_id_hint:
        m = re.search(
            r"[Ss]tatus\s*:\s*(?P<status>[^\n]+)\s*\n\s*[Jj]ustification\s*:\s*(?P<justification>.*?)(?:\n[Cc]ompensating[- ]?[Cc]ontrols?\s*:\s*(?P<compensating>.*?))?(?=\n\n|\Z)",
            text,
            re.DOTALL | re.IGNORECASE,
        )
        if m:
            normalized = _extract_status(m.group("status"))
            if normalized:
                return _make_result(
                    cve_id_hint, normalized, m.group("justification") or "", m.group("compensating") or ""
                )

    # 5. Key-value extraction — flexible keys (Status, Verdict, Justification, Reason), separators : = -
    kv_result = _parse_vat_block_key_value(text, cve_id_hint)
    if kv_result:
        return kv_result

    # 6. spaCy token-based extraction — handles unusual whitespace, fragmented tokens
    if _SPACY_AVAILABLE:
        spacy_result = _parse_vat_block_spacy(text, cve_id_hint)
        if spacy_result:
            return spacy_result

    return None


def _get_spacy_nlp():
    """Lazy-load spaCy model. Returns None if unavailable.
    Install model with: python -m spacy download en_core_web_sm"""
    if not _SPACY_AVAILABLE:
        return None
    try:
        return spacy.load("en_core_web_sm", exclude=["ner", "parser"])
    except OSError:
        try:
            return spacy.load("en_core_web_sm")
        except OSError:
            logger.debug("spaCy en_core_web_sm not found; run: python -m spacy download en_core_web_sm")
            return None


def _parse_vat_block_spacy(text: str, cve_id_hint: Optional[str] = None) -> Optional[dict]:
    """
    Extract VAT fields via spaCy token-based matching. Handles unusual whitespace,
    fragmented tokens, and punctuation variations. Fallback when regex/key-value miss.
    """
    if not text or not isinstance(text, str):
        return None
    nlp = _get_spacy_nlp()
    if nlp is None:
        return None
    cves = LinearAdapter.extract_cve_ids(text)
    cve_id = cve_id_hint or (cves[0] if cves else None)
    if not cve_id:
        return None

    matcher = Matcher(nlp.vocab)
    keys_lower = [k.lower() for k in _STATUS_KEYS + _JUSTIFICATION_KEYS + _COMPENSATING_KEYS]
    # Pattern: key + optional space + separator (: or =). Handles "status:" "Status :" "verdict ="
    for sep in [":", "="]:
        matcher.add("KV", [[{"LOWER": {"IN": keys_lower}}, {"IS_SPACE": True, "OP": "?"}, {"ORTH": sep}]])

    status_val = None
    justification_val = None
    compensating_val = None

    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        doc = nlp(line)
        matches = matcher(doc)
        for match_id, start, end in matches:
            key_token = doc[start]
            key_lower = key_token.text.lower()
            value = doc[end:].text.strip() if end < len(doc) else ""
            if not value:
                continue
            if key_lower in [k.lower() for k in _STATUS_KEYS]:
                status_val = value
            elif key_lower in [k.lower() for k in _JUSTIFICATION_KEYS]:
                justification_val = value
            elif key_lower in [k.lower() for k in _COMPENSATING_KEYS]:
                compensating_val = value

    if not status_val or not justification_val:
        return None
    normalized = _normalize_status(status_val)
    if not normalized:
        return None
    return {
        "cve_id": cve_id,
        "status": normalized,
        "justification": justification_val.strip(),
        "compensating_controls": (compensating_val or "").strip(),
    }


def _parse_vat_block_key_value(text: str, cve_id_hint: Optional[str] = None) -> Optional[dict]:
    """
    Extract VAT fields via key-value pairs. Handles alternative keys (Verdict, Reason)
    and separators (: = -). Fallback when regex patterns miss.
    """
    if not text or not isinstance(text, str):
        return None
    cves = LinearAdapter.extract_cve_ids(text)
    cve_id = cve_id_hint or (cves[0] if cves else None)
    if not cve_id:
        return None

    def _find_value(content: str, keys: list[str]) -> Optional[str]:
        for line in content.split("\n"):
            line_stripped = line.strip()
            for key in keys:
                # Match "key" or "key " followed by : = or -
                pattern = re.compile(
                    rf"^{re.escape(key)}\s*[:=\-]\s*(.+)$",
                    re.IGNORECASE,
                )
                m = pattern.match(line_stripped)
                if m:
                    val = m.group(1).strip()
                    if val:
                        return val
        return None

    status_val = _find_value(text, _STATUS_KEYS)
    justification_val = _find_value(text, _JUSTIFICATION_KEYS)
    if not status_val or not justification_val:
        return None
    normalized = _normalize_status(status_val)
    if not normalized:
        return None
    compensating_val = _find_value(text, _COMPENSATING_KEYS) or ""
    return {
        "cve_id": cve_id,
        "status": normalized,
        "justification": justification_val.strip(),
        "compensating_controls": compensating_val.strip() if compensating_val else "",
    }


@register_tracker_adapter("linear")
class LinearAdapter:
    """Linear GraphQL adapter."""

    @classmethod
    def get_settings_schema(cls) -> IntegrationSettingsSchema:
        """Schema for settings canvas. API key + team + webhook secret."""
        return IntegrationSettingsSchema(
            adapter_key="linear",
            display_name="Linear",
            description="Create issues and post reviewer decisions. Webhook for engineer comments.",
            fields=[
                IntegrationFieldSchema(
                    key="api_key",
                    label="API Key",
                    type="password",
                    required=True,
                    help_text="Linear API key (Settings → API)",
                ),
                IntegrationFieldSchema(
                    key="team_id",
                    label="Team ID",
                    type="text",
                    required=True,
                    placeholder="e.g. ENG or Automatedhass",
                    help_text="Team key (e.g. Automatedhass) or team UUID. Both are supported.",
                ),
                IntegrationFieldSchema(
                    key="webhook_secret",
                    label="Webhook Secret",
                    type="password",
                    required=False,
                    help_text="Optional: verify Linear webhook signatures",
                ),
            ],
            supports_test_connection=True,
            logo_url="https://linear.app/favicon.ico",
            brand_color="#5E6AD2",
            icon="list-checks",
        )

    def __init__(
        self,
        api_key: Optional[str] = None,
        team_id: Optional[str] = None,
        **kwargs: object,  # Accept **creds from resolver
    ):
        settings = get_settings()
        self._api_key = api_key or kwargs.get("api_key") or settings.linear_api_key
        self._team_id = team_id or kwargs.get("team_id") or settings.linear_team_id
        self._graphql_url = settings.linear_api_url or LINEAR_GRAPHQL_DEFAULT
        # Cache label name->id per team to avoid repeated API calls in batch processing
        self._label_cache: dict[str, dict[str, str]] = {}

    def get_capabilities(self) -> TrackerAdapterCapabilities:
        return TrackerAdapterCapabilities(
            supports_create_issue=True,
            supports_post_comment=True,
            supports_update_issue=True,
            supports_list_issues=True,
            supports_inbound_sync=True,  # Webhook/polling push updates to VAT
        )

    def _headers(self) -> dict:
        if not self._api_key:
            raise ValueError("LINEAR_API_KEY not configured")
        return {
            "Authorization": self._api_key,
            "Content-Type": "application/json",
        }

    async def _request(self, query: str, variables: Optional[dict] = None) -> dict:
        """Send GraphQL request. Retries once with delay on RATELIMITED."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        last_error = None
        for attempt in range(2):
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(self._graphql_url, json=payload, headers=self._headers())
                data = resp.json() if resp.content else {}
                errors = data.get("errors", [])
                # Check for rate limit (Linear returns 400 with RATELIMITED code)
                if errors and any(
                    e.get("extensions", {}).get("code") == "RATELIMITED" for e in errors
                ):
                    reset_ms = resp.headers.get("X-RateLimit-Requests-Reset")
                    delay = 65  # Default 65s if no header
                    if reset_ms:
                        import time
                        delay = max(5, (int(reset_ms) / 1000) - time.time())
                    logger.warning(
                        "Linear API rate limited, retrying in %.0fs (attempt %d/2)",
                        delay, attempt + 1,
                    )
                    await asyncio.sleep(min(delay, 120))
                    last_error = RuntimeError(f"Linear API errors: {errors}")
                    continue
                if resp.status_code >= 400:
                    body = resp.text[:1000] if resp.text else str(errors)
                    logger.warning("Linear API HTTP %d: %s", resp.status_code, body)
                    resp.raise_for_status()
                if errors:
                    raise RuntimeError(f"Linear API errors: {errors}")
                return data.get("data", {})
        if last_error:
            raise last_error
        return {}

    async def _create_label(self, team_uuid: str, label_name: str, color: str = "#E53935") -> Optional[str]:
        """
        Create a Linear label for the team if it doesn't exist.
        Returns the new label ID or None on failure.
        When Linear returns "duplicate label name", re-fetches team labels and returns the existing ID.
        Default color: red (#E53935).
        """
        display_name = (label_name or "").strip()
        if not display_name:
            return None
        mutation = """
        mutation IssueLabelCreate($input: IssueLabelCreateInput!) {
            issueLabelCreate(input: $input) {
                issueLabel { id name }
                success
            }
        }
        """
        try:
            result = await self._request(
                mutation,
                {"input": {"teamId": team_uuid, "name": display_name, "color": color}},
            )
            created = result.get("issueLabelCreate", {})
            if created.get("success") and created.get("issueLabel"):
                label_id = created["issueLabel"].get("id")
                logger.info("Created Linear label '%s' (id=%s)", display_name, label_id)
                return label_id
        except RuntimeError as e:
            err_str = str(e).lower()
            if "duplicate label name" in err_str or "already exists" in err_str:
                # Label exists; re-fetch team labels and return the existing ID
                existing = await self._fetch_label_id_by_name(team_uuid, display_name)
                if existing:
                    logger.debug("Using existing Linear label '%s' (id=%s)", display_name, existing)
                    return existing
            logger.warning("Failed to create Linear label '%s': %s", display_name, e)
        except Exception as e:
            logger.warning("Failed to create Linear label '%s': %s", display_name, e)
        return None

    async def _fetch_label_id_by_name(self, team_uuid: str, label_name: str) -> Optional[str]:
        """Fetch team label ID by name (case-insensitive). Returns None if not found."""
        # Use issueLabels with team filter. Linear API max for first is 250.
        query = """
        query IssueLabelsByTeam($filter: IssueLabelFilter!) {
            issueLabels(filter: $filter, first: 250) {
                nodes { id name }
            }
        }
        """
        try:
            result = await self._request(
                query,
                {"filter": {"team": {"id": {"eq": team_uuid}}}},
            )
            nodes = (result.get("issueLabels") or {}).get("nodes", [])
            needle = (label_name or "").strip().lower()
            for n in nodes:
                if n.get("name") and (n["name"] or "").strip().lower() == needle:
                    return n.get("id")
        except Exception as e:
            logger.debug("_fetch_label_id_by_name failed: %s", e)
        return None

    _DEFAULT_LABEL = "security-bug"

    async def _resolve_label_ids(
        self,
        label_names: list[str],
        *,
        create_if_missing: bool = True,
        name_to_color: Optional[dict[str, str]] = None,
        allow_empty: bool = False,
    ) -> list[str]:
        """
        Resolve label names to Linear label IDs. Uses only the configured team's labels.
        When create_if_missing=True, creates missing labels for the team.
        When label_names is empty: if allow_empty=True returns [] (idempotent label removal);
        otherwise uses default "security-bug".
        name_to_color: optional map of label name (lowercase) -> hex color for auto-creation.
        Note: We do NOT fall back to workspace labels—labels are team-scoped; using another
        team's label ID on our issues would fail.
        """
        if not label_names:
            if allow_empty:
                return []
            label_names = [self._DEFAULT_LABEL]
        name_to_color = name_to_color or {}
        team_uuid = await _resolve_team_uuid(self)
        # Reuse cached label map when processing batches (e.g. 19+ update_issue events)
        if team_uuid in self._label_cache:
            name_to_id = self._label_cache[team_uuid]
        else:
            nodes: list[dict] = []
            try:
                query_labels = """
                query IssueLabelsByTeam($filter: IssueLabelFilter!) {
                    issueLabels(filter: $filter, first: 250) {
                        nodes { id name }
                    }
                }
                """
                result = await self._request(
                    query_labels,
                    {"filter": {"team": {"id": {"eq": team_uuid}}}},
                )
                nodes = (result.get("issueLabels") or {}).get("nodes", [])
            except Exception as e:
                logger.debug("Team labels query failed: %s", e)
            name_to_id = {n["name"].lower(): n["id"] for n in nodes if n.get("name")}
            self._label_cache[team_uuid] = name_to_id
        ids = []
        for name in label_names:
            n = (name or "").strip().lower()
            display_name = (name or "").strip()
            if n and n in name_to_id:
                ids.append(name_to_id[n])
            elif n and create_if_missing and team_uuid:
                color = name_to_color.get(n) or "#E53935"
                label_id = await self._create_label(team_uuid, display_name, color)
                if label_id:
                    name_to_id[n] = label_id
                    ids.append(label_id)
                else:
                    logger.warning(
                        "Linear label '%s' not found and auto-creation failed. "
                        "Ensure your API key has Write or Admin permission.",
                        display_name,
                    )
            elif n:
                logger.debug("Linear label '%s' not found; skipping", display_name)
        return ids

    async def create_issue(self, request: VatTrackerCreateIssueRequest) -> str:
        """
        Create Linear issue with [VAT] template in body and optional labels.
        Returns Linear issue identifier (e.g. ENG-123).
        """
        if not self._team_id:
            raise ValueError("LINEAR_TEAM_ID not configured")

        finding = request.finding
        template = request.template
        label_names = request.label_names
        name_to_color = {}
        if request.label_configs:
            for c in request.label_configs:
                if c.name:
                    name_to_color[c.name.strip().lower()] = c.color or "#E53935"

        body = self._build_issue_body(finding, template)
        title = finding.get("title") or finding.get("cveId") or finding.get("cve_id") or "VAT Finding"
        if len(title) > 255:
            title = title[:252] + "..."

        team_uuid = await _resolve_team_uuid(self)
        input_data: dict = {
            "teamId": team_uuid,
            "title": title,
            "description": body,
        }
        label_ids = await self._resolve_label_ids(label_names or [], name_to_color=name_to_color if name_to_color else None)
        if label_ids:
            input_data["labelIds"] = label_ids
        # Set priority from severity (Linear: 0=urgent/none, 1=critical, 2=high, 3=medium, 4=low)
        sev = (finding.get("severity") or "").lower()
        priority_map = {"critical": 1, "high": 2, "medium": 3, "low": 4, "informational": 0}
        input_data["priority"] = priority_map.get(sev, 3)

        mutation = """
        mutation IssueCreate($input: IssueCreateInput!) {
            issueCreate(input: $input) {
                issue { id identifier }
                success
            }
        }
        """
        variables = {"input": input_data}
        result = await self._request(mutation, variables)
        issue_create = result.get("issueCreate", {})
        if not issue_create.get("success"):
            raise RuntimeError("Linear issueCreate failed")
        issue = issue_create.get("issue", {})
        identifier = issue.get("identifier") or issue.get("id")
        if not identifier:
            raise RuntimeError("Linear did not return issue identifier")
        issue_uuid = issue.get("id")  # UUID for efficient poll filtering
        return (identifier, issue_uuid) if issue_uuid else identifier

    async def create_issues_batch(
        self, requests: list[VatTrackerCreateIssueRequest]
    ) -> list[tuple[str, str | None] | Exception]:
        """
        Batch create Linear issues via issueBatchCreate. Reduces API calls for bulk sync.
        Returns list of (identifier, issue_uuid) or Exception per request.
        """
        if not self._team_id:
            raise ValueError("LINEAR_TEAM_ID not configured")
        if not requests:
            return []

        from app.core.config import get_settings

        batch_size = get_settings().tracker_create_batch_size
        max_batch = min(len(requests), max(1, batch_size))
        team_uuid = await _resolve_team_uuid(self)
        name_to_color = {}
        for r in requests:
            if r.label_configs:
                for c in r.label_configs:
                    if c.name:
                        name_to_color[c.name.strip().lower()] = c.color or "#E53935"
        label_ids = await self._resolve_label_ids(
            requests[0].label_names or [], name_to_color=name_to_color if name_to_color else None
        )

        inputs = []
        for req in requests[:max_batch]:
            finding = req.finding or {}
            body = self._build_issue_body(finding, req.template or "")
            title = finding.get("title") or finding.get("cveId") or finding.get("cve_id") or "VAT Finding"
            if len(title) > 255:
                title = title[:252] + "..."
            sev = (finding.get("severity") or "").lower()
            priority_map = {"critical": 1, "high": 2, "medium": 3, "low": 4, "informational": 0}
            inp = {
                "teamId": team_uuid,
                "title": title,
                "description": body,
                "priority": priority_map.get(sev, 3),
            }
            if label_ids:
                inp["labelIds"] = label_ids
            inputs.append(inp)

        mutation = """
        mutation IssueBatchCreate($input: IssueBatchCreateInput!) {
            issueBatchCreate(input: $input) {
                issues { id identifier }
            }
        }
        """
        try:
            result = await self._request(mutation, {"input": {"issues": inputs}})
            payload = result.get("issueBatchCreate", {})
            issues = payload.get("issues") or []
            out: list[tuple[str, str | None] | Exception] = []
            for i, req in enumerate(requests[:max_batch]):
                if i < len(issues):
                    issue = issues[i]
                    ident = issue.get("identifier") or issue.get("id")
                    uuid_val = issue.get("id")
                    if ident:
                        out.append((ident, uuid_val))
                    else:
                        out.append(RuntimeError("Linear did not return issue identifier"))
                else:
                    out.append(RuntimeError("Batch response missing issue"))
            return out
        except Exception as e:
            return [e] * len(requests[:max_batch])

    _REQUIRED_BLOCK = """[VAT] {cve_id}
status: false-positive | not-applicable | risk-accepted | mitigated | duplicate
justification: <required>
compensating-controls: <optional>"""

    def _build_issue_body(self, finding: dict, template: str) -> str:
        """Build issue body with finding details and [VAT] template. Ensures a parseable block exists."""
        cve_id = finding.get("cveId") or finding.get("cve_id") or "unknown"
        finding_id = finding.get("finding_id") or cve_id  # finding_id for unambiguous lookup; fallback to cve_id
        file_path = finding.get("file_path") or finding.get("filePath") or ""
        line = finding.get("line")
        source_file_url = finding.get("source_file_url") or finding.get("sourceFileUrl") or ""
        source_issue_url = finding.get("source_issue_url") or finding.get("sourceIssueUrl") or ""
        location_parts = []
        if file_path:
            location_parts.append(f"**File:** `{file_path}`" + (f" (line {line})" if line else ""))
        if source_file_url:
            location_parts.append(f"**Code:** {source_file_url}")
        if source_issue_url:
            location_parts.append(f"**View in source:** {source_issue_url}")
        location_block = "\n".join(location_parts) + "\n" if location_parts else ""

        try:
            formatted = template.format(
                cve_id=cve_id,
                finding_id=finding_id,
                file_path=file_path or "(not specified)",
                line=line or "(not specified)",
                source_file_url=source_file_url or "(not specified)",
                source_issue_url=source_issue_url or "(not specified)",
            )
        except KeyError:
            formatted = self._REQUIRED_BLOCK.format(cve_id=cve_id)
        # Ensure template has parseable structure; append minimal block if admin removed it
        if "status:" not in formatted or "justification:" not in formatted or "[VAT]" not in formatted:
            formatted = formatted.rstrip() + "\n\n" + self._REQUIRED_BLOCK.format(cve_id=cve_id)
        parts = [
            f"## VAT Finding: {cve_id}",
            "",
            f"**Severity:** {finding.get('severity', 'N/A')}",
            f"**Component:** {finding.get('component') or finding.get('image') or 'N/A'}",
            f"**Type:** {finding.get('findingType') or finding.get('finding_type') or 'SCA'}",
            "",
            location_block,
            (finding.get("description") or ""),
            "",
            "---",
            "",
            formatted,
        ]
        body = "\n".join(parts)
        group_key = finding.get("group_key")
        if group_key:
            body += f"\n\n<!-- [VAT-GROUP: {group_key}] -->"
        return body

    async def post_comment(self, request: VatTrackerPostDecisionRequest) -> None:
        """Post comment to Linear issue. issue_id can be identifier (ENG-123) or UUID."""
        issue_id = request.tracker_issue_id
        body = request.body
        issue_uuid = issue_id
        # If identifier format (e.g. ENG-123), resolve to UUID via issue(id:) query
        if "-" in issue_id and len(issue_id) < 40 and not issue_id.startswith(" "):
            resolved = await _resolve_issue_id(self, issue_id)
            if resolved:
                issue_uuid = resolved

        mutation = """
        mutation CommentCreate($input: CommentCreateInput!) {
            commentCreate(input: $input) {
                comment { id }
                success
            }
        }
        """
        variables = {
            "input": {
                "issueId": issue_uuid,
                "body": body,
            }
        }
        result = await self._request(mutation, variables)
        if not result.get("commentCreate", {}).get("success"):
            raise RuntimeError("Linear commentCreate failed")

    async def update_issue(self, request: VatTrackerUpdateIssueRequest) -> None:
        """Update Linear issue: labels, title, priority. Uses issue_uuid when present to avoid resolve query."""
        issue_id = request.issue_id
        issue_uuid = getattr(request, "issue_uuid", None) or request.issue_id
        if not _is_uuid(issue_uuid) and "-" in issue_id and len(issue_id) < 40 and not issue_id.startswith(" "):
            resolved = await _resolve_issue_id(self, issue_id)
            if resolved:
                issue_uuid = resolved

        input_data: dict = {}
        finding = request.finding
        changed = set(request.changed_fields or [])

        if "labels" in changed:
            name_to_color = {}
            if request.label_configs:
                for c in request.label_configs:
                    if c.name:
                        name_to_color[c.name.strip().lower()] = c.color or "#E53935"
            # allow_empty=True: when VAT labels are empty, clear tracker labels (idempotent)
            label_ids = await self._resolve_label_ids(
                request.label_names or [],
                name_to_color=name_to_color or None,
                allow_empty=True,
            )
            # Linear accepts empty labelIds to clear labels; always set for idempotency
            input_data["labelIds"] = label_ids

        if "title" in changed:
            title = finding.get("title") or finding.get("cveId") or finding.get("cve_id") or "VAT Finding"
            if len(title) > 255:
                title = title[:252] + "..."
            input_data["title"] = title

        if "severity" in changed:
            sev = (finding.get("severity") or "").lower()
            priority_map = {"critical": 1, "high": 2, "medium": 3, "low": 4, "informational": 0}
            input_data["priority"] = priority_map.get(sev, 3)

        if "status" in changed:
            vat_status = (finding.get("status") or "").strip()
            team_uuid = await _resolve_team_uuid(self)
            if team_uuid:
                if self._vat_status_to_should_close(vat_status):
                    state_id = await self._get_done_state_id_for_team(team_uuid)
                else:
                    state_id = await self._get_open_state_id_for_team(team_uuid)
                if state_id:
                    input_data["stateId"] = state_id

        if not input_data:
            return

        mutation = """
        mutation IssueUpdate($id: String!, $input: IssueUpdateInput!) {
            issueUpdate(id: $id, input: $input) {
                success
                issue { id }
            }
        }
        """
        result = await self._request(mutation, {"id": issue_uuid, "input": input_data})
        if not result.get("issueUpdate", {}).get("success"):
            raise RuntimeError("Linear issueUpdate failed")

    async def update_issues_batch(
        self, requests: list[VatTrackerUpdateIssueRequest], batch_size: int | None = None
    ) -> list[tuple[int, Exception | None]]:
        """
        Update multiple issues in batched GraphQL requests (aliased mutations).
        Reduces API calls when processing many corrections. Returns [(index, error), ...].
        """
        if not requests:
            return []
        settings = get_settings()
        # Use generic tracker config; Linear max query complexity 10k → cap at 15
        size = batch_size or min(15, settings.tracker_update_batch_size)
        delay_ms = settings.tracker_batch_delay_ms
        results: list[tuple[int, Exception | None]] = []

        # Resolve issue IDs in one list_issues pass for identifier format (e.g. AUT-123)
        # Skip when issue_uuid is already in the request (avoids list_issues)
        id_to_uuid: dict[str, str] = {}
        for r in requests:
            uid = getattr(r, "issue_uuid", None)
            if uid and _is_uuid(uid):
                id_to_uuid[r.issue_id] = uid
                id_to_uuid[r.issue_id.upper()] = uid
        needs_resolve = [
            r.issue_id for r in requests
            if r.issue_id not in id_to_uuid
            and "-" in r.issue_id
            and len(r.issue_id) < 40
            and not _is_uuid(r.issue_id)
        ]
        if needs_resolve:
            seen: set[str] = set()
            cursor: Optional[str] = None
            for _ in range(20):
                nodes, cursor = await self.list_issues(first=250, after=cursor, include_archived=True)
                for n in nodes:
                    ident = (n.get("identifier") or "").upper()
                    orig = n.get("identifier") or ""
                    if ident and ident not in seen:
                        uid = n.get("id") or ""
                        id_to_uuid[ident] = uid
                        id_to_uuid[orig] = uid
                        seen.add(ident)
                if not cursor:
                    break
            for rid in needs_resolve:
                if rid not in id_to_uuid:
                    resolved = await _resolve_issue_id(self, rid)
                    if resolved:
                        id_to_uuid[rid] = resolved
                        id_to_uuid[rid.upper()] = resolved

        def _uuid(r: VatTrackerUpdateIssueRequest) -> str:
            if _is_uuid(r.issue_id):
                return r.issue_id
            return id_to_uuid.get(r.issue_id) or id_to_uuid.get(r.issue_id.upper()) or r.issue_id

        for batch_start in range(0, len(requests), size):
            batch = requests[batch_start : batch_start + size]
            if batch_start > 0 and delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)

            # Build (batch_idx, issue_uuid, input_data) for each with non-empty input
            updates: list[tuple[int, str, dict]] = []
            for i, req in enumerate(batch):
                input_data: dict = {}
                changed = set(req.changed_fields or [])
                if "labels" in changed:
                    name_to_color = {}
                    if req.label_configs:
                        for c in req.label_configs:
                            if c.name:
                                name_to_color[c.name.strip().lower()] = c.color or "#E53935"
                    label_ids = await self._resolve_label_ids(
                        req.label_names or [], name_to_color=name_to_color or None, allow_empty=True
                    )
                    input_data["labelIds"] = label_ids
                if "title" in changed:
                    f = req.finding or {}
                    title = f.get("title") or f.get("cveId") or f.get("cve_id") or "VAT Finding"
                    input_data["title"] = title[:252] + "..." if len(title) > 255 else title
                if "severity" in changed:
                    sev = (req.finding or {}).get("severity", "").lower()
                    input_data["priority"] = {"critical": 1, "high": 2, "medium": 3, "low": 4, "informational": 0}.get(sev, 3)
                if "status" in changed:
                    vat_status = (req.finding or {}).get("status", "").strip()
                    team_uuid = await _resolve_team_uuid(self)
                    if team_uuid:
                        if self._vat_status_to_should_close(vat_status):
                            state_id = await self._get_done_state_id_for_team(team_uuid)
                        else:
                            state_id = await self._get_open_state_id_for_team(team_uuid)
                        if state_id:
                            input_data["stateId"] = state_id
                if input_data:
                    updates.append((i, _uuid(req), input_data))

            # Initialize batch results as success
            batch_results: dict[int, Exception | None] = {i: None for i in range(len(batch))}

            if updates:
                var_defs = ", ".join(f"$id{j}: String!, $input{j}: IssueUpdateInput!" for j in range(len(updates)))
                parts = [f"u{j}: issueUpdate(id: $id{j}, input: $input{j}) {{ success issue {{ id }} }}" for j in range(len(updates))]
                mutation = f"mutation BatchUpdate({var_defs}) {{ " + " ".join(parts) + " }"
                variables = {}
                for j, (_, uid, inp) in enumerate(updates):
                    variables[f"id{j}"] = uid
                    variables[f"input{j}"] = inp
                try:
                    data = await self._request(mutation, variables)
                    for j, (batch_idx, _, _) in enumerate(updates):
                        ok = (data.get(f"u{j}") or {}).get("success")
                        if not ok:
                            batch_results[batch_idx] = RuntimeError("issueUpdate failed")
                except Exception as e:
                    for batch_idx, _, _ in updates:
                        batch_results[batch_idx] = e

            for i in range(len(batch)):
                results.append((batch_start + i, batch_results[i]))

        return results

    # Linear WorkflowState.type: backlog, unstarted, started, done, canceled
    _CLOSED_STATE_TYPES = frozenset({"done", "canceled"})
    _OPEN_STATE_TYPES = frozenset({"backlog", "unstarted", "started"})
    # VAT statuses that map to Linear "done" (closed); all others map to "open"
    _VAT_CLOSED_STATUSES = frozenset({
        "mitigated", "riskaccepted", "falsepositive", "suppressed",
        "notapplicable", "duplicate", "resolved", "approved", "rejected",
    })

    async def _get_open_state_id_for_team(self, team_uuid: str) -> Optional[str]:
        """Return first open workflow state ID for team (for reopen)."""
        query = """
        query TeamWorkflowStates($teamId: String!) {
            team(id: $teamId) {
                states(first: 50) {
                    nodes { id type }
                }
            }
        }
        """
        try:
            result = await self._request(query, {"teamId": team_uuid})
            team = result.get("team", {})
            states = team.get("states", {}).get("nodes", [])
            for s in states:
                if (s.get("type") or "").lower() in self._OPEN_STATE_TYPES:
                    return s.get("id")
        except Exception as e:
            logger.warning("Failed to fetch workflow states for reopen: %s", e)
        return None

    async def _get_done_state_id_for_team(self, team_uuid: str) -> Optional[str]:
        """Return first done workflow state ID for team (for closing)."""
        query = """
        query TeamWorkflowStates($teamId: String!) {
            team(id: $teamId) {
                states(first: 50) {
                    nodes { id type }
                }
            }
        }
        """
        try:
            result = await self._request(query, {"teamId": team_uuid})
            team = result.get("team", {})
            states = team.get("states", {}).get("nodes", [])
            for s in states:
                if (s.get("type") or "").lower() in self._CLOSED_STATE_TYPES:
                    return s.get("id")
        except Exception as e:
            logger.warning("Failed to fetch workflow states for close: %s", e)
        return None

    def _vat_status_to_should_close(self, vat_status: str) -> bool:
        """True if VAT status maps to Linear closed (done/canceled)."""
        if not vat_status or not isinstance(vat_status, str):
            return False
        return vat_status.strip().lower() in self._VAT_CLOSED_STATUSES

    async def is_state_closed(self, state_id: str) -> bool:
        """True if workflow state is done or canceled."""
        if not state_id:
            return False
        query = """
        query WorkflowState($id: String!) {
            workflowState(id: $id) {
                type
            }
        }
        """
        try:
            result = await self._request(query, {"id": state_id})
            ws = result.get("workflowState", {})
            t = (ws.get("type") or "").lower()
            return t in self._CLOSED_STATE_TYPES
        except Exception as e:
            logger.debug("Could not resolve workflow state %s: %s", state_id, e)
            return False

    async def reopen_issue(self, issue_id: str, team_uuid: Optional[str] = None) -> bool:
        """
        Reopen a closed/canceled Linear issue by setting state to first open workflow state.
        Returns True if reopened, False if skipped or failed.
        """
        issue_uuid = issue_id
        if "-" in issue_id and len(issue_id) < 40 and not issue_id.startswith(" "):
            resolved = await _resolve_issue_id(self, issue_id)
            if resolved:
                issue_uuid = resolved
        if not team_uuid and _is_uuid(issue_id):
            id_query = """
            query Issue($id: String!) {
                issue(id: $id) {
                    id team { id }
                }
            }
            """
            try:
                result = await self._request(id_query, {"id": issue_id})
                issue = result.get("issue", {})
                if issue:
                    team_uuid = (issue.get("team") or {}).get("id")
            except Exception:
                pass
        team_uuid = team_uuid or (await _resolve_team_uuid(self) if self._team_id else None)
        if not team_uuid:
            logger.warning("Cannot reopen: no team UUID")
            return False
        open_state_id = await self._get_open_state_id_for_team(team_uuid)
        if not open_state_id:
            logger.warning("Cannot reopen: no open workflow state found for team %s", team_uuid)
            return False
        mutation = """
        mutation IssueUpdate($id: String!, $input: IssueUpdateInput!) {
            issueUpdate(id: $id, input: $input) {
                success
                issue { id }
            }
        }
        """
        try:
            result = await self._request(mutation, {"id": issue_uuid, "input": {"stateId": open_state_id}})
            if result.get("issueUpdate", {}).get("success"):
                logger.info("Reopened Linear issue %s (VAT finding not yet handled)", issue_id)
                return True
        except Exception as e:
            logger.warning("Failed to reopen Linear issue %s: %s", issue_id, e)
        return False

    def to_vat_comment_update(
        self, payload: dict, issue_body_hint: Optional[str] = None
    ) -> VatTrackerCommentUpdate | None:
        """
        Parse Linear webhook payload to VAT comment update. Returns None if no parseable block.
        issue_body_hint: optional issue description/title for CVE extraction when comment
        format is relaxed (e.g. Status: ... Justification: ... without [VAT] CVE prefix).
        """
        data_body = payload.get("data", payload)
        comment_body = data_body.get("body") or data_body.get("content") or ""
        if isinstance(comment_body, dict):
            comment_body = comment_body.get("body") or comment_body.get("content") or ""
        comment_body = str(comment_body)

        cve_hint = None
        if issue_body_hint:
            cves = self.extract_cve_ids(issue_body_hint)
            cve_hint = cves[0] if cves else None

        parsed = _parse_vat_block(comment_body, cve_id_hint=cve_hint)
        if not parsed:
            return None

        issue_obj = data_body.get("issue") or {}
        issue_id = issue_obj.get("identifier") or issue_obj.get("id") or data_body.get("issueId") or ""
        comment_id = data_body.get("id") or data_body.get("commentId") or ""

        return VatTrackerCommentUpdate(
            cve_id=parsed["cve_id"],
            status=parsed["status"],
            justification=parsed["justification"],
            compensating_controls=parsed["compensating_controls"],
            tracker_issue_id=str(issue_id),
            tracker_comment_id=str(comment_id) if comment_id else None,
        )

    @staticmethod
    def parse_vat_block_from_text(
        text: str, cve_id_hint: Optional[str] = None
    ) -> Optional[dict]:
        """
        Parse [VAT] block from any text (comment or issue body). Use for both
        Comment.create and Issue.update (description change). Returns dict with
        cve_id, status, justification, compensating_controls or None.
        """
        if cve_id_hint:
            return _parse_vat_block(text, cve_id_hint=cve_id_hint)
        cves = LinearAdapter.extract_cve_ids(text)
        hint = cves[0] if cves else None
        return _parse_vat_block(text, cve_id_hint=hint)

    async def list_comments(self, issue_id: str, first: int = 100) -> list[dict]:
        """
        Fetch comments for an issue. issue_id can be identifier (ENG-123) or UUID.
        Returns list of {id, body, createdAt}.
        """
        issue = await self.get_issue_with_comments(issue_id, first=first)
        if not issue:
            return []
        comments = issue.get("comments") or {}
        nodes = comments.get("nodes") or []
        return nodes

    async def get_issue_with_comments(self, issue_id: str, first: int = 100) -> dict | None:
        """Fetch issue with comments. Returns {id, identifier, title, description, comments: {nodes: [...]}} or None."""
        resolved_id = await _resolve_issue_id(self, issue_id) if issue_id else None
        lookup_id = resolved_id or issue_id
        try:
            query = """
            query IssueWithComments($id: String!, $first: Int!) {
                issue(id: $id) {
                    id
                    identifier
                    title
                    description
                    comments(first: $first) {
                        nodes { id body createdAt }
                    }
                }
            }
            """
            result = await self._request(query, {"id": lookup_id, "first": first})
            issue = result.get("issue")
            if issue:
                issue["comments"] = issue.get("comments") or {}
                return issue
        except Exception:
            pass
        return None

    async def get_issue(self, issue_id: str) -> dict | None:
        """Fetch a single issue by identifier (ENG-123) or UUID. Returns {id, identifier, title, description} or None."""
        resolved_id = await _resolve_issue_id(self, issue_id) if issue_id else None
        lookup_id = resolved_id or issue_id
        try:
            result = await self._request(
                "query Issue($id: String!) { issue(id: $id) { id identifier title description } }",
                {"id": lookup_id},
            )
            issue = result.get("issue")
            if issue:
                return issue
        except Exception:
            pass
        return None

    async def list_issues(
        self,
        *,
        first: int = 100,
        after: Optional[str] = None,
        include_archived: bool = False,
        include_comments: bool = False,
        comments_per_issue: int = 50,
        order_by: Optional[str] = None,
    ) -> tuple[list[dict], Optional[str]]:
        """
        List issues for the configured team. Returns (nodes, next_page_cursor).
        Each node: { id, identifier, title, description } or with comments when include_comments=True.
        order_by: 'updatedAt' for recently updated first (recommended for sync), None for createdAt.
        """
        if not self._team_id:
            raise ValueError("LINEAR_TEAM_ID not configured")
        if first > 250:
            first = 250  # Linear API max

        comments_fragment = ""
        if include_comments:
            comments_fragment = f"""
                comments(first: {comments_per_issue}) {{
                    nodes {{ id body createdAt }}
                }}
            """
        order_clause = f", orderBy: {order_by}" if order_by in ("updatedAt", "createdAt") else ""

        team_filter = _team_filter(self._team_id)
        query = f"""
        query TeamIssues($filter: IssueFilter!, $first: Int!, $after: String, $includeArchived: Boolean) {{
            issues(
                filter: $filter
                first: $first
                after: $after
                includeArchived: $includeArchived
                {order_clause}
            ) {{
                pageInfo {{ hasNextPage endCursor }}
                nodes {{
                    id
                    identifier
                    title
                    description
                    {comments_fragment}
                }}
            }}
        }}
        """
        variables = {
            "filter": team_filter,
            "first": first,
            "includeArchived": include_archived,
        }
        if after:
            variables["after"] = after

        result = await self._request(query, variables)
        issues_data = result.get("issues", {})
        nodes = issues_data.get("nodes", [])
        page_info = issues_data.get("pageInfo", {})
        next_cursor = page_info.get("endCursor") if page_info.get("hasNextPage") else None
        return (nodes, next_cursor)

    async def list_issues_by_ids(
        self,
        issue_uuids: list[str],
        *,
        include_comments: bool = True,
        comments_per_issue: int = 50,
    ) -> list[dict]:
        """
        Fetch issues by UUID list. Used for poll to fetch only VAT-tracked issues.
        Linear filter: id: { in: [uuid, ...] }. Returns nodes (no pagination).
        """
        if not issue_uuids:
            return []
        if not self._team_id:
            raise ValueError("LINEAR_TEAM_ID not configured")
        # Linear API limit; batch if needed
        batch_size = 100
        all_nodes: list[dict] = []
        comments_fragment = f"""
            comments(first: {comments_per_issue}) {{
                nodes {{ id body createdAt }}
            }}
        """ if include_comments else ""
        for i in range(0, len(issue_uuids), batch_size):
            batch = issue_uuids[i : i + batch_size]
            query = f"""
            query IssuesByIds($filter: IssueFilter!) {{
                issues(filter: $filter, first: {len(batch)}) {{
                    nodes {{
                        id
                        identifier
                        title
                        description
                        {comments_fragment}
                    }}
                }}
            }}
            """
            variables = {"filter": {"id": {"in": batch}}}
            result = await self._request(query, variables)
            nodes = (result.get("issues") or {}).get("nodes", [])
            all_nodes.extend(nodes)
        return all_nodes

    async def find_existing_issue_for_cve(self, cve_id: str, max_issues: int = 200) -> Optional[str]:
        """
        Search Linear for an existing issue containing the given CVE ID in title or description.
        Returns the first matching issue identifier (e.g. AUT-51), or None if not found.
        Used to avoid creating duplicate Linear issues when multiple VAT findings share the same CVE.
        """
        if not cve_id or not cve_id.strip():
            return None
        cve_upper = cve_id.strip().upper()
        if not _CVE_PATTERN.match(cve_upper):
            return None
        cursor: Optional[str] = None
        fetched = 0
        while fetched < max_issues:
            first = min(100, max_issues - fetched)
            nodes, cursor = await self.list_issues(first=first, after=cursor, include_archived=False)
            fetched += len(nodes)
            for node in nodes:
                identifier = node.get("identifier") or node.get("id")
                if not identifier:
                    continue
                title = node.get("title") or ""
                desc = node.get("description") or ""
                for cve in LinearAdapter.extract_cve_ids(title + " " + desc):
                    if cve == cve_upper:
                        return identifier
            if not cursor:
                break
        return None

    @staticmethod
    def _normalize_title(title: str) -> str:
        """Normalize title for comparison: strip, collapse whitespace, lowercase."""
        if not title or not isinstance(title, str):
            return ""
        return " ".join(title.strip().split()).lower()

    _VAT_GROUP_RE = re.compile(r"\[VAT-GROUP:\s*([^\]]+)\]")

    @staticmethod
    def _extract_group_key(desc: str) -> Optional[str]:
        """Extract [VAT-GROUP: key] from issue description. Returns key or None."""
        if not desc or not isinstance(desc, str):
            return None
        m = LinearAdapter._VAT_GROUP_RE.search(desc)
        return m.group(1).strip() if m else None

    async def find_existing_issue_for_group_key(self, group_key: str, max_issues: int = 200) -> Optional[str]:
        """
        Search Linear for an existing issue containing [VAT-GROUP: group_key] in description.
        Returns the first matching issue identifier, or None if not found.
        Used when pushMode=groups to deduplicate by backend-calculated group key.
        """
        if not group_key or not group_key.strip():
            return None
        needle = group_key.strip()
        cursor: Optional[str] = None
        fetched = 0
        while fetched < max_issues:
            first = min(100, max_issues - fetched)
            nodes, cursor = await self.list_issues(first=first, after=cursor, include_archived=False)
            fetched += len(nodes)
            for node in nodes:
                identifier = node.get("identifier") or node.get("id")
                if not identifier:
                    continue
                desc = node.get("description") or ""
                extracted = self._extract_group_key(desc)
                if extracted and extracted == needle:
                    return identifier
            if not cursor:
                break
        return None

    async def find_existing_issue_for_title(self, title: str, max_issues: int = 200) -> Optional[str]:
        """
        Search Linear for an existing issue with the same (normalized) title.
        Returns the first matching issue identifier (e.g. AUT-51), or None if not found.
        Used to avoid creating duplicate Linear issues when findings share the same title
        but have no CVE (e.g. "SQL injection in user lookup").
        """
        if not title or not title.strip():
            return None
        needle = self._normalize_title(title)
        if not needle:
            return None
        cursor: Optional[str] = None
        fetched = 0
        while fetched < max_issues:
            first = min(100, max_issues - fetched)
            nodes, cursor = await self.list_issues(first=first, after=cursor, include_archived=False)
            fetched += len(nodes)
            for node in nodes:
                identifier = node.get("identifier") or node.get("id")
                if not identifier:
                    continue
                node_title = node.get("title") or ""
                if self._normalize_title(node_title) == needle:
                    return identifier
            if not cursor:
                break
        return None

    @staticmethod
    def extract_cve_ids(text: str) -> list[str]:
        """Extract CVE IDs from issue title or description. Returns normalized list (uppercase, deduped)."""
        if not text or not isinstance(text, str):
            return []
        matches = _CVE_PATTERN.findall(text)
        return list(dict.fromkeys(m.upper() for m in matches))

    async def inject_vat_template_on_issue(
        self,
        issue_id: str,
        cve_id: str,
        template: str,
        *,
        reason: str = "watched label applied",
    ) -> None:
        """
        Post [VAT] template as a comment to an issue. PRD §5.9.4 — when watched label is applied
        or when template was removed/altered (re-injection).
        issue_id: Linear identifier (e.g. ENG-123) or UUID.
        reason: Short reason for injection (e.g. "watched label applied", "template was removed").
        """
        try:
            formatted = template.format(cve_id=cve_id)
        except KeyError:
            formatted = self._REQUIRED_BLOCK.format(cve_id=cve_id)
        if "status:" not in formatted or "justification:" not in formatted or "[VAT]" not in formatted:
            formatted = formatted.rstrip() + "\n\n" + self._REQUIRED_BLOCK.format(cve_id=cve_id)
        body = f"**VAT template injected** ({reason})\n\n{formatted}"
        from app.schemas.vat import VatTrackerPostDecisionRequest

        await self.post_comment(
            VatTrackerPostDecisionRequest(tracker_issue_id=issue_id, body=body)
        )

    def format_canonical_block(self, cve_id: str, status: str, justification: str, compensating: str = "") -> str:
        """Return canonical [VAT] block for posting back to Linear after successful parse."""
        status_lower = status.lower().replace(" ", "-")
        block = f"[VAT] {cve_id}\nstatus: {status_lower}\njustification: {justification}"
        if compensating:
            block += f"\ncompensating-controls: {compensating}"
        return block
