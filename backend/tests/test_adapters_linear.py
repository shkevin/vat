"""Tests for Linear adapter using respx to mock the GraphQL API.
Comprehensive parsing tests to ensure VAT block extraction is robust and fault-tolerant."""

import pytest

from app.adapters.linear import LinearAdapter
from app.schemas.vat import (
    VatTrackerCreateIssueRequest,
    VatTrackerPostDecisionRequest,
    VatTrackerUpdateIssueRequest,
)


# ---------------------------------------------------------------------------
# CVE extraction
# ---------------------------------------------------------------------------


class TestExtractCveIds:
    """Extract CVE IDs from issue title/description."""

    def test_single_cve(self):
        assert LinearAdapter.extract_cve_ids("Fix CVE-2024-1234") == ["CVE-2024-1234"]

    def test_multiple_cves_deduplicated_ordered(self):
        assert LinearAdapter.extract_cve_ids("CVE-2023-9999 and CVE-2024-1234") == [
            "CVE-2023-9999",
            "CVE-2024-1234",
        ]

    def test_vat_finding_prefix(self):
        assert LinearAdapter.extract_cve_ids("VAT Finding: CVE-2024-21626") == ["CVE-2024-21626"]

    def test_no_cve(self):
        assert LinearAdapter.extract_cve_ids("no cve here") == []
        assert LinearAdapter.extract_cve_ids("") == []
        assert LinearAdapter.extract_cve_ids(None) == []

    def test_cve_with_many_digits(self):
        assert LinearAdapter.extract_cve_ids("CVE-2024-12345678") == ["CVE-2024-12345678"]

    def test_case_insensitive_returns_uppercase(self):
        assert LinearAdapter.extract_cve_ids("cve-2024-1234") == ["CVE-2024-1234"]


# ---------------------------------------------------------------------------
# Standard [VAT] block format
# ---------------------------------------------------------------------------


class TestParseVatBlockStandard:
    """Standard [VAT] block format per PRD §5.9.3."""

    def test_basic_format(self):
        text = "[VAT] CVE-2024-1234\nstatus: false-positive\njustification: Not in use"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-1234"
        assert result["status"] == "False Positive"
        assert result["justification"] == "Not in use"
        assert result["compensating_controls"] == ""

    def test_with_compensating_controls(self):
        text = "[VAT] CVE-2024-1234\nstatus: risk-accepted\njustification: Accepted\ncompensating-controls: WAF rule"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["compensating_controls"] == "WAF rule"

    def test_compensating_controls_optional_absent(self):
        text = "[VAT] CVE-2024-1234\nstatus: mitigated\njustification: Patched"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["compensating_controls"] == ""


# ---------------------------------------------------------------------------
# All status values and aliases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status_input,expected_canonical",
    [
        ("false-positive", "False Positive"),
        ("false positive", "False Positive"),
        ("fp", "False Positive"),
        ("not-applicable", "Not Applicable"),
        ("not applicable", "Not Applicable"),
        ("na", "Not Applicable"),
        ("n/a", "Not Applicable"),
        ("risk-accepted", "Risk Accepted"),
        ("risk accepted", "Risk Accepted"),
        ("ra", "Risk Accepted"),
        ("mitigated", "Mitigated"),
        ("duplicate", "Duplicate"),
        ("dup", "Duplicate"),
    ],
)
def test_all_status_values_and_aliases(status_input, expected_canonical):
    """All status values and aliases normalize correctly."""
    text = f"[VAT] CVE-2024-1234\nstatus: {status_input}\njustification: test"
    result = LinearAdapter.parse_vat_block_from_text(text)
    assert result is not None
    assert result["status"] == expected_canonical


# ---------------------------------------------------------------------------
# Casing and formatting variations
# ---------------------------------------------------------------------------


class TestParseVatBlockCasing:
    """Status/Justification with different casing."""

    def test_sentence_case(self):
        text = "[VAT] CVE-2024-1234\nStatus: false positive\nJustification: Package not used"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["status"] == "False Positive"
        assert result["justification"] == "Package not used"

    def test_uppercase(self):
        text = "[VAT] CVE-2024-1234\nSTATUS: MITIGATED\nJUSTIFICATION: FIXED"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["status"] == "Mitigated"
        assert result["justification"] == "FIXED"

    def test_no_space_after_colon(self):
        text = "[VAT] CVE-2024-1234\nstatus:fp\njustification:not used"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["status"] == "False Positive"


# ---------------------------------------------------------------------------
# Compact / single-line format
# ---------------------------------------------------------------------------


class TestParseVatBlockCompact:
    """Single-line / compact format."""

    def test_single_line(self):
        text = "[VAT] CVE-2024-1234 status: mitigated justification: Patched in v2"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-1234"
        assert result["status"] == "Mitigated"
        assert result["justification"] == "Patched in v2"

    def test_with_pipe_separator(self):
        text = "[VAT] CVE-2024-1234 status: fp | justification: N/A"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["status"] == "False Positive"


# ---------------------------------------------------------------------------
# Context-aware (CVE from hint)
# ---------------------------------------------------------------------------


class TestParseVatBlockContextAware:
    """Format without [VAT] CVE prefix when CVE hint from issue."""

    def test_status_justification_only_with_hint(self):
        text = "Status: risk-accepted\nJustification: Accepted by security team"
        result = LinearAdapter.parse_vat_block_from_text(text, cve_id_hint="CVE-2024-1234")
        assert result is not None
        assert result["cve_id"] == "CVE-2024-1234"
        assert result["status"] == "Risk Accepted"

    def test_cve_extracted_from_surrounding_text(self):
        text = "VAT Finding: CVE-2024-5678\n\nStatus: false-positive\nJustification: Not used"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-5678"


# ---------------------------------------------------------------------------
# Key-value extraction: alternative keys
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status_key,justification_key",
    [
        ("status", "justification"),
        ("Status", "Justification"),
        ("verdict", "reason"),
        ("Verdict", "Reason"),
        ("disposition", "rationale"),
        ("Disposition", "Rationale"),
        ("result", "because"),
        ("outcome", "justification"),
    ],
)
def test_key_value_alternative_keys(status_key, justification_key):
    """Key-value extraction with all alternative keys."""
    text = f"CVE-2024-1234\n{status_key}: mitigated\n{justification_key}: Patched"
    result = LinearAdapter.parse_vat_block_from_text(text)
    assert result is not None
    assert result["cve_id"] == "CVE-2024-1234"
    assert result["status"] == "Mitigated"
    assert result["justification"] == "Patched"


# ---------------------------------------------------------------------------
# Key-value extraction: separators
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sep", [":", "=", "-"])
def test_key_value_separators(sep):
    """Key-value extraction with : = - separators."""
    text = f"CVE-2024-5678\nstatus {sep} mitigated\njustification {sep} Patched in v2"
    result = LinearAdapter.parse_vat_block_from_text(text)
    assert result is not None
    assert result["status"] == "Mitigated"
    assert result["justification"] == "Patched in v2"


# ---------------------------------------------------------------------------
# RapidFuzz typo handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "typo,expected",
    [
        ("fals positive", "False Positive"),
        ("mitagated", "Mitigated"),
        ("duplicat", "Duplicate"),
        ("risk-accepted", "Risk Accepted"),
    ],
)
def test_fuzzy_typo_handling(typo, expected):
    """RapidFuzz handles typos in status."""
    text = f"[VAT] CVE-2024-1234\nstatus: {typo}\njustification: typo test"
    result = LinearAdapter.parse_vat_block_from_text(text)
    assert result is not None
    assert result["status"] == expected


# ---------------------------------------------------------------------------
# Compensating controls
# ---------------------------------------------------------------------------


class TestCompensatingControls:
    """Compensating controls extraction."""

    def test_compensating_controls_key(self):
        text = "[VAT] CVE-2024-1234\nstatus: risk-accepted\njustification: OK\ncompensating-controls: WAF rule"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["compensating_controls"] == "WAF rule"

    def test_compensating_controls_alternative_key(self):
        text = "CVE-2024-1234\nstatus: mitigated\njustification: Fixed\ncompensating controls: Monitoring"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["compensating_controls"] == "Monitoring"


# ---------------------------------------------------------------------------
# Invalid / failure cases
# ---------------------------------------------------------------------------


class TestParseVatBlockInvalid:
    """Invalid or missing format returns None."""

    def test_empty_string(self):
        assert LinearAdapter.parse_vat_block_from_text("") is None

    def test_none(self):
        assert LinearAdapter.parse_vat_block_from_text(None) is None

    def test_random_prose(self):
        assert LinearAdapter.parse_vat_block_from_text("Just some random text") is None

    def test_status_only_no_cve(self):
        assert LinearAdapter.parse_vat_block_from_text("status: fp") is None

    def test_status_only_no_justification(self):
        assert LinearAdapter.parse_vat_block_from_text("CVE-2024-1234\nstatus: fp") is None

    def test_justification_only_no_status(self):
        assert LinearAdapter.parse_vat_block_from_text("CVE-2024-1234\njustification: test") is None

    def test_invalid_status_unrecognized(self):
        text = "[VAT] CVE-2024-1234\nstatus: xyzzy\njustification: test"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is None

    def test_status_too_fuzzy(self):
        """Status that is too far from any canonical to match."""
        text = "[VAT] CVE-2024-1234\nstatus: qwerty\njustification: test"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is None

    def test_whitespace_only(self):
        assert LinearAdapter.parse_vat_block_from_text("   \n\n  ") is None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestParseVatBlockEdgeCases:
    """Edge cases."""

    def test_justification_with_newlines(self):
        text = "[VAT] CVE-2024-1234\nstatus: false-positive\njustification: Line one\nLine two\nLine three"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert "Line one" in result["justification"]
        assert "Line two" in result["justification"]

    def test_justification_with_special_chars(self):
        text = "[VAT] CVE-2024-1234\nstatus: fp\njustification: See https://example.com/issue#123"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert "https://example.com" in result["justification"]

    def test_prose_before_block(self):
        text = "Some intro text.\n\n[VAT] CVE-2024-1234\nstatus: mitigated\njustification: Done"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-1234"

    def test_prose_after_block(self):
        text = "[VAT] CVE-2024-1234\nstatus: fp\njustification: OK\n\nMore discussion below."
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["justification"] == "OK"

    def test_status_with_pipe_or_comma_takes_first(self):
        text = "[VAT] CVE-2024-1234\nstatus: fp | duplicate\njustification: test"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["status"] == "False Positive"

    def test_multiple_vat_blocks_first_wins(self):
        text = "[VAT] CVE-2024-1111\nstatus: fp\njustification: first\n\n[VAT] CVE-2024-2222\nstatus: mitigated\njustification: second"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-1111"
        assert result["status"] == "False Positive"

    def test_trailing_whitespace(self):
        text = "  [VAT] CVE-2024-1234  \n  status: fp  \n  justification: test  "
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-1234"
        assert result["justification"] == "test"

    def test_long_justification_preserved(self):
        justification = "A" * 500
        text = f"[VAT] CVE-2024-1234\nstatus: mitigated\njustification: {justification}"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["justification"] == justification

    def test_mixed_separators_in_block(self):
        """Key-value can use different separators for different keys."""
        text = "CVE-2024-1234\nstatus: fp\njustification= Not used in production"
        result = LinearAdapter.parse_vat_block_from_text(text)
        assert result is not None
        assert result["status"] == "False Positive"
        assert result["justification"] == "Not used in production"


# ---------------------------------------------------------------------------
# to_vat_comment_update (webhook payload parsing)
# ---------------------------------------------------------------------------


class TestToVatCommentUpdate:
    """Parse Linear webhook payload to VatTrackerCommentUpdate."""

    def test_standard_payload(self):
        adapter = LinearAdapter()
        payload = {
            "data": {
                "body": "[VAT] CVE-2024-1234\nstatus: false-positive\njustification: Not used",
                "issue": {"identifier": "ENG-123", "id": "uuid-1"},
                "id": "comment-1",
            }
        }
        result = adapter.to_vat_comment_update(payload)
        assert result is not None
        assert result.cve_id == "CVE-2024-1234"
        assert result.status == "False Positive"
        assert result.justification == "Not used"
        assert result.tracker_issue_id == "ENG-123"
        assert result.tracker_comment_id == "comment-1"

    def test_unparseable_returns_none(self):
        adapter = LinearAdapter()
        payload = {"data": {"body": "Random comment", "issue": {"identifier": "ENG-123"}}}
        result = adapter.to_vat_comment_update(payload)
        assert result is None

    def test_issue_body_hint_for_cve(self):
        """Webhook passes issue description+title as hint when comment has no CVE."""
        adapter = LinearAdapter()
        payload = {
            "data": {
                "body": "Status: mitigated\nJustification: Fixed",
                "issue": {
                    "identifier": "ENG-123",
                    "description": "VAT Finding: CVE-2024-5678",
                    "title": "Fix CVE",
                },
            }
        }
        issue_body_hint = "VAT Finding: CVE-2024-5678 Fix CVE"
        result = adapter.to_vat_comment_update(payload, issue_body_hint=issue_body_hint)
        assert result is not None
        assert result.cve_id == "CVE-2024-5678"

    def test_minimal_payload_missing_ids(self):
        """Gracefully handles payload with missing issue/comment identifiers."""
        adapter = LinearAdapter()
        payload = {
            "data": {
                "body": "[VAT] CVE-2024-1234\nstatus: fp\njustification: OK",
            }
        }
        result = adapter.to_vat_comment_update(payload)
        assert result is not None
        assert result.cve_id == "CVE-2024-1234"
        assert result.tracker_issue_id == ""
        assert result.tracker_comment_id is None or result.tracker_comment_id == ""


# ---------------------------------------------------------------------------
# GraphQL / API (mocked)
# ---------------------------------------------------------------------------


async def test_linear_create_issue(linear_respx):
    """Create issue returns (identifier, uuid) from mocked GraphQL response."""
    adapter = LinearAdapter(api_key="test-key", team_id="test-team-id")
    req = VatTrackerCreateIssueRequest(
        finding={"cveId": "CVE-2024-21626", "title": "Test finding", "severity": "high"},
        template="[VAT] {cve_id}\nstatus: ...\njustification: ...",
    )
    result = await adapter.create_issue(req)
    ident = result[0] if isinstance(result, tuple) else result
    assert ident == "VAT-1"
    if isinstance(result, tuple):
        assert result[1] == "mock-uuid"


async def test_linear_post_comment(linear_respx):
    """Post comment succeeds with mocked commentCreate response."""
    adapter = LinearAdapter(api_key="test-key")
    req = VatTrackerPostDecisionRequest(tracker_issue_id="VAT-1", body="Reviewer decision: Risk Accepted")
    await adapter.post_comment(req)
    # No exception = success; respx intercepts the identifier lookup and comment create


async def test_linear_update_issue(linear_respx):
    """Update issue succeeds with mocked issueUpdate response."""
    adapter = LinearAdapter(api_key="test-key")
    req = VatTrackerUpdateIssueRequest(
        issue_id="VAT-1",
        finding={"cveId": "CVE-2024-21626", "title": "Updated title", "severity": "critical"},
        changed_fields=["title", "severity"],
        label_names=["security-bug"],
    )
    await adapter.update_issue(req)
    # No exception = success; respx intercepts identifier lookup, label resolution, and issueUpdate


async def test_linear_reopen_issue(linear_respx):
    """Reopen closed issue succeeds with mocked team states and issueUpdate."""
    adapter = LinearAdapter(api_key="test-key", team_id="automatedhass")
    result = await adapter.reopen_issue("VAT-1")
    assert result is True
    # respx: issues filter (identifier), team states, issueUpdate


async def test_linear_is_state_closed(linear_respx):
    """is_state_closed returns True for done/canceled workflow state."""
    adapter = LinearAdapter(api_key="test-key")
    assert await adapter.is_state_closed("mock-state-done") is True


async def test_linear_create_issue_with_labels(linear_respx):
    """Create issue with labels resolves label IDs from issueLabels query."""
    adapter = LinearAdapter(api_key="test-key", team_id="test-team-id")
    req = VatTrackerCreateIssueRequest(
        finding={"cveId": "CVE-1", "title": "Test"},
        template="[VAT] {cve_id}\nstatus: ...\njustification: ...",
        label_names=["security-bug"],
    )
    result = await adapter.create_issue(req)
    ident = result[0] if isinstance(result, tuple) else result
    assert ident == "VAT-1"


async def test_linear_create_issue_default_label(linear_respx):
    """When no labels configured, uses default security-bug."""
    adapter = LinearAdapter(api_key="test-key", team_id="test-team-id")
    req = VatTrackerCreateIssueRequest(
        finding={"cveId": "CVE-1", "title": "Test"},
        template="[VAT] {cve_id}\nstatus: ...\njustification: ...",
        label_names=[],
    )
    result = await adapter.create_issue(req)
    ident = result[0] if isinstance(result, tuple) else result
    assert ident == "VAT-1"


async def test_linear_create_issue_creates_missing_label(linear_respx):
    """When a configured label doesn't exist in Linear, create it and use it."""
    adapter = LinearAdapter(api_key="test-key", team_id="test-team-id")
    # "vat-security" is not in the mock's issueLabels; adapter should create it via issueLabelCreate
    req = VatTrackerCreateIssueRequest(
        finding={"cveId": "CVE-1", "title": "Test"},
        template="[VAT] {cve_id}\nstatus: ...\njustification: ...",
        label_names=["vat-security"],
    )
    result = await adapter.create_issue(req)
    ident = result[0] if isinstance(result, tuple) else result
    assert ident == "VAT-1"


async def test_linear_find_existing_issue_for_cve(linear_respx):
    """find_existing_issue_for_cve returns identifier when Linear has an issue with that CVE."""
    adapter = LinearAdapter(api_key="test-key", team_id="test-team-id")
    result = await adapter.find_existing_issue_for_cve("CVE-2024-1234")
    assert result == "AUT-51"


async def test_linear_find_existing_issue_for_cve_not_found(linear_respx):
    """find_existing_issue_for_cve returns None when no issue contains the CVE."""
    adapter = LinearAdapter(api_key="test-key", team_id="test-team-id")
    # Mock returns AUT-51 with CVE-2024-1234; CVE-9999-99999 is not in the mock
    result = await adapter.find_existing_issue_for_cve("CVE-9999-99999")
    assert result is None


async def test_linear_find_existing_issue_for_title(linear_respx):
    """find_existing_issue_for_title returns identifier when Linear has an issue with that title."""
    adapter = LinearAdapter(api_key="test-key", team_id="test-team-id")
    # Mock returns AUT-51 with title "Kafka client auth bypass CVE-2024-1234"
    result = await adapter.find_existing_issue_for_title("Kafka client auth bypass CVE-2024-1234")
    assert result == "AUT-51"


async def test_linear_find_existing_issue_for_title_not_found(linear_respx):
    """find_existing_issue_for_title returns None when no issue has that title."""
    adapter = LinearAdapter(api_key="test-key", team_id="test-team-id")
    result = await adapter.find_existing_issue_for_title("SQL injection in user lookup")
    assert result is None


async def test_linear_get_organization_url_key_by_slug(linear_respx):
    """get_organization_url_key returns urlKey when team_id is slug (e.g. Automatedhass)."""
    from app.adapters.linear import get_organization_url_key

    adapter = LinearAdapter(api_key="test-key", team_id="automatedhass")
    result = await get_organization_url_key(adapter)
    assert result == "automatedhass"


async def test_linear_get_organization_url_key_by_uuid(linear_respx):
    """get_organization_url_key returns urlKey when team_id is UUID."""
    from app.adapters.linear import get_organization_url_key

    adapter = LinearAdapter(api_key="test-key", team_id="mock-team-uuid")
    result = await get_organization_url_key(adapter)
    assert result == "automatedhass"


# ---------------------------------------------------------------------------
# spaCy token-based extraction (optional)
# ---------------------------------------------------------------------------


def test_spacy_token_extraction():
    """spaCy handles unusual whitespace and fragmented tokens when model is available."""
    try:
        import spacy
        spacy.load("en_core_web_sm")
    except (OSError, ImportError):
        pytest.skip("spaCy or en_core_web_sm not available")
    text = "CVE-2024-1234\nverdict : mitigated\nreason : Patched in v2"
    result = LinearAdapter.parse_vat_block_from_text(text)
    assert result is not None
    assert result["status"] == "Mitigated"
    assert result["justification"] == "Patched in v2"


# ---------------------------------------------------------------------------
# format_canonical_block
# ---------------------------------------------------------------------------


class TestFormatCanonicalBlock:
    """Format canonical block for posting back to Linear."""

    def test_basic(self):
        block = LinearAdapter().format_canonical_block(
            "CVE-2024-1234", "False Positive", "Not in use", ""
        )
        assert "[VAT] CVE-2024-1234" in block
        assert "status: false-positive" in block
        assert "justification: Not in use" in block

    def test_with_compensating(self):
        block = LinearAdapter().format_canonical_block(
            "CVE-2024-1234", "Risk Accepted", "OK", "WAF rule"
        )
        assert "compensating-controls: WAF rule" in block
