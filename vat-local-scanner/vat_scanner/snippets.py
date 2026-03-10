"""Strip code snippets from findings for --no-snippets compliance."""

from __future__ import annotations

from typing import Any

# Keys that may contain secret/code snippets
SNIPPET_KEYS = frozenset({
    "Code", "code", "Match", "match", "Secret", "secret",
    "Content", "content", "Snippet", "snippet", "MatchContent",
    "Lines", "lines", "matched_content",
})


def _strip_snippets_from_obj(obj: Any) -> Any:
    """Recursively remove snippet-like fields from dict/list."""
    if isinstance(obj, dict):
        return {
            k: _strip_snippets_from_obj(v)
            for k, v in obj.items()
            if k not in SNIPPET_KEYS
        }
    if isinstance(obj, list):
        return [_strip_snippets_from_obj(x) for x in obj]
    return obj


def strip_snippets(report: dict | list) -> dict | list:
    """Remove snippet/code/secret fields from report. Returns new copy."""
    return _strip_snippets_from_obj(report)
