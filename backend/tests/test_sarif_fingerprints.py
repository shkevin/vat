"""SARIF partialFingerprints resolution (plan §4.5)."""

import hashlib

from app.services.sarif_fingerprints import resolve_partial_fingerprints


def test_precedence_primary_location_v1():
    pf = {
        "primaryLocationLineHash/v1": "hash-a",
        "contextRegionHash/v1": "hash-b",
    }
    digest, branch = resolve_partial_fingerprints(pf)
    assert branch == "primaryLocationLineHash/v1"
    expected = hashlib.sha256(b"hash-a").hexdigest()
    assert digest == expected


def test_fallback_sorted_keys():
    pf = {"zzz": "last", "aaa": "first"}
    digest, branch = resolve_partial_fingerprints(pf)
    assert branch == "sorted_all_keys_sha256"
    blob = "aaa=first|zzz=last"
    assert digest == hashlib.sha256(blob.encode()).hexdigest()


def test_empty_returns_none():
    assert resolve_partial_fingerprints({}) == (None, "none")
    assert resolve_partial_fingerprints(None) == (None, "none")
