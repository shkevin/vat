"""Tests for deduplication fingerprint."""

import pytest

from app.services.dedup import make_fingerprint


def test_make_fingerprint_same_input_same_hash():
    """Same inputs produce same fingerprint (backward compat when source_name omitted)."""
    fp1 = make_fingerprint("private-key", "2026-03-08_0429")
    fp2 = make_fingerprint("private-key", "2026-03-08_0429")
    assert fp1 == fp2


def test_make_fingerprint_different_sources_different_hash():
    """Findings from different parsers (vat-local-gitleaks vs vat-local-trivy) produce different fingerprints."""
    fp_gitleaks = make_fingerprint(
        "private-key", "2026-03-08_0429", source_name="vat-local-gitleaks"
    )
    fp_trivy = make_fingerprint(
        "private-key", "2026-03-08_0429", source_name="vat-local-trivy"
    )
    assert fp_gitleaks != fp_trivy


def test_make_fingerprint_empty_source_same_as_omitted():
    """Empty or omitted source_name produces same fingerprint (backward compat)."""
    fp_omit = make_fingerprint("cve-1", "pkg")
    fp_empty = make_fingerprint("cve-1", "pkg", source_name="")
    fp_none = make_fingerprint("cve-1", "pkg", source_name=None)
    assert fp_omit == fp_empty == fp_none
